using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace Blazma.Sandbox.Processes;

/// <summary>The real <see cref="IProcessRunner"/>: no shell, no window, bounded output, bounded time.</summary>
public sealed class ProcessRunner : IProcessRunner
{
    public static ProcessRunner Instance { get; } = new();

    /// <summary>How long to keep reading output after the process exited (a grandchild may still hold the pipe).</summary>
    private static readonly TimeSpan DrainGrace = TimeSpan.FromSeconds(5);

    public async Task<ProcessResult> RunAsync(ProcessRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var psi = new ProcessStartInfo(request.FileName)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        };
        if (request.OutputEncoding is { } encoding)
        {
            psi.StandardOutputEncoding = encoding;
            psi.StandardErrorEncoding = encoding;
        }
        if (!string.IsNullOrEmpty(request.WorkingDirectory)) psi.WorkingDirectory = request.WorkingDirectory;
        foreach (var argument in request.Arguments) psi.ArgumentList.Add(argument);

        using var process = new Process { StartInfo = psi };
        if (!process.Start()) throw new InvalidOperationException($"{Path.GetFileName(request.FileName)} did not start.");

        var stdout = new CappedText(request.MaxOutputChars);
        var stderr = new CappedText(request.MaxOutputChars);
        var readers = Task.WhenAll(stdout.ReadAllAsync(process.StandardOutput), stderr.ReadAllAsync(process.StandardError));

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(request.Timeout);
        var timedOut = false;
        try
        {
            try
            {
                if (request.StandardInput is { } input) await process.StandardInput.WriteAsync(input.AsMemory(), timeout.Token).ConfigureAwait(false);
                process.StandardInput.Close();
            }
            catch (IOException)
            {
                // The program exited (or closed stdin) before reading everything; its exit code tells the rest.
            }
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            KillTree(process);
            if (cancellationToken.IsCancellationRequested) throw;
            timedOut = true;
        }

        await Task.WhenAny(readers, Task.Delay(DrainGrace, CancellationToken.None)).ConfigureAwait(false);
        return new ProcessResult(timedOut ? -1 : process.ExitCode, stdout.ToString(), stderr.ToString())
        {
            TimedOut = timedOut,
            OutputTruncated = stdout.Truncated || stderr.Truncated,
        };
    }

    private static void KillTree(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit(5000);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
        {
            // Already gone.
        }
    }

    /// <summary>Collects up to a fixed number of characters and keeps draining the stream so the child never blocks on a full pipe.</summary>
    private sealed class CappedText(int max)
    {
        private readonly StringBuilder _text = new();
        private readonly object _lock = new();

        public bool Truncated { get; private set; }

        public async Task ReadAllAsync(StreamReader reader)
        {
            var buffer = new char[4096];
            try
            {
                int read;
                while ((read = await reader.ReadAsync(buffer.AsMemory()).ConfigureAwait(false)) > 0)
                {
                    lock (_lock)
                    {
                        var room = Math.Max(0, max - _text.Length);
                        if (room > 0) _text.Append(buffer, 0, Math.Min(read, room));
                        if (read > room) Truncated = true;
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
            {
                // The process was killed or disposed; keep what was read.
            }
        }

        public override string ToString()
        {
            lock (_lock) return _text.ToString();
        }
    }
}
