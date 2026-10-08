using System.Text;

namespace Blazma.Sandbox.Processes;

/// <summary>
/// One external program to run. Arguments are passed one by one (<see cref="System.Diagnostics.ProcessStartInfo.ArgumentList"/>),
/// never as a concatenated command line, so a hostile VM or snapshot name stays a single argument.
/// Secrets never go into <see cref="Arguments"/>: use <see cref="StandardInput"/> or a <see cref="SecretFile"/>.
/// </summary>
public sealed record ProcessRequest(string FileName, IReadOnlyList<string> Arguments)
{
    /// <summary>Written to the program's standard input, which is then closed. May carry secrets; never logged.</summary>
    public string? StandardInput { get; init; }

    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>Characters kept from each of stdout and stderr; the rest is drained and discarded.</summary>
    public int MaxOutputChars { get; init; } = 1024 * 1024;

    /// <summary>Encoding of stdout and stderr; null keeps the platform default.</summary>
    public Encoding? OutputEncoding { get; init; }

    public string? WorkingDirectory { get; init; }

    /// <summary>Deliberately leaves out <see cref="StandardInput"/>, which may contain a password.</summary>
    public override string ToString() => $"{Path.GetFileName(FileName)} {string.Join(' ', Arguments.Take(3))}{(Arguments.Count > 3 ? " …" : "")}";
}

public sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError)
{
    /// <summary>The program ran longer than <see cref="ProcessRequest.Timeout"/> and was killed with its children.</summary>
    public bool TimedOut { get; init; }

    /// <summary>At least one stream was longer than <see cref="ProcessRequest.MaxOutputChars"/>.</summary>
    public bool OutputTruncated { get; init; }

    public bool Succeeded => ExitCode == 0 && !TimedOut;

    /// <summary>A short, single-line description of a failure for logs and error messages.</summary>
    public string Describe()
    {
        if (TimedOut) return "timed out";
        var text = (StandardError.Trim().Length > 0 ? StandardError : StandardOutput).Trim().ReplaceLineEndings(" ");
        if (text.Length > 300) text = text[..300] + "…";
        return text.Length == 0 ? $"exit code {ExitCode}" : $"exit code {ExitCode}: {text}";
    }
}

/// <summary>Starts external programs (VBoxManage, PowerShell). Replaced by a recording fake in tests.</summary>
public interface IProcessRunner
{
    /// <summary>
    /// Runs the program to completion. A timeout kills the process tree and returns a result with
    /// <see cref="ProcessResult.TimedOut"/>; cancellation kills the process tree and throws
    /// <see cref="OperationCanceledException"/>. Failing to start throws.
    /// </summary>
    Task<ProcessResult> RunAsync(ProcessRequest request, CancellationToken cancellationToken);
}
