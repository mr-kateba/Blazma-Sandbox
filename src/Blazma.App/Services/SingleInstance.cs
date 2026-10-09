using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;

namespace Blazma.App.Services;

/// <summary>
/// Keeps one Blazma window per user. A second launch (for example "Analyze with Blazma Sandbox"
/// in Explorer while the app is open) hands its file to the running window and exits. The pipe
/// is limited to the current user, and a message can only ask to prepare an existing file on the
/// New Analysis screen; nothing is ever run from it.
/// </summary>
public sealed class SingleInstance : IDisposable
{
    private const int MaxMessageBytes = 8192;
    private const string OpenPrefix = "open\n";
    private const string ActivateMessage = "activate";

    private readonly Mutex _mutex;
    private readonly CancellationTokenSource _stop = new();

    public bool IsFirst { get; }
    public string PipeName { get; }

    private SingleInstance(string name)
    {
        PipeName = name;
        _mutex = new Mutex(initiallyOwned: true, @"Local\" + name, out var createdNew);
        IsFirst = createdNew;
    }

    /// <summary>A name per user (and per data folder in tests), so two accounts never share a window.</summary>
    public static string NameFor(string? scope = null)
    {
        var who = $"{Environment.UserDomainName}\\{Environment.UserName}|{scope}";
        return "BlazmaSandbox." + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(who)))[..16];
    }

    public static SingleInstance Acquire(string? scope = null) => new(NameFor(scope));

    // ---- messages ----------------------------------------------------------------------------

    internal static byte[] Encode(string? file) =>
        Encoding.UTF8.GetBytes(file is null ? ActivateMessage : OpenPrefix + file);

    /// <summary>The file to prepare, or null to just bring the window forward. Anything malformed is ignored.</summary>
    internal static (bool Valid, string? File) Decode(ReadOnlySpan<byte> data)
    {
        if (data.Length is 0 or > MaxMessageBytes) return (false, null);
        string text;
        try { text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(data); }
        catch (DecoderFallbackException) { return (false, null); }
        if (text == ActivateMessage) return (true, null);
        if (!text.StartsWith(OpenPrefix, StringComparison.Ordinal)) return (false, null);
        var path = text[OpenPrefix.Length..];
        if (path.Length == 0 || path.IndexOfAny(['\0', '\n', '\r']) >= 0 || !Path.IsPathFullyQualified(path)) return (false, null);
        return File.Exists(path) ? (true, path) : (false, null);
    }

    // ---- second instance ---------------------------------------------------------------------

    /// <summary>Sends the file to the running window. False when it did not answer (start normally then).</summary>
    public bool TrySendToFirst(string? file, TimeSpan timeout)
    {
        try
        {
            using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out, PipeOptions.CurrentUserOnly);
            client.Connect((int)timeout.TotalMilliseconds);
            var bytes = Encode(file);
            if (bytes.Length > MaxMessageBytes) return false;
            client.Write(bytes);
            client.Flush();
            return true;
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    // ---- first instance ----------------------------------------------------------------------

    /// <summary>Accepts messages until disposed. <paramref name="onMessage"/> gets the file (or null) on a background thread.</summary>
    public void Listen(Action<string?> onMessage)
    {
        if (!IsFirst) throw new InvalidOperationException("Only the first instance listens.");
        _ = Task.Run(async () =>
        {
            var buffer = new byte[MaxMessageBytes + 1];
            while (!_stop.IsCancellationRequested)
            {
                try
                {
                    await using var server = new NamedPipeServerStream(PipeName, PipeDirection.In, 1,
                        PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                    await server.WaitForConnectionAsync(_stop.Token).ConfigureAwait(false);
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                    timeout.CancelAfter(TimeSpan.FromSeconds(2));
                    var total = 0;
                    int read;
                    while (total < buffer.Length && (read = await server.ReadAsync(buffer.AsMemory(total), timeout.Token).ConfigureAwait(false)) > 0)
                        total += read;
                    var (valid, file) = Decode(buffer.AsSpan(0, total));
                    if (valid) onMessage(file);
                }
                catch (OperationCanceledException) when (_stop.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex) when (ex is IOException or OperationCanceledException or UnauthorizedAccessException)
                {
                    // A client that misbehaved or timed out; keep serving the next one.
                }
            }
        });
    }

    public void Dispose()
    {
        _stop.Cancel();
        _stop.Dispose();
        if (IsFirst)
        {
            try { _mutex.ReleaseMutex(); } catch (ApplicationException) { }
        }
        _mutex.Dispose();
    }
}
