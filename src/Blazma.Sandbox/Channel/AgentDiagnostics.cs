using System.Text;

namespace Blazma.Sandbox.Channel;

/// <summary>
/// The agent's plain-text diagnostic logs in <c>out/</c>: <see cref="LogFile"/>, written by the agent
/// itself, and <see cref="StartLogFile"/>, the output of the launcher that starts it. They are NOT
/// signed, so they are only ever shown as text: exact names, no links, at most
/// <see cref="MaxBytes"/> read, control and direction-override characters removed.
/// </summary>
public static class AgentDiagnostics
{
    public const string LogFile = Contracts.Protocol.AgentLogFile;
    public const string StartLogFile = "agent-start.txt";

    /// <summary>The agent caps its own log at this size; only the last this-many bytes of a larger file are read.</summary>
    public const int MaxBytes = 1024 * 1024;

    private static readonly string[] Names = [StartLogFile, LogFile];

    public static bool IsDiagnosticName(string name) => name is LogFile or StartLogFile;

    /// <summary>The cleaned text of one diagnostic file, or null when it is missing, a link or unreadable.</summary>
    public static string? Read(string outFolder, string name)
    {
        if (!IsDiagnosticName(name)) return null;
        var path = Path.Combine(outFolder, name);
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Attributes.HasFlag(FileAttributes.ReparsePoint) || info.LinkTarget is not null) return null;

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);
            var length = stream.Length;
            if (length > MaxBytes) stream.Seek(length - MaxBytes, SeekOrigin.Begin);
            var buffer = new byte[Math.Min(length, MaxBytes)];
            var read = stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
            return Clean(Encoding.UTF8.GetString(buffer, 0, read));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }

    /// <summary>The last <paramref name="maxLines"/> non-empty lines of the launcher output and the agent log, labelled, or null when there are none.</summary>
    public static string? Tail(string outFolder, int maxLines = 20)
    {
        var parts = new List<string>();
        foreach (var name in Names)
        {
            var lines = Read(outFolder, name)?.Split('\n').Select(l => l.TrimEnd()).Where(l => l.Length > 0).TakeLast(maxLines).ToList();
            if (lines is { Count: > 0 }) parts.Add($"{name} (last lines):\n" + string.Join('\n', lines.Select(l => l.Length > 500 ? l[..500] + "…" : l)));
        }
        return parts.Count == 0 ? null : string.Join("\n", parts);
    }

    /// <summary>Stores cleaned copies next to the analysis artifacts. Returns the files written.</summary>
    public static IReadOnlyList<string> CopyTo(string outFolder, string destinationFolder)
    {
        var written = new List<string>();
        foreach (var name in Names)
        {
            if (Read(outFolder, name) is not { } text) continue;
            try
            {
                Directory.CreateDirectory(destinationFolder);
                var target = Path.Combine(destinationFolder, name);
                SharedFileRetry.Default.Run(() => File.WriteAllText(target, text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)));
                written.Add(target);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return written;
    }

    /// <summary>Keeps tabs and line breaks; removes other control characters and the embedding, override and isolate characters that reorder text on screen.</summary>
    internal static string Clean(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (var c in text.ReplaceLineEndings("\n"))
        {
            if (c is '\n' or '\t') sb.Append(c);
            else if (char.IsControl(c) || IsDirectionControl(c)) continue;
            else sb.Append(c);
        }
        return sb.ToString();
    }

    private static bool IsDirectionControl(char c) => c is (>= '\u202A' and <= '\u202E') or (>= '\u2066' and <= '\u2069');
}
