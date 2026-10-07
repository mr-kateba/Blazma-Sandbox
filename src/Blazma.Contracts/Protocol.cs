using System.Text.RegularExpressions;

namespace Blazma.Contracts;

/// <summary>
/// File-based protocol over two mapped folders:
/// <list type="bullet">
/// <item><c>in/</c> is mapped READ-ONLY into the sandbox. The host writes the agent, the
/// session config, the sample and the go signal there.</item>
/// <item><c>out/</c> is the only writable mapping. The agent writes events, heartbeats,
/// snapshots and the done marker. The host parses it strictly and never executes
/// anything from it.</item>
/// </list>
/// Files are written to a <c>.tmp</c> name and renamed when complete, so the host never
/// reads a half-written file.
/// </summary>
public static partial class Protocol
{
    public const int Version = 1;

    public const string SessionFile = "session.json";
    public const string GoFile = "go.json";
    public const string SampleFolder = "sample";
    public const string AgentFolder = "agent";
    public const string AgentExecutable = "Blazma.Agent.exe";

    public const string HelloFile = "hello.json";
    public const string HeartbeatFile = "heartbeat.json";
    public const string DoneFile = "done.json";
    public const string BaselineFile = "baseline.json";
    public const string AfterFile = "after.json";
    public const string EventChunkPrefix = "events-";
    public const string EventChunkExtension = ".ndjson";
    public const string TempExtension = ".tmp";

    /// <summary>Limits the host enforces on everything read from <c>out/</c>.</summary>
    public static class Limits
    {
        public const long MaxFileBytes = 64L * 1024 * 1024;
        public const int MaxLineBytes = 64 * 1024;
        public const int MaxStringLength = 8 * 1024;
        public const int MaxDetails = 32;
        public const int MaxChunkFiles = 100_000;
        public const int MaxSnapshotEntries = 200_000;
    }

    public static string EventChunkName(int index) => $"{EventChunkPrefix}{index:D6}{EventChunkExtension}";

    /// <summary>The complete list of names the host will open in <c>out/</c>. Anything else is ignored and reported.</summary>
    public static bool IsAllowedOutboxName(string name) =>
        name is HelloFile or HeartbeatFile or DoneFile or BaselineFile or AfterFile || EventChunkRegex().IsMatch(name);

    public static bool TryParseChunkIndex(string name, out int index)
    {
        index = -1;
        var m = EventChunkRegex().Match(name);
        return m.Success && int.TryParse(m.Groups[1].ValueSpan, out index);
    }

    [GeneratedRegex(@"^events-(\d{6})\.ndjson$", RegexOptions.CultureInvariant)]
    private static partial Regex EventChunkRegex();
}
