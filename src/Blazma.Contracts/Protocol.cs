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
    public const int Version = 2;

    public const string SessionFile = "session.json";
    public const string GoFile = "go.json";

    /// <summary>Host to agent, in the read-only folder: extend or finish the run. Re-written with a higher sequence.</summary>
    public const string ControlFile = "control.json";
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
    public const string PcapFile = "capture.pcapng";

    /// <summary>
    /// The agent's plain-text diagnostic log (UTF-8, appended, at most 1 MB). NOT signed and never
    /// trusted: show it as text only. Deliberately not in <see cref="IsAllowedOutboxName"/>, which
    /// lists the signed protocol files.
    /// </summary>
    public const string AgentLogFile = "agent.log";

    /// <summary>Raw screenshot: "BLZF", u16 width, u16 height, u32 relative ms, then gzip(BGRA pixels). Signed.</summary>
    public static string ScreenshotName(int index) => $"screen-{index:D6}.raw";
    public static string DroppedDataName(int index) => $"dropped-{index:D4}.bin";
    public static string DroppedMetaName(int index) => $"dropped-{index:D4}.json";
    public static string MemoryDataName(int index) => $"memory-{index:D4}.bin";
    public static string MemoryMetaName(int index) => $"memory-{index:D4}.json";
    public static ReadOnlySpan<byte> ScreenshotMagic => "BLZF"u8;

    /// <summary>Limits the host enforces on everything read from <c>out/</c>.</summary>
    public static class Limits
    {
        public const long MaxFileBytes = 64L * 1024 * 1024;
        public const int MaxLineBytes = 64 * 1024;
        public const int MaxStringLength = 8 * 1024;
        public const int MaxDetails = 32;
        public const int MaxChunkFiles = 100_000;
        public const int MaxSnapshotEntries = 200_000;

        public const int MaxScreenshots = 360;
        public const int MaxScreenshotWidth = 1920;
        public const int MaxScreenshotHeight = 1200;
        public const int MaxDroppedFiles = 100;
        public const int MaxMemoryRegions = 64;
        public const long MaxMemoryRegionBytes = 32L * 1024 * 1024;
        public const long MaxPcapBytes = 64L * 1024 * 1024;
    }

    public static string EventChunkName(int index) => $"{EventChunkPrefix}{index:D6}{EventChunkExtension}";

    /// <summary>The complete list of names the host will open in <c>out/</c>. Anything else is ignored and reported.</summary>
    public static bool IsAllowedOutboxName(string name) =>
        name is HelloFile or HeartbeatFile or DoneFile or BaselineFile or AfterFile or PcapFile
        || EventChunkRegex().IsMatch(name) || ArtifactRegex().IsMatch(name);

    public static bool TryParseChunkIndex(string name, out int index)
    {
        index = -1;
        var m = EventChunkRegex().Match(name);
        return m.Success && int.TryParse(m.Groups[1].ValueSpan, out index);
    }

    [GeneratedRegex(@"^events-(\d{6})\.ndjson$", RegexOptions.CultureInvariant)]
    private static partial Regex EventChunkRegex();

    [GeneratedRegex(@"^(screen-\d{6}\.raw|dropped-\d{4}\.(bin|json)|memory-\d{4}\.(bin|json))$", RegexOptions.CultureInvariant)]
    private static partial Regex ArtifactRegex();
}
