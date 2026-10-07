using System.Text.Json.Serialization;

namespace Blazma.Contracts;

/// <summary>Host to agent: what to capture and for how long. Written before the sandbox starts.</summary>
public sealed class SessionConfigDto
{
    public int ProtocolVersion { get; set; } = Protocol.Version;
    public Guid AnalysisId { get; set; }
    public int DurationSeconds { get; set; }
    public bool CaptureProcesses { get; set; } = true;
    public bool CaptureFiles { get; set; } = true;
    public bool CaptureRegistry { get; set; } = true;
    public bool CaptureNetwork { get; set; } = true;
    public bool TakeSnapshots { get; set; } = true;
    public bool StopWhenTreeExits { get; set; } = true;
    public int HeartbeatSeconds { get; set; } = 2;

    /// <summary>Base64 HMAC key for <see cref="SignedFile"/>. Removed from disk by the host after the agent's hello.</summary>
    public string? ChannelKey { get; set; }
}

/// <summary>Host to agent: the sample is in place, verify it and run it.</summary>
public sealed class GoDto
{
    public string SampleFileName { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public DateTimeOffset IssuedAt { get; set; }
}

public sealed class HelloDto
{
    public int ProtocolVersion { get; set; }
    public string AgentVersion { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public DateTimeOffset At { get; set; }
}

public sealed class HeartbeatDto
{
    public DateTimeOffset At { get; set; }
    public long EventsWritten { get; set; }
    public string State { get; set; } = string.Empty;
}

public sealed class DoneDto
{
    public DateTimeOffset At { get; set; }
    public string Reason { get; set; } = string.Empty;
    public long EventsWritten { get; set; }
    public bool SampleStarted { get; set; }
    public int? SampleExitCode { get; set; }
    public string? Error { get; set; }
}

/// <summary>One observed event, as written by the agent. Field names are short to keep chunks small.</summary>
public sealed class AgentEventDto
{
    [JsonPropertyName("seq")] public long Sequence { get; set; }
    [JsonPropertyName("ts")] public long TimestampUnixMs { get; set; }
    [JsonPropertyName("rel")] public long RelativeMs { get; set; }
    [JsonPropertyName("act")] public string Action { get; set; } = string.Empty;
    [JsonPropertyName("pid")] public int ProcessId { get; set; }
    [JsonPropertyName("ppid")] public int ParentProcessId { get; set; }
    [JsonPropertyName("pst")] public long ProcessStartMs { get; set; }
    [JsonPropertyName("proc")] public string ProcessName { get; set; } = string.Empty;
    [JsonPropertyName("tgt")] public string? Target { get; set; }
    [JsonPropertyName("d")] public Dictionary<string, string>? Details { get; set; }
    [JsonPropertyName("src")] public string Source { get; set; } = string.Empty;
}

public sealed class SnapshotDto
{
    public DateTimeOffset TakenAt { get; set; }
    public List<FileEntryDto> Files { get; set; } = [];
    public List<RegistryEntryDto> Registry { get; set; } = [];
    public List<string> Services { get; set; } = [];
    public List<string> ScheduledTasks { get; set; } = [];
    public List<string> StartupItems { get; set; } = [];
}

public sealed class FileEntryDto
{
    public string Path { get; set; } = string.Empty;
    public long Size { get; set; }
    public DateTimeOffset LastWriteUtc { get; set; }
    public string? Sha256 { get; set; }
}

public sealed class RegistryEntryDto
{
    public string Key { get; set; } = string.Empty;
    public string ValueName { get; set; } = string.Empty;
    public string? Data { get; set; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = false)]
[JsonSerializable(typeof(SessionConfigDto))]
[JsonSerializable(typeof(GoDto))]
[JsonSerializable(typeof(HelloDto))]
[JsonSerializable(typeof(HeartbeatDto))]
[JsonSerializable(typeof(DoneDto))]
[JsonSerializable(typeof(AgentEventDto))]
[JsonSerializable(typeof(SnapshotDto))]
public sealed partial class ProtocolJson : JsonSerializerContext;
