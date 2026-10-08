using Blazma.Core.Samples;

namespace Blazma.Core.Analysis;

/// <summary>
/// A screenshot of the sandbox desktop. Pixels arrive raw from the agent and the host
/// encodes the PNG itself, so no image parser ever reads data produced inside the sandbox.
/// </summary>
public sealed record ScreenshotInfo(TimeSpan RelativeTime, string FileName, int Width, int Height);

/// <summary>A file the analyzed programs created, copied out of the sandbox and stored defanged.</summary>
public sealed record DroppedFileInfo
{
    public required string OriginalPath { get; init; }
    public required string ProcessName { get; init; }
    public required string Sha256 { get; init; }
    public required long Size { get; init; }

    /// <summary>The stored copy, relative to the analysis' artifact folder. Never executable by name.</summary>
    public string? StoredName { get; init; }

    public StaticReport? Static { get; init; }
}

public enum MemoryRegionKind
{
    /// <summary>Private memory that can execute: typical of unpacked or injected code.</summary>
    PrivateExecutable,

    /// <summary>Readable, writable and executable at once.</summary>
    ReadWriteExecute,

    /// <summary>A program image in memory that is not backed by a file on disk.</summary>
    UnbackedImage,
}

/// <summary>A suspicious memory region of an analyzed process, dumped by the agent at the end of the run.</summary>
public sealed record MemoryArtifact
{
    public required int ProcessId { get; init; }
    public required string ProcessName { get; init; }
    public required ulong BaseAddress { get; init; }
    public required long Size { get; init; }
    public required string Protection { get; init; }
    public required MemoryRegionKind Kind { get; init; }
    public required string Sha256 { get; init; }
    public bool HasPeHeader { get; init; }
    public string? StoredName { get; init; }
    public PeInfo? Pe { get; init; }
    public IReadOnlyList<YaraMatch> YaraMatches { get; init; } = [];
    public IReadOnlyList<ExtractedArtifact> Artifacts { get; init; } = [];
}

public enum ReputationVerdict { Unknown, NotFound, Clean, Suspicious, Malicious }

/// <summary>A hash-only lookup. The sample itself is never uploaded.</summary>
public sealed record ReputationResult
{
    public required string ProviderId { get; init; }
    public required string ProviderName { get; init; }
    public required ReputationVerdict Verdict { get; init; }
    public DateTimeOffset CheckedAt { get; init; }
    public int? Detections { get; init; }
    public int? Engines { get; init; }
    public string? Family { get; init; }
    public IReadOnlyList<string> Tags { get; init; } = [];
    public DateTimeOffset? FirstSeen { get; init; }
    public string? Link { get; init; }
    public string? Error { get; init; }
}
