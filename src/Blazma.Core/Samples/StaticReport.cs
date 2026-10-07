namespace Blazma.Core.Samples;

public enum SignatureStatus
{
    /// <summary>No Authenticode signature in the file.</summary>
    NotSigned,

    /// <summary>A signature is present but this platform cannot verify it (e.g. not running on Windows).</summary>
    PresentUnverified,

    Valid,
    Invalid,
}

public sealed record SignatureInfo(SignatureStatus Status, string? Publisher = null, string? Detail = null);

public sealed record PeSection(string Name, uint VirtualSize, uint RawSize, double Entropy, bool Executable, bool Writable);

public sealed record PeImport(string Library, IReadOnlyList<string> Functions);

public sealed record PeInfo
{
    public required string Machine { get; init; }
    public required bool Is64Bit { get; init; }
    public required bool IsDll { get; init; }
    public required string Subsystem { get; init; }
    public required bool IsDotNet { get; init; }

    /// <summary>From the COFF header. Trivially forged; always shown with that caveat.</summary>
    public DateTimeOffset? CompileTimestamp { get; init; }

    public IReadOnlyList<PeSection> Sections { get; init; } = [];
    public IReadOnlyList<PeImport> Imports { get; init; } = [];
    public IReadOnlyList<string> Exports { get; init; } = [];
    public int ResourceCount { get; init; }
    public IReadOnlyDictionary<string, string> VersionInfo { get; init; } = new Dictionary<string, string>();
    public bool HasOverlay { get; init; }
}

public enum InterestingStringKind
{
    Url,
    IpAddress,
    Domain,
    RegistryPath,
    FilePath,
    Command,
}

public sealed record InterestingString(InterestingStringKind Kind, string Value);

/// <summary>Everything learned about a sample without executing it.</summary>
public sealed record StaticReport
{
    public required SampleInfo Sample { get; init; }
    public PeInfo? Pe { get; init; }
    public SignatureInfo Signature { get; init; } = new(SignatureStatus.NotSigned);
    public double Entropy { get; init; }
    public IReadOnlyList<InterestingString> Strings { get; init; } = [];
    public IReadOnlyList<string> Warnings { get; init; } = [];
}
