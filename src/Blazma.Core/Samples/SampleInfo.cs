namespace Blazma.Core.Samples;

public enum FileKind
{
    Unknown,
    Executable,
    Dll,
    Driver,
    Msi,
    PowerShell,
    Batch,
    VbScript,
    JScript,
    Shortcut,
    Archive,

    /// <summary>A web address opened in the sandbox's browser. Requires the real network.</summary>
    Url,

    /// <summary>A document type the sandbox has no viewer for (Office, PDF). Static analysis only.</summary>
    Document,
}

/// <summary>Where a sample came from when it was taken out of an archive.</summary>
public sealed record ArchiveOrigin(string ArchiveName, string ArchiveSha256, string EntryPath);

public sealed record SampleInfo
{
    public required string FileName { get; init; }
    public required long Size { get; init; }
    public required string Sha256 { get; init; }

    /// <summary>Kept for compatibility with external tools only. Not used for identity.</summary>
    public required string Sha1 { get; init; }

    public required FileKind Kind { get; init; }

    /// <summary>For <see cref="FileKind.Url"/> samples: the address. The hashes are of this text.</summary>
    public string? Url { get; init; }

    /// <summary>Set when the sample was extracted from an archive.</summary>
    public ArchiveOrigin? Origin { get; init; }
    public string Extension => Path.GetExtension(FileName).ToLowerInvariant();

    /// <summary>Whether Blazma can run this kind of file inside the sandbox.</summary>
    public bool IsExecutableKind => IsRunnable(Kind);

    /// <summary>Kinds the sandbox knows how to start (a URL is opened in the browser).</summary>
    public static bool IsRunnable(FileKind kind) => kind is FileKind.Executable or FileKind.Dll or FileKind.Msi or FileKind.PowerShell
        or FileKind.Batch or FileKind.VbScript or FileKind.JScript or FileKind.Shortcut or FileKind.Url;
}
