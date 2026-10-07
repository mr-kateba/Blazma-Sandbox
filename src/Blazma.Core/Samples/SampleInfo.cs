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
}

public sealed record SampleInfo
{
    public required string FileName { get; init; }
    public required long Size { get; init; }
    public required string Sha256 { get; init; }

    /// <summary>Kept for compatibility with external tools only. Not used for identity.</summary>
    public required string Sha1 { get; init; }

    public required FileKind Kind { get; init; }
    public string Extension => Path.GetExtension(FileName).ToLowerInvariant();

    /// <summary>Whether Blazma can run this kind of file inside the sandbox.</summary>
    public bool IsExecutableKind => Kind is FileKind.Executable or FileKind.Dll or FileKind.Msi or FileKind.PowerShell
        or FileKind.Batch or FileKind.VbScript or FileKind.JScript or FileKind.Shortcut;
}
