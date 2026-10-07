using Blazma.Core.Samples;

namespace Blazma.Analysis.Static;

/// <summary>Identifies a file by its content first and its extension second.</summary>
public static class FileTypeDetector
{
    public static FileKind Detect(ReadOnlySpan<byte> head, string fileName, PeInfo? pe)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();

        if (head.Length >= 2 && head[0] == 'M' && head[1] == 'Z')
        {
            if (pe is null) return FileKind.Executable;
            if (pe.Subsystem == "Native" || ext == ".sys") return FileKind.Driver;
            return pe.IsDll ? FileKind.Dll : FileKind.Executable;
        }

        if (head.Length >= 8 && head[0] == 0xD0 && head[1] == 0xCF && head[2] == 0x11 && head[3] == 0xE0)
            return ext == ".msi" ? FileKind.Msi : FileKind.Unknown;

        if (head.Length >= 4 && head[0] == 0x4C && head[1] == 0x00 && head[2] == 0x00 && head[3] == 0x00)
            return FileKind.Shortcut;

        if (head.Length >= 4 && head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4)
            return FileKind.Archive;

        return ext switch
        {
            ".ps1" or ".psm1" => FileKind.PowerShell,
            ".bat" or ".cmd" => FileKind.Batch,
            ".vbs" or ".vbe" => FileKind.VbScript,
            ".js" or ".jse" => FileKind.JScript,
            _ => FileKind.Unknown,
        };
    }
}
