using Blazma.Core.Samples;

namespace Blazma.Analysis.Static;

/// <summary>Identifies a file by its content first and its extension second.</summary>
public static class FileTypeDetector
{
    /// <summary>
    /// Entry names that make a ZIP an Office Open XML or OpenDocument package. These are ZIP files
    /// too, but a document must not be opened as an archive: it gets document analysis instead.
    /// </summary>
    private static readonly byte[][] PackageNamePrefixes =
    [
        "[Content_Types].xml"u8.ToArray(), "mimetype"u8.ToArray(), "_rels/.rels"u8.ToArray(), "docProps/"u8.ToArray(),
        "word/"u8.ToArray(), "xl/"u8.ToArray(), "ppt/"u8.ToArray(),
    ];

    public static FileKind Detect(ReadOnlySpan<byte> head, string fileName, PeInfo? pe)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();

        if (head.Length >= 2 && head[0] == 'M' && head[1] == 'Z')
        {
            if (pe is null) return FileKind.Executable;
            if (pe.Subsystem == "Native" || ext == ".sys") return FileKind.Driver;
            return pe.IsDll ? FileKind.Dll : FileKind.Executable;
        }

        // OLE compound file: MSI installers and legacy Office documents (.doc, .xls, .ppt, .msg).
        if (head.Length >= 8 && head[0] == 0xD0 && head[1] == 0xCF && head[2] == 0x11 && head[3] == 0xE0)
            return ext == ".msi" ? FileKind.Msi : FileKind.Document;

        if (head.Length >= 4 && head[0] == 0x4C && head[1] == 0x00 && head[2] == 0x00 && head[3] == 0x00)
            return FileKind.Shortcut;

        if (head.Length >= 4 && head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4)
            return IsOfficePackage(head) ? FileKind.Document : FileKind.Archive;

        // PDF readers accept the header anywhere in the first kilobyte.
        if (head[..Math.Min(head.Length, 1024)].IndexOf("%PDF-"u8) >= 0) return FileKind.Document;
        if (head.StartsWith("{\\rtf"u8)) return FileKind.Document;

        if (IsArchiveMagic(head)) return FileKind.Archive;

        return ext switch
        {
            ".ps1" or ".psm1" => FileKind.PowerShell,
            ".bat" or ".cmd" => FileKind.Batch,
            ".vbs" or ".vbe" => FileKind.VbScript,
            ".js" or ".jse" => FileKind.JScript,
            _ => FileKind.Unknown,
        };
    }

    /// <summary>The archive formats Blazma can list: 7z, RAR (4 and 5), GZip and POSIX TAR.</summary>
    private static bool IsArchiveMagic(ReadOnlySpan<byte> head) =>
        head.StartsWith((ReadOnlySpan<byte>)[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])
        || head.StartsWith((ReadOnlySpan<byte>)[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07])
        || head.StartsWith((ReadOnlySpan<byte>)[0x1F, 0x8B])
        || (head.Length >= 262 && head.Slice(257, 5).SequenceEqual("ustar"u8));

    /// <summary>Whether any local file header visible in <paramref name="head"/> names a package part.</summary>
    private static bool IsOfficePackage(ReadOnlySpan<byte> head)
    {
        ReadOnlySpan<byte> signature = [0x50, 0x4B, 0x03, 0x04];
        for (var at = 0; at + 30 <= head.Length;)
        {
            var found = head[at..].IndexOf(signature);
            if (found < 0) break;
            at += found;
            if (at + 30 > head.Length) break;
            var nameLength = head[at + 26] | (head[at + 27] << 8);
            var name = head.Slice(at + 30, Math.Min(nameLength, head.Length - at - 30));
            foreach (var prefix in PackageNamePrefixes)
                if (name.StartsWith(prefix)) return true;
            at += 4;
        }
        return false;
    }
}
