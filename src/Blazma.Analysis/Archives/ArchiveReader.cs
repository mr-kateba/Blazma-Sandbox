using System.Globalization;
using System.Text;
using Blazma.Analysis.Static;
using Blazma.Core.Samples;
using SharpCompress.Archives;
using SharpCompress.Archives.GZip;
using SharpCompress.Archives.Rar;
using SharpCompress.Archives.SevenZip;
using SharpCompress.Archives.Tar;
using SharpCompress.Archives.Zip;
using SharpCompress.Common;
using SharpCompress.Readers;

namespace Blazma.Analysis.Archives;

/// <summary>
/// Lists archives (ZIP with ZipCrypto or AES, 7z including AES, RAR 4 and 5, TAR, GZip) and
/// extracts one entry at a time for analysis. An archive is hostile input, so:
/// <list type="bullet">
/// <item>at most <see cref="MaxEntries"/> entries are listed or extractable; the rest is cut off with a note;</item>
/// <item>an extracted entry may not exceed <see cref="MaxEntryBytes"/>. This is counted on the bytes actually
/// written, never taken from the header, which an attacker controls;</item>
/// <item>past 16 MB, output larger than <see cref="MaxCompressionRatio"/> times its compressed size is treated as a
/// compression bomb and stopped;</item>
/// <item>entry names are flattened to a single sanitized file name: no directories, no "..", no drive letters, no
/// ':' alternate data streams, no Windows device names (CON, NUL, COM1…), no invisible characters;</item>
/// <item>symbolic and hard links are never followed or extracted;</item>
/// <item>a nested archive is reported with <see cref="FileKind.Archive"/> and is not opened recursively;</item>
/// <item>a missing or wrong password raises <see cref="ArchivePasswordException"/>, a broken limit
/// <see cref="ArchiveLimitException"/>, an unreadable file <see cref="InvalidDataException"/>.</item>
/// </list>
/// Nothing in an archive is ever executed here.
/// </summary>
public static class ArchiveReader
{
    public const int MaxEntries = 10_000;
    public const long MaxEntryBytes = 512L * 1024 * 1024;
    public const int MaxCompressionRatio = 100;

    /// <summary>Passwords conventionally used for sharing malware samples, tried after the user's own.</summary>
    public static IReadOnlyList<string> DefaultPasswords { get; } = ["infected", "malware", "virus"];

    private const int SniffBytes = 4096;
    private const long PasswordCheckBytes = 64L * 1024 * 1024;

    public static ArchiveInfo List(string path, string? password) => List(path, password, ArchiveLimits.Default);

    public static string ExtractEntry(string archivePath, string entryPath, string? password, string destinationFolder) =>
        ExtractEntry(archivePath, entryPath, password, destinationFolder, ArchiveLimits.Default);

    /// <summary>
    /// Opens the archive without a password if it is not encrypted, otherwise with the first of
    /// <paramref name="passwords"/> and then <see cref="DefaultPasswords"/> that works. Returns null
    /// when no password works or the file is not a readable archive.
    /// </summary>
    public static ArchiveInfo? TryOpen(string path, IEnumerable<string> passwords, out string? workingPassword) =>
        TryOpen(path, passwords, out workingPassword, ArchiveLimits.Default);

    internal static ArchiveInfo? TryOpen(string path, IEnumerable<string> passwords, out string? workingPassword, ArchiveLimits limits)
    {
        workingPassword = null;
        try
        {
            var plain = List(path, null, limits);
            if (!plain.Encrypted) return plain;
        }
        catch (ArchivePasswordException) { /* encrypted headers: a password is needed even to list */ }
        catch (InvalidDataException) { return null; }

        foreach (var candidate in passwords.Concat(DefaultPasswords).Where(p => !string.IsNullOrEmpty(p)).Distinct(StringComparer.Ordinal))
        {
            try
            {
                var info = List(path, candidate, limits);
                workingPassword = candidate;
                return info;
            }
            catch (ArchivePasswordException) { /* try the next one */ }
            catch (InvalidDataException) { return null; }
        }
        return null;
    }

    internal static ArchiveInfo List(string path, string? password, ArchiveLimits limits)
    {
        using var archive = Open(path, password);
        try
        {
            var (files, links, truncated) = Files(archive, path, limits);
            var entries = new List<ArchiveEntry>(files.Count);
            string? bombHint = null;
            foreach (var (entry, key) in files)
            {
                if (bombHint is null && entry.CompressedSize > 0 && entry.Size > limits.RatioCheckFloor
                    && entry.Size / entry.CompressedSize > limits.MaxCompressionRatio)
                    bombHint = key;

                var sniff = entries.Count < limits.SniffEntries && !archive.IsSolid && (!entry.IsEncrypted || password is not null);
                entries.Add(new ArchiveEntry(key, Math.Max(0, entry.Size), Math.Max(0, entry.CompressedSize), entry.IsEncrypted,
                    KindOf(sniff ? Head(entry) : null, key)));
            }

            var encrypted = archive.IsEncrypted || files.Any(f => f.Entry.IsEncrypted);
            if (password is not null && files.Select(f => f.Entry).Where(e => e.IsEncrypted).MinBy(e => e.Size) is { } smallest)
                VerifyPassword(smallest);

            var notes = new List<string>();
            if (truncated) notes.Add($"Only the first {limits.MaxEntries:N0} entries are listed.");
            if (links > 0) notes.Add($"{links} link entr{(links == 1 ? "y was" : "ies were")} skipped; links are never followed.");
            if (bombHint is not null) notes.Add($"\"{bombHint}\" declares a compression ratio above {limits.MaxCompressionRatio}:1 and may be a compression bomb.");

            return new ArchiveInfo
            {
                Format = FormatName(archive.Type),
                Encrypted = encrypted,
                Entries = entries,
                LimitNote = notes.Count == 0 ? null : string.Join(" ", notes),
            };
        }
        catch (Exception ex) when (IsReadFailure(ex))
        {
            throw Translate(ex, encrypted: password is not null);
        }
    }

    internal static string ExtractEntry(string archivePath, string entryPath, string? password, string destinationFolder, ArchiveLimits limits)
    {
        using var archive = Open(archivePath, password);
        IArchiveEntry? match = null;
        try
        {
            match = archive.Entries.Where(e => !e.IsDirectory).Take(limits.MaxEntries)
                .FirstOrDefault(e => string.Equals(KeyOf(e, archivePath), entryPath, StringComparison.Ordinal));
        }
        catch (Exception ex) when (IsReadFailure(ex))
        {
            throw Translate(ex, password is not null);
        }
        if (match is null) throw new FileNotFoundException("The archive has no such entry.", entryPath);
        if (IsLink(match)) throw new ArchiveLimitException("Links inside archives are never extracted.");
        if (match.IsEncrypted && password is null) throw new ArchivePasswordException();

        var folder = Path.GetFullPath(destinationFolder);
        Directory.CreateDirectory(folder);
        var target = UniquePath(folder, SafeFileName(entryPath));

        var archiveLength = new FileInfo(archivePath).Length;
        var compressed = match.CompressedSize > 0 ? Math.Min(match.CompressedSize, archiveLength) : archiveLength;
        try
        {
            using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            using var input = match.OpenEntryStream();
            CopyBounded(input, output, compressed, limits);
        }
        catch (Exception ex)
        {
            TryDelete(target);
            if (ex is ArchiveLimitException or ArchivePasswordException) throw;
            if (IsReadFailure(ex)) throw Translate(ex, match.IsEncrypted);
            throw;
        }
        return target;
    }

    /// <summary>
    /// Copies an entry while counting: the size and ratio limits apply to what is really
    /// produced, whatever the header claims.
    /// </summary>
    private static void CopyBounded(Stream input, Stream? output, long compressedSize, ArchiveLimits limits, long? stopAfter = null)
    {
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            total += read;
            if (total > limits.MaxEntryBytes)
                throw new ArchiveLimitException($"The entry is larger than {limits.MaxEntryBytes / (1024 * 1024)} MB; extraction was stopped.");
            if (total > limits.RatioCheckFloor && total / Math.Max(1, compressedSize) > limits.MaxCompressionRatio)
                throw new ArchiveLimitException($"The entry expands more than {limits.MaxCompressionRatio}:1 and looks like a compression bomb; extraction was stopped.");
            output?.Write(buffer, 0, read);
            if (total >= stopAfter) return;
        }
    }

    /// <summary>
    /// Reads the smallest encrypted entry through to the end (or the first 64 MB), so the
    /// decryption, decompression and CRC checks reject a wrong password. ZipCrypto's own
    /// password check is a single byte and lets one wrong password in 256 through.
    /// </summary>
    private static void VerifyPassword(IArchiveEntry entry)
    {
        try
        {
            using var s = entry.OpenEntryStream();
            CopyBounded(s, null, Math.Max(1, entry.CompressedSize), ArchiveLimits.Default, PasswordCheckBytes);
        }
        catch (ArchiveLimitException) { /* a big entry is not a wrong password */ }
        catch (Exception ex) when (IsReadFailure(ex))
        {
            throw new ArchivePasswordException("The password is wrong.", ex);
        }
    }

    /// <summary>
    /// Opens one of the five supported formats. The format is identified without the password
    /// first, because probing with a wrong password makes an encrypted ZIP look like no archive at
    /// all; other formats the library knows (ARC, ARJ, ACE) are refused to keep the surface small.
    /// </summary>
    private static IArchive Open(string path, string? password)
    {
        ArchiveType? type;
        try
        {
            if (!ArchiveFactory.IsArchive(path, out type)) type = null;
        }
        catch (Exception ex) when (IsReadFailure(ex))
        {
            throw Translate(ex, encrypted: false);
        }
        if (type is not (ArchiveType.Zip or ArchiveType.SevenZip or ArchiveType.Rar or ArchiveType.Tar or ArchiveType.GZip))
            throw new InvalidDataException("The file is not a supported archive (ZIP, 7z, RAR, TAR or GZip).");

        var options = new ReaderOptions { Password = password, LookForHeader = false, LeaveStreamOpen = false };
        try
        {
            return type switch
            {
                ArchiveType.Zip => ZipArchive.OpenArchive(path, options),
                ArchiveType.SevenZip => SevenZipArchive.OpenArchive(path, options),
                ArchiveType.Rar => RarArchive.OpenArchive(path, options),
                ArchiveType.Tar => TarArchive.OpenArchive(path, options),
                _ => GZipArchive.OpenArchive(path, options),
            };
        }
        catch (Exception ex) when (IsReadFailure(ex))
        {
            throw Translate(ex, encrypted: password is not null);
        }
    }

    /// <summary>The regular files of the archive, links counted and left out, cut at the entry limit.</summary>
    private static (List<(IArchiveEntry Entry, string Key)> Files, int Links, bool Truncated) Files(IArchive archive, string path, ArchiveLimits limits)
    {
        var files = new List<(IArchiveEntry, string)>();
        var links = 0;
        foreach (var e in archive.Entries)
        {
            if (e.IsDirectory) continue;
            if (IsLink(e)) { links++; continue; }
            if (files.Count >= limits.MaxEntries) return (files, links, true);
            files.Add((e, KeyOf(e, path)));
        }
        return (files, links, false);
    }

    private static bool IsLink(IArchiveEntry e) => !string.IsNullOrEmpty(e.LinkTarget);

    /// <summary>The entry's path; a GZip stream without a stored name is named after the archive.</summary>
    private static string KeyOf(IArchiveEntry entry, string archivePath)
    {
        if (!string.IsNullOrEmpty(entry.Key)) return entry.Key;
        var name = Path.GetFileName(archivePath);
        foreach (var ext in (string[])[".gz", ".tgz", ".gzip"])
            if (name.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                return ext == ".tgz" ? name[..^4] + ".tar" : name[..^ext.Length];
        return "data";
    }

    /// <summary>The first bytes of an entry, or null when it cannot be read (no password, damaged).</summary>
    private static byte[]? Head(IArchiveEntry entry)
    {
        try
        {
            using var s = entry.OpenEntryStream();
            var buffer = new byte[SniffBytes];
            var n = s.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
            return buffer[..n];
        }
        catch (Exception ex) when (IsReadFailure(ex))
        {
            if (entry.IsEncrypted && ex is CryptographicException) throw new ArchivePasswordException("The password is wrong.", ex);
            return null;
        }
    }

    /// <summary>What an entry is, by content when it could be read and by name otherwise.</summary>
    internal static FileKind KindOf(byte[]? head, string name)
    {
        if (head is { Length: > 0 })
        {
            var byContent = FileTypeDetector.Detect(head, name, pe: null);
            if (byContent != FileKind.Unknown) return byContent;
        }
        var ext = Path.GetExtension(name).ToLowerInvariant();
        return ext switch
        {
            ".exe" or ".scr" or ".com" or ".pif" => FileKind.Executable,
            ".dll" or ".ocx" or ".cpl" => FileKind.Dll,
            ".sys" => FileKind.Driver,
            ".msi" => FileKind.Msi,
            ".lnk" => FileKind.Shortcut,
            ".zip" or ".7z" or ".rar" or ".tar" or ".gz" or ".tgz" or ".bz2" or ".xz" or ".cab" or ".iso" or ".img" or ".vhd" or ".vhdx" => FileKind.Archive,
            ".doc" or ".docx" or ".docm" or ".xls" or ".xlsx" or ".xlsm" or ".xlsb" or ".ppt" or ".pptx" or ".pptm" or ".pdf" or ".rtf"
                or ".odt" or ".ods" or ".odp" or ".one" => FileKind.Document,
            _ => FileTypeDetector.Detect([], name, pe: null),
        };
    }

    private static readonly HashSet<string> DeviceNames = new(
        ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
         "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³",
         "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³"],
        StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// A single file name that is safe on Windows and Linux: the last path segment only, Windows
    /// reserved characters (including ':' for alternate streams) and invisible characters replaced,
    /// no trailing dots or spaces, no device names, at most 120 characters.
    /// </summary>
    internal static string SafeFileName(string entryPath)
    {
        var last = entryPath.Replace('\\', '/').TrimEnd('/');
        last = last[(last.LastIndexOf('/') + 1)..];

        var sb = new StringBuilder(last.Length);
        foreach (var c in last)
        {
            var bad = c < 0x20 || c == 0x7F || c is '<' or '>' or ':' or '"' or '/' or '\\' or '|' or '?' or '*'
                || CharUnicodeInfo.GetUnicodeCategory(c) is UnicodeCategory.Format or UnicodeCategory.Surrogate or UnicodeCategory.OtherNotAssigned;
            sb.Append(bad ? '_' : c);
        }
        var name = sb.ToString().Trim().TrimEnd('.', ' ');
        if (name.Length == 0 || name.All(c => c == '.')) name = "entry";

        var stem = name.Split('.')[0].TrimEnd(' ');
        if (DeviceNames.Contains(stem)) name = "_" + name;

        if (name.Length > 120)
        {
            var ext = Path.GetExtension(name);
            if (ext.Length > 20) ext = "";
            name = name[..(120 - ext.Length)] + ext;
        }
        return name;
    }

    /// <summary>A path inside <paramref name="folder"/> that does not exist yet; never escapes the folder.</summary>
    private static string UniquePath(string folder, string name)
    {
        var root = folder.EndsWith(Path.DirectorySeparatorChar) ? folder : folder + Path.DirectorySeparatorChar;
        var stem = Path.GetFileNameWithoutExtension(name);
        var ext = Path.GetExtension(name);
        for (var i = 1; i < 10_000; i++)
        {
            var candidate = Path.GetFullPath(Path.Combine(root, i == 1 ? name : $"{stem} ({i}){ext}"));
            if (!candidate.StartsWith(root, StringComparison.Ordinal) || Path.GetDirectoryName(candidate) + Path.DirectorySeparatorChar != root)
                throw new ArchiveLimitException("The entry name would leave the destination folder.");
            if (!File.Exists(candidate) && !Directory.Exists(candidate)) return candidate;
        }
        throw new IOException("Too many files with the same name in the destination folder.");
    }

    private static string FormatName(ArchiveType type) => type switch
    {
        ArchiveType.Zip => "ZIP",
        ArchiveType.SevenZip => "7z",
        ArchiveType.Rar => "RAR",
        ArchiveType.Tar => "TAR",
        ArchiveType.GZip => "GZip",
        _ => type.ToString(),
    };

    /// <summary>Exceptions a damaged or hostile archive can cause inside the library; anything else is a bug and propagates.</summary>
    private static bool IsReadFailure(Exception ex) =>
        ex is SharpCompressException or InvalidDataException or IOException or InvalidOperationException or NotSupportedException
            or ArgumentException or IndexOutOfRangeException or OverflowException or NullReferenceException or FormatException
            or System.Security.Cryptography.CryptographicException
        && ex is not (ArchivePasswordException or ArchiveLimitException or FileNotFoundException or DirectoryNotFoundException or UnauthorizedAccessException);

    private static Exception Translate(Exception ex, bool encrypted) => ex switch
    {
        ArchivePasswordException or ArchiveLimitException => ex,
        CryptographicException or System.Security.Cryptography.CryptographicException => new ArchivePasswordException("The archive is encrypted and the password is missing or wrong.", ex),
        _ when encrypted => new ArchivePasswordException("The archive could not be decrypted; the password is probably wrong.", ex),
        InvalidFormatException or ArchiveOperationException => new InvalidDataException("The file is not a supported archive, or it is damaged.", ex),
        _ => new InvalidDataException("The archive is damaged or could not be read.", ex),
    };

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (IOException) { /* best effort */ }
        catch (UnauthorizedAccessException) { /* best effort */ }
    }
}

/// <summary>The safety limits, adjustable for tests so a bomb does not need gigabytes.</summary>
internal sealed record ArchiveLimits(int MaxEntries, long MaxEntryBytes, int MaxCompressionRatio, long RatioCheckFloor, int SniffEntries)
{
    public static ArchiveLimits Default { get; } = new(ArchiveReader.MaxEntries, ArchiveReader.MaxEntryBytes, ArchiveReader.MaxCompressionRatio, 16L * 1024 * 1024, 500);
}
