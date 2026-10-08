using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Blazma.Core.Analysis;
using ICSharpCode.SharpZipLib.Zip;

namespace Blazma.Reporting.Interop;

/// <summary>A file to put in a sample archive, and the name it should be known by (defaults to its file name).</summary>
public sealed record SampleArchiveItem(string SourcePath, string? Name = null);

/// <summary>
/// Packs samples and dropped files the way analysts exchange them: an AES-256 encrypted ZIP
/// with the conventional password "infected" (so mail filters and antivirus leave it alone;
/// it is a handling convention, not secrecy), every file renamed so it cannot be started by
/// double-clicking (<c>setup.exe</c> becomes <c>setup.exe_</c>), and a README that says what
/// is inside. Files are only read, never opened or run.
/// </summary>
public sealed class SampleArchiveExporter
{
    public const string DefaultPassword = "infected";
    public const string ReadmeName = "README.txt";
    public const string FileExtension = ".zip";

    /// <summary>Fixed entry time: the archive's metadata does not leak when it was made or reveal host clock settings.</summary>
    private static readonly DateTime EntryTime = new(2000, 1, 1, 0, 0, 0, DateTimeKind.Unspecified);

    public async Task ExportAsync(IEnumerable<SampleArchiveItem> items, Stream destination, string password = DefaultPassword, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        var list = items.ToList();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ReadmeName };
        var entries = new List<(SampleArchiveItem Item, string Original, string Stored, long Size, string Sha256)>();
        foreach (var item in list)
        {
            var original = SafeFileName(item.Name ?? Path.GetFileName(item.SourcePath));
            var stored = Unique(original, names);
            var (size, sha) = await HashAsync(item.SourcePath, cancellationToken).ConfigureAwait(false);
            entries.Add((item, original, stored, size, sha));
        }

        using var zip = new ZipOutputStream(destination) { IsStreamOwner = false, Password = password };
        zip.SetLevel(6);
        zip.SetComment("Contains potentially harmful files collected by Blazma Sandbox. Password-protected (AES-256); see README.txt. Do not run outside an isolated environment.");

        var readme = Encoding.UTF8.GetBytes(Readme(entries.Select(e => (e.Original, e.Stored, e.Size, e.Sha256)), password));
        await PutAsync(zip, ReadmeName, new MemoryStream(readme), cancellationToken).ConfigureAwait(false);
        foreach (var e in entries)
        {
            var source = new FileStream(e.Item.SourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan);
            await using (source.ConfigureAwait(false))
                await PutAsync(zip, e.Stored, source, cancellationToken).ConfigureAwait(false);
        }
        await zip.FinishAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The analysis' dropped files that are present in its artifact folder, named after their
    /// original file names. Stored names that would leave the folder are ignored.
    /// </summary>
    public static IReadOnlyList<SampleArchiveItem> DroppedFiles(AnalysisResult result, string artifactFolder)
    {
        var root = Path.GetFullPath(artifactFolder);
        var prefix = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        var items = new List<SampleArchiveItem>();
        foreach (var d in result.DroppedFiles)
        {
            if (string.IsNullOrEmpty(d.StoredName)) continue;
            var path = Path.GetFullPath(Path.Combine(root, d.StoredName));
            if (!path.StartsWith(prefix, StringComparison.Ordinal) || !File.Exists(path)) continue;
            items.Add(new SampleArchiveItem(path, LastSegment(d.OriginalPath)));
        }
        return items;
    }

    /// <summary>Appends '_' so Windows no longer associates the file with a program; already-defanged names are kept.</summary>
    public static string DefangName(string name)
    {
        var safe = SafeFileName(name);
        return safe.EndsWith('_') ? safe : safe + "_";
    }

    /// <summary>
    /// The last path segment (either separator), with control and reserved characters replaced,
    /// so an entry can never carry a directory or traversal into the archive.
    /// </summary>
    private static string SafeFileName(string name)
    {
        var sb = new StringBuilder();
        foreach (var c in LastSegment(name))
            sb.Append(char.IsControl(c) || c is ':' or '*' or '?' or '"' or '<' or '>' or '|' ? '_' : c);
        var s = sb.ToString().Trim().TrimEnd('.');
        return s.Length == 0 || s is "." or ".." ? "file" : s;
    }

    private static string LastSegment(string path)
    {
        var i = path.LastIndexOfAny(['\\', '/']);
        return i >= 0 ? path[(i + 1)..] : path;
    }

    private static string Unique(string original, HashSet<string> used)
    {
        var name = DefangName(original);
        var stem = Path.GetFileNameWithoutExtension(original);
        var ext = Path.GetExtension(original);
        for (var n = 2; !used.Add(name); n++)
            name = DefangName(string.Create(CultureInfo.InvariantCulture, $"{stem} ({n}){ext}"));
        return name;
    }

    private static async Task PutAsync(ZipOutputStream zip, string name, Stream content, CancellationToken ct)
    {
        var entry = new ZipEntry(name) { DateTime = EntryTime, AESKeySize = 256, IsUnicodeText = true };
        await zip.PutNextEntryAsync(entry, ct).ConfigureAwait(false);
        await content.CopyToAsync(zip, ct).ConfigureAwait(false);
        await zip.CloseEntryAsync(ct).ConfigureAwait(false);
    }

    private static async Task<(long Size, string Sha256)> HashAsync(string path, CancellationToken ct)
    {
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using (stream.ConfigureAwait(false))
        {
            var hash = await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false);
            return (stream.Length, Convert.ToHexStringLower(hash));
        }
    }

    private static string Readme(IEnumerable<(string Original, string Stored, long Size, string Sha256)> entries, string password)
    {
        var sb = new StringBuilder();
        sb.Append("WARNING: POTENTIALLY HARMFUL FILES\n");
        sb.Append("==================================\n\n");
        sb.Append("This archive was created by Blazma Sandbox. The files in it were submitted for analysis or\n");
        sb.Append("created by analyzed programs, and may be malicious. Handle them only in an isolated analysis\n");
        sb.Append("environment, never on a production or personal machine.\n\n");
        sb.Append("- Each file name ends with \"_\" so it cannot be started by double-clicking. Do not rename it back\n");
        sb.Append("  outside an isolated environment.\n");
        sb.Append(CultureInfo.InvariantCulture, $"- The archive is encrypted with AES-256. Password: {password}\n");
        sb.Append("  (an industry convention that keeps mail filters and antivirus from acting on the contents; it is\n");
        sb.Append("  not meant to keep the files secret).\n\n");
        sb.Append("تحذير: ملفات قد تكون ضارة. أُنشئ هذا الأرشيف بواسطة Blazma Sandbox. لا تتعامل مع هذه الملفات إلا داخل\n");
        sb.Append("بيئة تحليل معزولة. أُضيف \"_\" إلى نهاية كل اسم ملف حتى لا يعمل بالنقر المزدوج.\n\n");
        sb.Append("Contents (stored name | original name | size in bytes | SHA-256):\n");
        foreach (var (original, stored, size, sha) in entries)
            sb.Append(CultureInfo.InvariantCulture, $"{stored} | {original} | {size} | {sha}\n");
        return sb.ToString();
    }
}
