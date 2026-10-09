using System.Formats.Tar;
using System.IO.Compression;
using Blazma.Analysis.Archives;
using Blazma.Analysis.Static;
using Blazma.Core.Samples;
using ZipEntry = ICSharpCode.SharpZipLib.Zip.ZipEntry;
using ZipOutputStream = ICSharpCode.SharpZipLib.Zip.ZipOutputStream;
using SharpCompress.Common;
using SharpCompress.Writers;
using SharpCompress.Writers.SevenZip;

namespace Blazma.Analysis.Tests;

public sealed class ArchiveReaderTests : IDisposable
{
    private static readonly byte[] Mz = [(byte)'M', (byte)'Z', 0x90, 0, 3, 0, 0, 0];
    private readonly DirectoryInfo _dir = Directory.CreateTempSubdirectory("blazma-archive-tests-");

    public void Dispose() => _dir.Delete(recursive: true);

    private string PathFor(string name) => Path.Combine(_dir.FullName, name);
    private string Out => Directory.CreateDirectory(PathFor("out")).FullName;

    private string Zip(string name, params (string Name, byte[] Data)[] entries)
    {
        var path = PathFor(name);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (entryName, data) in entries)
        {
            using var s = zip.CreateEntry(entryName, CompressionLevel.Optimal).Open();
            s.Write(data);
        }
        return path;
    }

    /// <summary>A password-protected ZIP: AES-256 by default, classic ZipCrypto with <paramref name="aesKeySize"/> 0.</summary>
    private string EncryptedZip(string name, string password, int aesKeySize, params (string Name, byte[] Data)[] entries)
    {
        var path = PathFor(name);
        using var zip = new ZipOutputStream(File.Create(path)) { Password = password };
        foreach (var (entryName, data) in entries)
        {
            zip.PutNextEntry(new ZipEntry(entryName) { AESKeySize = aesKeySize, Size = data.Length });
            zip.Write(data);
            zip.CloseEntry();
        }
        return path;
    }

    private static byte[] Random(int n, int seed = 1)
    {
        var b = new byte[n];
        new Random(seed).NextBytes(b);
        return b;
    }

    [Fact]
    public void A_zip_is_listed_with_kinds_from_content_and_name()
    {
        var path = Zip("plain.zip", ("bin/tool.exe", Mz), ("readme.txt", "hello"u8.ToArray()), ("disguised.txt", Mz), ("inner.zip", File.ReadAllBytes(Zip("inner.zip", ("a.txt", "a"u8.ToArray())))));
        var info = ArchiveReader.List(path, null);
        Assert.Equal("ZIP", info.Format);
        Assert.False(info.Encrypted);
        Assert.Null(info.LimitNote);
        Assert.Equal(FileKind.Executable, info.Entries.Single(e => e.Path == "bin/tool.exe").Kind);
        Assert.Equal(FileKind.Executable, info.Entries.Single(e => e.Path == "disguised.txt").Kind);
        Assert.Equal(FileKind.Unknown, info.Entries.Single(e => e.Path == "readme.txt").Kind);
        Assert.Equal(FileKind.Archive, info.Entries.Single(e => e.Path == "inner.zip").Kind);
        Assert.Equal(Mz.Length, info.Entries.Single(e => e.Path == "bin/tool.exe").Size);
    }

    [Fact]
    public void A_nested_archive_is_extracted_as_a_file_not_opened()
    {
        var inner = Zip("inner.zip", ("payload.exe", Mz));
        var outer = Zip("outer.zip", ("level1/inner.zip", File.ReadAllBytes(inner)));
        var extracted = ArchiveReader.ExtractEntry(outer, "level1/inner.zip", null, Out);
        Assert.Equal("inner.zip", Path.GetFileName(extracted));
        Assert.Equal(File.ReadAllBytes(inner), File.ReadAllBytes(extracted));
        Assert.Single(Directory.GetFileSystemEntries(Out));
    }

    [Theory]
    [InlineData("../../evil.exe", "evil.exe")]
    [InlineData("..\\..\\Windows\\win.ini", "win.ini")]
    [InlineData("C:\\Windows\\System32\\x.dll", "x.dll")]
    [InlineData("/etc/cron.d/job", "job")]
    [InlineData("docs/report.pdf:Zone.Identifier", "report.pdf_Zone.Identifier")]
    [InlineData("dir/CON.txt", "_CON.txt")]
    [InlineData("nul", "_nul")]
    [InlineData("COM1.tar.gz", "_COM1.tar.gz")]
    [InlineData("invoice\u202Etxt.exe", "invoice_txt.exe")]
    [InlineData("trailing. . ", "trailing")]
    [InlineData("..", "entry")]
    public void Entry_names_are_flattened_and_sanitized(string entryName, string expected)
    {
        var path = Zip("names.zip", (entryName, "x"u8.ToArray()));
        var extracted = ArchiveReader.ExtractEntry(path, entryName, null, Out);
        Assert.Equal(Out, Path.GetDirectoryName(extracted));
        Assert.Equal(expected, Path.GetFileName(extracted));
    }

    [Fact]
    public void Extracting_the_same_name_twice_never_overwrites()
    {
        var path = Zip("dup.zip", ("a/x.exe", Mz), ("b/x.exe", "other"u8.ToArray()));
        var first = ArchiveReader.ExtractEntry(path, "a/x.exe", null, Out);
        var second = ArchiveReader.ExtractEntry(path, "b/x.exe", null, Out);
        Assert.NotEqual(first, second);
        Assert.Equal(Mz, File.ReadAllBytes(first));
    }

    [Fact]
    public void A_compression_bomb_is_stopped_while_streaming_and_leaves_nothing_behind()
    {
        var path = Zip("bomb.zip", ("zeros.bin", new byte[8 * 1024 * 1024]));
        var limits = ArchiveLimits.Default with { RatioCheckFloor = 1024 * 1024 };
        var info = ArchiveReader.List(path, null, limits);
        Assert.Contains("compression bomb", info.LimitNote, StringComparison.Ordinal);
        Assert.Throws<ArchiveLimitException>(() => ArchiveReader.ExtractEntry(path, "zeros.bin", null, Out, limits));
        Assert.Empty(Directory.GetFileSystemEntries(Out));
    }

    [Fact]
    public void The_size_limit_counts_real_bytes()
    {
        var path = Zip("big.zip", ("big.bin", Random(3 * 1024 * 1024)));
        var limits = ArchiveLimits.Default with { MaxEntryBytes = 1024 * 1024 };
        Assert.Throws<ArchiveLimitException>(() => ArchiveReader.ExtractEntry(path, "big.bin", null, Out, limits));
        Assert.Empty(Directory.GetFileSystemEntries(Out));
    }

    [Fact]
    public void Listing_stops_at_the_entry_limit_with_a_note()
    {
        var path = Zip("many.zip", Enumerable.Range(0, 60).Select(i => ($"f{i:D3}.txt", new[] { (byte)i })).ToArray());
        var limits = ArchiveLimits.Default with { MaxEntries = 50 };
        var info = ArchiveReader.List(path, null, limits);
        Assert.Equal(50, info.Entries.Count);
        Assert.NotNull(info.LimitNote);
        Assert.Throws<FileNotFoundException>(() => ArchiveReader.ExtractEntry(path, "f055.txt", null, Out, limits));
        Assert.Equal(60, ArchiveReader.List(path, null).Entries.Count);
    }

    [Theory]
    [InlineData(256)]
    [InlineData(0)]
    public void Encrypted_zips_open_with_the_right_password_only(int aesKeySize)
    {
        var path = EncryptedZip($"enc{aesKeySize}.zip", "infected", aesKeySize, ("sample.exe", Mz), ("notes.txt", Random(5000)));

        var listed = ArchiveReader.List(path, null);
        Assert.True(listed.Encrypted);
        Assert.All(listed.Entries, e => Assert.True(e.Encrypted));
        Assert.Equal(FileKind.Executable, listed.Entries.Single(e => e.Path == "sample.exe").Kind); // by name only

        Assert.Throws<ArchivePasswordException>(() => ArchiveReader.List(path, "wrong-password"));
        Assert.Throws<ArchivePasswordException>(() => ArchiveReader.ExtractEntry(path, "sample.exe", "wrong-password", Out));
        Assert.Throws<ArchivePasswordException>(() => ArchiveReader.ExtractEntry(path, "sample.exe", null, Out));
        Assert.Empty(Directory.GetFileSystemEntries(Out));

        var extracted = ArchiveReader.ExtractEntry(path, "sample.exe", "infected", Out);
        Assert.Equal(Mz, File.ReadAllBytes(extracted));
    }

    [Fact]
    public void TryOpen_tries_the_users_password_then_the_conventional_ones()
    {
        var custom = EncryptedZip("custom.zip", "s3cret!", 256, ("a.exe", Mz));
        Assert.NotNull(ArchiveReader.TryOpen(custom, ["nope", "s3cret!"], out var pw));
        Assert.Equal("s3cret!", pw);
        Assert.Null(ArchiveReader.TryOpen(custom, [], out pw));
        Assert.Null(pw);

        var conventional = EncryptedZip("conv.zip", "malware", 0, ("a.exe", Mz));
        var info = ArchiveReader.TryOpen(conventional, ["user-guess"], out pw);
        Assert.Equal("malware", pw);
        Assert.Equal(FileKind.Executable, Assert.Single(info!.Entries).Kind);

        var plain = Zip("plain.zip", ("a.exe", Mz));
        Assert.NotNull(ArchiveReader.TryOpen(plain, ["whatever"], out pw));
        Assert.Null(pw);

        File.WriteAllBytes(PathFor("junk.zip"), Random(1000));
        Assert.Null(ArchiveReader.TryOpen(PathFor("junk.zip"), [], out _));
        Assert.Throws<InvalidDataException>(() => ArchiveReader.List(PathFor("junk.zip"), null));
    }

    [Fact]
    public void Tar_links_are_skipped_and_never_extracted()
    {
        var path = PathFor("links.tar");
        using (var tar = new TarWriter(File.Create(path), TarEntryFormat.Pax, leaveOpen: false))
        {
            var file = new PaxTarEntry(TarEntryType.RegularFile, "app/run.sh") { DataStream = new MemoryStream("#!/bin/sh\n"u8.ToArray()) };
            tar.WriteEntry(file);
            tar.WriteEntry(new PaxTarEntry(TarEntryType.SymbolicLink, "app/passwd") { LinkName = "/etc/passwd" });
            tar.WriteEntry(new PaxTarEntry(TarEntryType.HardLink, "app/hosts") { LinkName = "/etc/hosts" });
        }

        var info = ArchiveReader.List(path, null);
        Assert.Equal("TAR", info.Format);
        Assert.Equal("app/run.sh", Assert.Single(info.Entries).Path);
        Assert.Contains("link", info.LimitNote, StringComparison.Ordinal);
        Assert.Throws<ArchiveLimitException>(() => ArchiveReader.ExtractEntry(path, "app/passwd", null, Out));
        Assert.Empty(Directory.GetFileSystemEntries(Out));
    }

    [Fact]
    public void A_gzip_stream_is_one_entry_named_after_the_archive()
    {
        var path = PathFor("dropper.exe.gz");
        using (var gz = new GZipStream(File.Create(path), CompressionLevel.Optimal))
            gz.Write(Mz);

        var info = ArchiveReader.List(path, null);
        Assert.Equal("GZip", info.Format);
        var entry = Assert.Single(info.Entries);
        Assert.Equal(FileKind.Executable, entry.Kind);
        var extracted = ArchiveReader.ExtractEntry(path, entry.Path, null, Out);
        Assert.Equal(Mz, File.ReadAllBytes(extracted));
    }

    [Fact]
    public void A_7z_archive_is_listed_and_extracted()
    {
        var path = PathFor("plain.7z");
        using (var stream = File.Create(path))
        using (var writer = WriterFactory.OpenWriter(stream, ArchiveType.SevenZip, new SevenZipWriterOptions(CompressionType.LZMA)))
        {
            writer.Write("x/payload.dll", new MemoryStream(Mz), null);
            writer.Write("x/inner.rar", new MemoryStream([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]), null);
        }

        var info = ArchiveReader.List(path, null);
        Assert.Equal("7z", info.Format);
        Assert.Equal(FileKind.Archive, info.Entries.Single(e => e.Path == "x/inner.rar").Kind);
        var extracted = ArchiveReader.ExtractEntry(path, "x/payload.dll", null, Out);
        Assert.Equal("payload.dll", Path.GetFileName(extracted));
        Assert.Equal(Mz, File.ReadAllBytes(extracted));
    }

    [Fact]
    public void The_conventional_passwords_are_the_usual_ones() =>
        Assert.Equal(["infected", "malware", "virus"], ArchiveReader.DefaultPasswords);

    [Fact]
    public void Documents_are_not_archives()
    {
        byte[] ole = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        Assert.Equal(FileKind.Document, FileTypeDetector.Detect(ole, "invoice.doc", null));
        Assert.Equal(FileKind.Msi, FileTypeDetector.Detect(ole, "setup.msi", null));
        Assert.Equal(FileKind.Document, FileTypeDetector.Detect("%PDF-1.7\n"u8, "a.pdf", null));
        Assert.Equal(FileKind.Document, FileTypeDetector.Detect("{\\rtf1\\ansi"u8, "a.rtf", null));

        var docx = File.ReadAllBytes(Zip("a.docx", ("[Content_Types].xml", "<Types/>"u8.ToArray()), ("word/document.xml", "<w/>"u8.ToArray())));
        var odt = File.ReadAllBytes(Zip("a.odt", ("mimetype", "application/vnd.oasis.opendocument.text"u8.ToArray())));
        var zip = File.ReadAllBytes(Zip("a.zip", ("password/list.txt", "x"u8.ToArray())));
        Assert.Equal(FileKind.Document, FileTypeDetector.Detect(docx.AsSpan(0, 64), "a.docx", null));
        Assert.Equal(FileKind.Document, FileTypeDetector.Detect(odt.AsSpan(0, 64), "a.odt", null));
        Assert.Equal(FileKind.Archive, FileTypeDetector.Detect(zip.AsSpan(0, 64), "a.zip", null));

        Assert.Equal(FileKind.Archive, FileTypeDetector.Detect([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4], "x.bin", null));
        Assert.Equal(FileKind.Archive, FileTypeDetector.Detect([0x1F, 0x8B, 8, 0], "x.bin", null));
    }
}
