using System.Text;
using Blazma.Core.Analysis;
using Blazma.Reporting.Interop;
using ICSharpCode.SharpZipLib.Zip;

namespace Blazma.Reporting.Tests;

public sealed class SampleArchiveExporterTests : IDisposable
{
    private readonly DirectoryInfo _dir = Directory.CreateTempSubdirectory("blz-archive");

    public void Dispose()
    {
        try { _dir.Delete(recursive: true); } catch (IOException) { }
    }

    private string File(string name, string content)
    {
        var path = Path.Combine(_dir.FullName, name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        System.IO.File.WriteAllText(path, content);
        return path;
    }

    private static async Task<MemoryStream> Archive(IEnumerable<SampleArchiveItem> items, string password = SampleArchiveExporter.DefaultPassword)
    {
        var ms = new MemoryStream();
        await new SampleArchiveExporter().ExportAsync(items, ms, password);
        ms.Position = 0;
        return ms;
    }

    private static string Read(ZipFile zip, ZipEntry entry)
    {
        using var s = zip.GetInputStream(entry);
        using var reader = new StreamReader(s, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    [Theory]
    [InlineData("setup.exe", "setup.exe_")]
    [InlineData("already.exe_", "already.exe_")]
    [InlineData(@"..\..\Windows\evil.exe", "evil.exe_")]
    [InlineData("../../etc/evil.sh", "evil.sh_")]
    [InlineData("bad:name?.exe", "bad_name_.exe_")]
    [InlineData("..", "file_")]
    [InlineData("برنامج.exe", "برنامج.exe_")]
    public void Names_are_defanged_and_flattened(string name, string expected) =>
        Assert.Equal(expected, SampleArchiveExporter.DefangName(name));

    [Fact]
    public async Task Archive_is_aes256_encrypted_and_readable_with_the_password()
    {
        var setup = File("setup.exe", "MZ fake setup");
        var dll = File("sub/payload.dll", "MZ fake dll");
        var dup = File("other/setup.exe", "MZ second setup");
        using var ms = await Archive([new(setup), new(dll), new(dup)]);

        using var zip = new ZipFile(ms) { Password = SampleArchiveExporter.DefaultPassword };
        var entries = zip.Cast<ZipEntry>().ToList();
        Assert.Equal(["README.txt", "setup.exe_", "payload.dll_", "setup (2).exe_"], entries.Select(e => e.Name));
        Assert.All(entries, e =>
        {
            Assert.True(e.IsCrypted);
            Assert.Equal(256, e.AESKeySize);
        });
        Assert.Equal("MZ fake setup", Read(zip, entries[1]));
        Assert.Equal("MZ fake dll", Read(zip, entries[2]));
        Assert.Equal("MZ second setup", Read(zip, entries[3]));

        var readme = Read(zip, entries[0]);
        Assert.Contains("WARNING", readme, StringComparison.Ordinal);
        Assert.Contains("Password: infected", readme, StringComparison.Ordinal);
        Assert.Contains("setup (2).exe_ | setup.exe | 15 |", readme, StringComparison.Ordinal);
        Assert.Contains("تحذير", readme, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Archive_cannot_be_read_without_the_right_password()
    {
        using var ms = await Archive([new(File("setup.exe", "MZ fake setup"))], "s3cret");

        using (var noPassword = new ZipFile(ms) { IsStreamOwner = false })
        {
            var entry = noPassword.GetEntry("setup.exe_");
            Assert.ThrowsAny<Exception>(() => Read(noPassword, entry));
        }
        ms.Position = 0;
        using (var wrong = new ZipFile(ms) { IsStreamOwner = false, Password = SampleArchiveExporter.DefaultPassword })
        {
            var entry = wrong.GetEntry("setup.exe_");
            Assert.ThrowsAny<Exception>(() => Read(wrong, entry));
        }
        ms.Position = 0;
        using var right = new ZipFile(ms) { Password = "s3cret" };
        Assert.Equal("MZ fake setup", Read(right, right.GetEntry("setup.exe_")));
    }

    [Fact]
    public async Task Empty_password_is_rejected()
    {
        await Assert.ThrowsAnyAsync<ArgumentException>(() => new SampleArchiveExporter().ExportAsync([], new MemoryStream(), ""));
    }

    [Fact]
    public void Dropped_files_resolve_inside_the_artifact_folder_only()
    {
        File(Path.Combine("artifacts", "dropped", "0001.bin_"), "x");
        File("outside.bin", "y");
        var a = TestData.Demo();
        a.DroppedFiles =
        [
            new DroppedFileInfo { OriginalPath = @"C:\Users\x\AppData\Roaming\updater.exe", ProcessName = "setup.exe", Sha256 = new string('a', 64), Size = 1, StoredName = "dropped/0001.bin_" },
            new DroppedFileInfo { OriginalPath = @"C:\evil.exe", ProcessName = "setup.exe", Sha256 = new string('b', 64), Size = 1, StoredName = "../outside.bin" },
            new DroppedFileInfo { OriginalPath = @"C:\missing.exe", ProcessName = "setup.exe", Sha256 = new string('c', 64), Size = 1, StoredName = "dropped/missing.bin_" },
        ];
        var item = Assert.Single(SampleArchiveExporter.DroppedFiles(a, Path.Combine(_dir.FullName, "artifacts")));
        Assert.Equal("updater.exe", item.Name);
    }
}
