using System.Text;
using Blazma.Analysis.Static;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Tests;

public class StaticAnalysisTests
{
    private sealed class NoVerify : ISignatureVerifier
    {
        public SignatureInfo Verify(string path, bool hasSignatureDirectory) =>
            new(hasSignatureDirectory ? SignatureStatus.PresentUnverified : SignatureStatus.NotSigned);
    }

    [Fact]
    public async Task Parses_a_real_PE_without_running_it()
    {
        // A safe fixture: Blazma's own analysis library is a PE file (a DLL).
        var path = typeof(PeParser).Assembly.Location;
        var report = await new StaticAnalyzer(new NoVerify()).AnalyzeAsync(path, CancellationToken.None);

        Assert.Empty(report.Warnings);
        Assert.Equal(64, report.Sample.Sha256.Length);
        Assert.Equal(40, report.Sample.Sha1.Length);
        Assert.Equal(FileKind.Dll, report.Sample.Kind);
        Assert.NotNull(report.Pe);
        Assert.True(report.Pe!.IsDotNet);
        Assert.Contains(report.Pe.Sections, s => s.Name == ".text");
        Assert.Contains(report.Pe.Imports, i => i.Library.Equals("mscoree.dll", StringComparison.OrdinalIgnoreCase));
        Assert.InRange(report.Entropy, 0, 8);
    }

    [Fact]
    public async Task Reads_version_information()
    {
        var path = typeof(object).Assembly.Location; // System.Private.CoreLib carries a VS_VERSIONINFO resource
        var report = await new StaticAnalyzer(new NoVerify()).AnalyzeAsync(path, CancellationToken.None);
        Assert.True(report.Pe!.ResourceCount > 0);
        Assert.Contains("Microsoft", report.Pe.VersionInfo.GetValueOrDefault("CompanyName") ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Malformed_and_random_files_never_throw()
    {
        var dir = Directory.CreateTempSubdirectory("blz-static");
        try
        {
            var rnd = new Random(42);
            var junk = new byte[4096];
            rnd.NextBytes(junk);
            var truncatedMz = new byte[] { (byte)'M', (byte)'Z', 0x90, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0xFF, 0xFF };
            var badLfanew = new byte[256];
            badLfanew[0] = (byte)'M'; badLfanew[1] = (byte)'Z';
            BitConverter.GetBytes(0x7FFFFFF0).CopyTo(badLfanew, 0x3C);

            foreach (var (name, bytes) in new[] { ("junk.bin", junk), ("trunc.exe", truncatedMz), ("lfanew.exe", badLfanew), ("empty.exe", Array.Empty<byte>()) })
            {
                var p = Path.Combine(dir.FullName, name);
                await File.WriteAllBytesAsync(p, bytes);
                var report = await new StaticAnalyzer(new NoVerify()).AnalyzeAsync(p, CancellationToken.None);
                Assert.Null(report.Pe);
            }
        }
        finally { dir.Delete(true); }
    }

    [Theory]
    [InlineData("install.ps1", FileKind.PowerShell)]
    [InlineData("run.bat", FileKind.Batch)]
    [InlineData("a.vbs", FileKind.VbScript)]
    [InlineData("notes.txt", FileKind.Unknown)]
    public void Script_types_are_detected_by_extension(string name, FileKind kind) =>
        Assert.Equal(kind, FileTypeDetector.Detect("text"u8, name, null));

    [Fact]
    public void Entropy_is_zero_for_uniform_data_and_high_for_random_data()
    {
        Assert.Equal(0, Entropy.Of(new byte[1000]));
        var random = new byte[65536];
        new Random(1).NextBytes(random);
        Assert.True(Entropy.Of(random) > 7.9);
    }

    [Fact]
    public void Extracts_only_interesting_strings()
    {
        var data = Encoding.ASCII.GetBytes("xx\0http://evil.example/payload.bin\0hello world\0198.51.100.7\0HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\0")
            .Concat(Encoding.Unicode.GetBytes("powershell.exe -enc AAAA\0")).ToArray();
        var strings = StringExtractor.Extract(data);
        Assert.Contains(strings, s => s.Kind == InterestingStringKind.Url && s.Value.StartsWith("http://evil.example", StringComparison.Ordinal));
        Assert.Contains(strings, s => s.Kind == InterestingStringKind.IpAddress && s.Value == "198.51.100.7");
        Assert.Contains(strings, s => s.Kind == InterestingStringKind.RegistryPath);
        Assert.Contains(strings, s => s.Kind == InterestingStringKind.Command);
        Assert.DoesNotContain(strings, s => s.Value == "hello world");
    }
}
