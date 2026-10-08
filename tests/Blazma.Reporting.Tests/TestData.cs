using System.Security.Cryptography;
using System.Text;
using Blazma.Analysis.Engine;
using Blazma.Analysis.Rules;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Samples;
using Blazma.Sandbox.Providers.Demo;

namespace Blazma.Reporting.Tests;

/// <summary>Deterministic analyses: the demo scenario run through the real engine with fixed times and IDs.</summary>
internal static class TestData
{
    public static readonly DateTimeOffset Start = new(2026, 10, 7, 10, 0, 0, 250, TimeSpan.Zero);
    public static readonly Guid AnalysisId = Guid.Parse("3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b");

    public static ExportOptions Options(bool redact = false, string language = "en") => new(language, redact, false, true, true, true, 200);

    public static AnalysisResult Demo(string name = "setup.exe")
    {
        var scenario = DemoScenario.For(name, Start);
        var sample = Sample(name);
        var result = new AnalysisResult
        {
            AnalysisId = AnalysisId,
            Sample = sample,
            Static = Static(sample),
            Options = new AnalysisOptions(),
            ProviderId = "demo",
            IsDemo = true,
            StartedAt = Start,
            CompletedAt = Start.AddSeconds(125),
        };
        new AnalysisEngine(new RuleEngine(RuleEngine.BuiltInRules())).Process(result, scenario.Events, scenario.Baseline, scenario.After, new EngineSettings());
        return result;
    }

    public static SampleInfo Sample(string name) => new()
    {
        FileName = name,
        Size = 1_843_200,
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(name))),
#pragma warning disable CA5350 // test data only
        Sha1 = Convert.ToHexStringLower(SHA1.HashData(Encoding.UTF8.GetBytes(name))),
#pragma warning restore CA5350
        Kind = FileKind.Executable,
    };

    public static StaticReport Static(SampleInfo sample) => new()
    {
        Sample = sample,
        Pe = new PeInfo { Machine = "x64", Is64Bit = true, IsDll = false, Subsystem = "Windows GUI", IsDotNet = false },
        ImpHash = "f34d5f2d4577ed6d9ceec516c1f5a744",
        Strings =
        [
            new(InterestingStringKind.Domain, "api.contoso-update.example"),
            new(InterestingStringKind.Url, "https://api.contoso-update.example/v1/check?id=\"x\""),
            new(InterestingStringKind.Command, "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand"),
            new(InterestingStringKind.RegistryPath, @"Software\Microsoft\Windows\CurrentVersion\Run"),
            new(InterestingStringKind.FilePath, @"C:\Users\WDAGUtilityAccount\AppData\Roaming\ContosoUpdate\updater.exe"),
            new(InterestingStringKind.IpAddress, "203.0.113.24"),
            new(InterestingStringKind.Command, "schtasks /create /tn \"ContosoUpdateTask\" /sc hourly\t/f"),
            new(InterestingStringKind.FilePath, "short"),
        ],
        Artifacts = [new(ArtifactKind.MutexName, "Global\\ContosoUpdaterMutex", "sample")],
    };
}
