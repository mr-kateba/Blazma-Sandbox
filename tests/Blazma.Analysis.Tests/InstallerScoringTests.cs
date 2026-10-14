using Blazma.Analysis.Engine;
using Blazma.Core.Findings;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Tests;

/// <summary>Everyday installers must not look like malware; droppers must stay high even when wrapped in an installer or signed.</summary>
public class InstallerScoringTests
{
    public static TheoryData<string> SafeInstallers => new()
    {
        "inno", "nsis", "msi", "msi-offline", "squirrel", "web-installer", "quiet", "quiet-noise",
    };

    private static Scenarios.Scenario Pick(string key) => key switch
    {
        "inno" => Scenarios.InnoSetupSigned(),
        "nsis" => Scenarios.NsisUnsigned(),
        "msi" => Scenarios.MsiWithService(),
        "msi-offline" => Scenarios.MsiWithService(false),
        "squirrel" => Scenarios.SquirrelSigned(),
        "web-installer" => Scenarios.SignedUpdaterInstaller(),
        "quiet" => Scenarios.QuietConsoleTool(false),
        "quiet-noise" => Scenarios.QuietConsoleTool(true),
        _ => throw new ArgumentOutOfRangeException(nameof(key)),
    };

    [Theory]
    [MemberData(nameof(SafeInstallers))]
    public void Ordinary_installers_stay_below_high_risk(string key)
    {
        var result = Pick(key).Run();
        Assert.True(result.Risk.Verdict is Verdict.LowRisk or Verdict.Suspicious, $"{key}: {result.Risk.Score} {result.Risk.Verdict}");
    }

    [Fact]
    public void Discounted_findings_say_why()
    {
        var result = Scenarios.InnoSetupSigned().Run();
        Assert.Contains(result.Findings, f => f.Explanation.En.Contains("counts for less", StringComparison.Ordinal) && f.Explanation.Ar.Contains("بوزن أقل", StringComparison.Ordinal));
    }

    [Fact]
    public void Trusting_the_publisher_lowers_a_signed_installer_further()
    {
        var plain = Scenarios.SquirrelSigned().Run();
        var trusted = Scenarios.SquirrelSigned().Run(new EngineSettings { TrustedPublishers = ["Northwind Traders Ltd"] });
        Assert.True(trusted.Risk.Score < plain.Risk.Score);
        Assert.Equal(Verdict.LowRisk, trusted.Risk.Verdict);
    }

    [Fact]
    public void Droppers_stay_high_even_when_signed_or_wrapped_in_an_installer()
    {
        Assert.Equal(Verdict.CriticalBehavior, Scenarios.StealthyDropper().Run().Risk.Verdict);
        // Stealth (a hidden command, deleting itself) cancels any installer discount, signature or not.
        Assert.Equal(Verdict.CriticalBehavior, Scenarios.StealthyDropper(SignatureStatus.Valid, "Some Company").Run().Risk.Verdict);
        Assert.True(Scenarios.NsisWrappedDropper().Run().Risk.Verdict >= Verdict.HighRiskBehavior);
    }
}
