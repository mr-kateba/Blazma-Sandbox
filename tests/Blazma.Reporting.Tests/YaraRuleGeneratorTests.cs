using System.Text.RegularExpressions;
using Blazma.Core.Samples;
using Blazma.Reporting.Interop;

namespace Blazma.Reporting.Tests;

public partial class YaraRuleGeneratorTests
{
    private static readonly DateOnly Date = new(2026, 10, 7);

    [GeneratedRegex(@"^\s*\$s\d+ = ""((?:[^""\\]|\\.)*)"" ascii wide$", RegexOptions.Multiline)]
    private static partial Regex StringLine();

    [Fact]
    public void Escaping_follows_yara_text_string_rules()
    {
        Assert.Equal(@"a\""b\\c\td\ne\rf", YaraRuleGenerator.Escape("a\"b\\c\td\ne\rf"));
        Assert.Equal(@"x\x01y\x7f", YaraRuleGenerator.Escape("x\u0001y\u007f"));
        Assert.Equal(@"\xd8\xb9", YaraRuleGenerator.Escape("ع"));
        Assert.Equal(@"C:\\Users\\x", YaraRuleGenerator.Escape(@"C:\Users\x"));
    }

    [Fact]
    public void Rule_names_are_valid_identifiers()
    {
        Assert.Equal("Blazma_Draft_setup_e4fd277e", YaraRuleGenerator.RuleName("setup.exe", "e4fd277eda17a946afd024f2d1478243e70df236282cbeeb36e764d492f74247"));
        Assert.Equal("Blazma_Draft_my_evil_file_v2", YaraRuleGenerator.RuleName("my evil--file (v2).exe", "nothex"));
        Assert.Equal("Blazma_Draft_00000000", YaraRuleGenerator.RuleName("برنامج.exe", new string('0', 64)));
        Assert.Matches(@"^[A-Za-z_][A-Za-z0-9_]{0,127}$", YaraRuleGenerator.RuleName(new string('a', 500) + ".exe", new string('f', 64)));
    }

    [Fact]
    public void File_size_limit_is_rounded()
    {
        Assert.Equal(4000, YaraRuleGenerator.FileSizeLimitKb(1_843_200));
        Assert.Equal(10, YaraRuleGenerator.FileSizeLimitKb(100));
        Assert.Equal(200, YaraRuleGenerator.FileSizeLimitKb(100_000));
        Assert.Null(YaraRuleGenerator.FileSizeLimitKb(0));
    }

    [Fact]
    public void Draft_rule_has_meta_distinctive_strings_and_condition()
    {
        var report = TestData.Static(TestData.Sample("setup.exe"));
        var rule = new YaraRuleGenerator().Generate(report, Date, redact: false)!;

        Assert.StartsWith("// Draft YARA rule", rule, StringComparison.Ordinal);
        Assert.Contains("rule Blazma_Draft_setup_", rule, StringComparison.Ordinal);
        Assert.Contains("author = \"Blazma Sandbox (generated)\"", rule, StringComparison.Ordinal);
        Assert.Contains("date = \"2026-10-07\"", rule, StringComparison.Ordinal);
        Assert.Contains($"sha256 = \"{report.Sample.Sha256}\"", rule, StringComparison.Ordinal);
        Assert.Contains("imphash = \"f34d5f2d4577ed6d9ceec516c1f5a744\"", rule, StringComparison.Ordinal);
        Assert.DoesNotContain("import", rule, StringComparison.Ordinal);

        var strings = StringLine().Matches(rule).Select(m => m.Groups[1].Value).ToList();
        // URL first, its quotes escaped; the domain is skipped because the URL contains it; "short" is too short.
        Assert.Equal(@"https://api.contoso-update.example/v1/check?id=\""x\""", strings[0]);
        Assert.Contains(@"schtasks /create /tn \""ContosoUpdateTask\"" /sc hourly\t/f", strings);
        Assert.Contains(@"Global\\ContosoUpdaterMutex", strings);
        Assert.DoesNotContain("api.contoso-update.example", strings);
        Assert.DoesNotContain("short", strings);
        Assert.Equal(7, strings.Count);
        Assert.Contains("condition:\n        uint16(0) == 0x5A4D and filesize < 4000KB and 4 of them\n}", rule, StringComparison.Ordinal);
    }

    [Fact]
    public void Generation_is_deterministic_and_respects_redaction()
    {
        var report = TestData.Static(TestData.Sample("setup.exe"));
        var gen = new YaraRuleGenerator(redact => redact ? new Redactor(["WDAGUtilityAccount"], ["SANDBOX-PC"]) : Redactor.None);
        Assert.Equal(gen.Generate(report, Date, true), gen.Generate(report, Date, true));
        Assert.Contains("WDAGUtilityAccount", gen.Generate(report, Date, false)!, StringComparison.Ordinal);
        Assert.DoesNotContain("WDAGUtilityAccount", gen.Generate(report, Date, true)!, StringComparison.Ordinal);
        Assert.Equal(gen.Generate(TestData.Demo().Static!, Date, true), gen.Generate(TestData.Demo(), TestData.Options(redact: true)));
    }

    [Fact]
    public void Strings_are_capped_and_non_pe_files_skip_the_mz_check()
    {
        var sample = TestData.Sample("dropper.ps1") with { Kind = FileKind.PowerShell };
        var report = new StaticReport
        {
            Sample = sample,
            Strings = [.. Enumerable.Range(0, 30).Select(i => new InterestingString(InterestingStringKind.Url, $"https://host{i:00}.example/path"))],
        };
        var rule = new YaraRuleGenerator().Generate(report, Date, false)!;
        Assert.Equal(YaraRuleGenerator.MaxStrings, StringLine().Count(rule));
        Assert.DoesNotContain("uint16", rule, StringComparison.Ordinal);
        Assert.Contains("filesize < 4000KB and 6 of them", rule, StringComparison.Ordinal);
    }

    [Fact]
    public void No_usable_strings_means_no_rule()
    {
        var sample = TestData.Sample("a.exe");
        var report = new StaticReport
        {
            Sample = sample,
            Strings = [new(InterestingStringKind.Url, "http://schemas.microsoft.com/SMI/2005/WindowsSettings"), new(InterestingStringKind.Domain, "abc"), new(InterestingStringKind.Command, "cmd /c برنامج")],
        };
        Assert.Null(new YaraRuleGenerator().Generate(report, Date, false));
    }
}
