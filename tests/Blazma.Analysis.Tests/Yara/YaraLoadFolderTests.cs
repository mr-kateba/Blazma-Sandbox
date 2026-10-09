using Blazma.Analysis.Yara;
using Blazma.Core.Abstractions;

namespace Blazma.Analysis.Tests.Yara;

public sealed class YaraLoadFolderTests : IDisposable
{
    private readonly DirectoryInfo _dir = Directory.CreateTempSubdirectory("blz-yara");

    public void Dispose() => _dir.Delete(recursive: true);

    private string Write(string relative, string text)
    {
        var path = Path.Combine(_dir.FullName, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text);
        return path;
    }

    [Fact]
    public void Loads_yar_and_yara_files_recursively_and_ignores_others()
    {
        Write("a.yar", "rule from_a { condition: true }");
        Write("sub/deeper/b.YARA", "rule from_b { strings: $x = \"evil\" condition: $x }");
        Write("notes.txt", "rule not_loaded { condition: true }");

        IYaraScanner set = YaraRuleSet.LoadFolder(_dir.FullName);
        Assert.Equal(2, set.RuleCount);
        Assert.Empty(set.LoadErrors);
        var matches = set.Scan("an evil file"u8, "dropped:C:\\x.exe");
        Assert.Equal(["from_a", "from_b"], matches.Select(m => m.Rule).Order(StringComparer.Ordinal));
        Assert.All(matches, m => Assert.Equal("dropped:C:\\x.exe", m.Target));
        Assert.Contains(matches, m => m.Rule == "from_b" && m.Source.EndsWith("b.YARA", StringComparison.Ordinal));
    }

    [Fact]
    public void Bad_files_become_errors_and_good_ones_still_load()
    {
        var bad = Write("bad.yar", "rule broken {\n condition: (\n}");
        Write("partial.yar", "rule ok { condition: true }\nrule uses_math { condition: math.entropy(0, 10) > 7 }");
        var huge = Write("huge.yar", "// " + new string('x', (int)YaraLimits.MaxRuleFileBytes + 10));

        var set = YaraRuleSet.LoadFolder(_dir.FullName);
        Assert.Equal(["ok"], set.Rules.Select(r => r.Name));
        Assert.Contains(set.LoadErrors, e => e.StartsWith(bad + ":3:", StringComparison.Ordinal));
        Assert.Contains(set.LoadErrors, e => e.Contains("rule uses_math: uses the 'math' module", StringComparison.Ordinal));
        Assert.Contains(set.LoadErrors, e => e.StartsWith(huge, StringComparison.Ordinal) && e.Contains("larger than 2 MB", StringComparison.Ordinal));
    }

    [Fact]
    public void Same_rule_name_in_two_files_is_fine()
    {
        Write("one.yar", "rule same { condition: true }");
        Write("two.yar", "rule same { condition: true }");
        var set = YaraRuleSet.LoadFolder(_dir.FullName);
        Assert.Equal(2, set.RuleCount);
        Assert.Empty(set.LoadErrors);
    }

    [Fact]
    public void At_most_256_files_are_loaded()
    {
        for (var i = 0; i < YaraLimits.MaxRuleFiles + 4; i++) Write($"r{i:D3}.yar", $"rule r{i} {{ condition: true }}");
        var set = YaraRuleSet.LoadFolder(_dir.FullName);
        Assert.Equal(YaraLimits.MaxRuleFiles, set.RuleCount);
        Assert.Contains(set.LoadErrors, e => e.Contains($"more than {YaraLimits.MaxRuleFiles} rule files", StringComparison.Ordinal));
    }

    [Fact]
    public void Missing_or_empty_folders_never_throw()
    {
        var missing = YaraRuleSet.LoadFolder(Path.Combine(_dir.FullName, "nope"));
        Assert.Equal(0, missing.RuleCount);
        Assert.Contains("rules folder not found", Assert.Single(missing.LoadErrors), StringComparison.Ordinal);

        var empty = YaraRuleSet.LoadFolder(_dir.FullName);
        Assert.Equal(0, empty.RuleCount);
        Assert.Empty(empty.LoadErrors);
        Assert.Empty(empty.Scan("data"u8, "sample"));

        Assert.Single(YaraRuleSet.LoadFolder("\0bad").LoadErrors);
    }
}
