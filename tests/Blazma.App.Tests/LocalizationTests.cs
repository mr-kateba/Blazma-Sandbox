using System.Text.RegularExpressions;
using Blazma.App.Localization;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Indicators;
using Blazma.Core.Processes;
using Blazma.Core.Samples;
using Blazma.Core.Settings;

namespace Blazma.App.Tests;

public partial class LocalizationTests
{
    private static readonly Loc L = Loc.Instance;

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Blazma.Sandbox.slnx"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Repository root not found");
    }

    [Fact]
    public void English_and_Arabic_have_exactly_the_same_keys()
    {
        var en = L.Keys(AppLanguage.English).ToHashSet();
        var ar = L.Keys(AppLanguage.Arabic).ToHashSet();
        Assert.Empty(en.Except(ar));
        Assert.Empty(ar.Except(en));
    }

    [Fact]
    public void Every_key_used_in_xaml_exists()
    {
        var keys = L.Keys(AppLanguage.English).ToHashSet();
        var missing = Directory.EnumerateFiles(Path.Combine(RepoRoot(), "src", "Blazma.App"), "*.axaml", SearchOption.AllDirectories)
            .SelectMany(f => KeyRegex().Matches(File.ReadAllText(f)).Select(m => m.Groups[1].Value))
            .Where(k => !keys.Contains(k)).Distinct().ToList();
        Assert.Empty(missing);
    }

    [Fact]
    public void Every_key_used_in_code_exists()
    {
        var keys = L.Keys(AppLanguage.English).ToHashSet();
        var missing = Directory.EnumerateFiles(Path.Combine(RepoRoot(), "src", "Blazma.App"), "*.cs", SearchOption.AllDirectories)
            .SelectMany(f => CodeKeyRegex().Matches(File.ReadAllText(f)).Select(m => m.Groups[1].Value))
            .Where(k => !keys.Contains(k)).Distinct().ToList();
        Assert.Empty(missing);
    }

    [Fact]
    public void Keys_built_from_enums_exist()
    {
        var keys = L.Keys(AppLanguage.English).ToHashSet();
        var expected = Enum.GetNames<AnalysisStage>().Select(n => "Stage" + n)
            .Concat(Enum.GetNames<EventCategory>().Select(n => "Cat" + n))
            .Concat(Enum.GetNames<EventAction>().Select(n => "Act" + n))
            .Concat(Enum.GetNames<FindingCategory>().Select(n => "FCat" + n))
            .Concat(Enum.GetNames<IndicatorStatus>().Select(n => "Ind" + n))
            .Concat(Enum.GetNames<IndicatorType>().Select(n => "IndType" + n))
            .Concat(Enum.GetNames<Severity>().Select(n => "Severity" + n))
            .Concat(Enum.GetNames<ChainStepKind>().Select(n => "Step" + n))
            .Concat(Enum.GetNames<Provenance>().Select(n => "Prov" + n))
            .Concat(Enum.GetNames<FileKind>().Select(n => "Kind" + n))
            .Concat(Enum.GetNames<WatchlistEntryType>().Select(n => "Watch" + n))
            .Concat(Enum.GetNames<Core.Abstractions.SearchSource>().Select(n => "Src" + n))
            .Concat(Enum.GetNames<ThemeVariant>().Select(n => "Theme" + n))
            .Concat(ShortcutSettings.Defaults.Keys.Select(n => "Cmd" + n));
        Assert.All(expected, k => Assert.Contains(k, keys));
    }

    [Fact]
    public void No_translation_is_empty_and_placeholders_match()
    {
        foreach (var key in L.Keys(AppLanguage.English))
        {
            L.SetLanguage(AppLanguage.English);
            var en = L[key];
            L.SetLanguage(AppLanguage.Arabic);
            var ar = L[key];
            Assert.False(string.IsNullOrWhiteSpace(en), key);
            Assert.False(string.IsNullOrWhiteSpace(ar), key);
            Assert.Equal(Placeholders().Matches(en).Select(m => m.Value).Order(), Placeholders().Matches(ar).Select(m => m.Value).Order());
        }
        L.SetLanguage(AppLanguage.English);
    }

    [Fact]
    public void Arabic_switches_layout_to_right_to_left()
    {
        L.SetLanguage(AppLanguage.Arabic);
        Assert.Equal(Avalonia.Media.FlowDirection.RightToLeft, L.FlowDirection);
        Assert.Equal("لوحة التحكم", L["NavDashboard"]);
        L.SetLanguage(AppLanguage.English);
        Assert.Equal(Avalonia.Media.FlowDirection.LeftToRight, L.FlowDirection);
    }

    [GeneratedRegex(@"\{l:T (\w+)\}")]
    private static partial Regex KeyRegex();

    [GeneratedRegex(@"Loc\.[TF]\(""(\w+)""\s*[,)]")]
    private static partial Regex CodeKeyRegex();

    [GeneratedRegex(@"\{\d+\}")]
    private static partial Regex Placeholders();
}
