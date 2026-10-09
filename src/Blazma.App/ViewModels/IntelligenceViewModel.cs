using System.Collections.ObjectModel;
using Blazma.Analysis.Rules;
using Blazma.Analysis.Yara;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Settings;
using Blazma.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Blazma.App.ViewModels;

public sealed record WatchTypeOption(WatchlistEntryType Type)
{
    public string Label => Loc.T("Watch" + Type);
    public override string ToString() => Label;
}

public sealed record RuleRow(string Id, string Name, string Category, string Severity, int Weight, string Origin, string Attack)
{
    public string Meta => string.Join(" · ", new[] { Category, Severity, Attack, Origin == "built-in" ? null : Origin }.Where(x => !string.IsNullOrEmpty(x)));
}

public sealed record YaraRuleRow(string Name, string Origin, string Tags, string Description);

/// <summary>
/// Intelligence that stays on this computer: the watchlist, detection rules and custom
/// rule packs and YARA rules. Community intelligence is shown as planned and disabled.
/// </summary>
public sealed partial class IntelligenceViewModel(MainViewModel main, SettingsService settings, AnalysisCoordinator coordinator, BlazmaPaths paths, ToastService toasts) : PageViewModel
{
    public override string NavKey => "Intelligence";

    public ObservableCollection<WatchlistEntry> Watchlist { get; } = [];
    public ObservableCollection<WatchTypeOption> WatchTypes { get; } = [];
    public ObservableCollection<RuleRow> Rules { get; } = [];
    public ObservableCollection<string> RuleErrors { get; } = [];
    public ObservableCollection<YaraRuleRow> YaraRules { get; } = [];
    public ObservableCollection<string> YaraErrors { get; } = [];

    [ObservableProperty] private string _yaraSummary = string.Empty;
    public string YaraFolder => paths.Yara;
    public bool HasYaraErrors => YaraErrors.Count > 0;
    public bool YaraEnabled => settings.Current.Detection.EnableYara;

    /// <summary>A small, valid starting point the user can edit.</summary>
    public const string ExampleYara = """
        // Blazma Sandbox scans the sample, files it created and memory regions with every
        // rule in this folder. Supported syntax and limits: docs/YARA.md
        rule Example_PowerShell_Download_Cradle : example
        {
            meta:
                description = "PowerShell that downloads and runs code"
                author = "you"
            strings:
                $iwr = "Invoke-WebRequest" ascii wide nocase
                $iex = "IEX" ascii wide nocase fullword
                $dl  = "DownloadString" ascii wide nocase
            condition:
                $iex and ($iwr or $dl)
        }
        """;

    [ObservableProperty] private WatchTypeOption? _newType;
    [ObservableProperty] private string _newValue = string.Empty;
    [ObservableProperty] private string _newNote = string.Empty;
    [ObservableProperty] private string _rulesSummary = string.Empty;

    public string RulesFolder => paths.Rules;
    public bool HasRuleErrors => RuleErrors.Count > 0;
    public string ExamplePack => JsonRulePack.Example;

    public override Task OnShownAsync()
    {
        WatchTypes.Clear();
        foreach (var t in Enum.GetValues<WatchlistEntryType>()) WatchTypes.Add(new WatchTypeOption(t));
        NewType ??= WatchTypes[0];
        Watchlist.Clear();
        foreach (var w in settings.Current.Detection.Watchlist) Watchlist.Add(w);
        ReloadRules();
        return Task.CompletedTask;
    }

    private void ReloadRules()
    {
        var engine = coordinator.BuildRuleEngine();
        Rules.Clear();
        foreach (var r in engine.Rules)
        {
            var m = r.Metadata;
            Rules.Add(new RuleRow(m.Id, m.Name.Get(Loc.Instance.Code), Fmt.FindingCategory(m.Category), Fmt.Severity(m.Severity), m.Weight, m.Origin, string.Join(", ", m.AttackTechniques)));
        }
        RuleErrors.Clear();
        foreach (var e in coordinator.RulePackErrors) RuleErrors.Add(e);
        RulesSummary = Loc.F("RulesSummary", Rules.Count(r => r.Origin == "built-in"), Rules.Count(r => r.Origin != "built-in"));
        OnPropertyChanged(nameof(HasRuleErrors));
        ReloadYara();
    }

    private void ReloadYara()
    {
        // The user's own rule files (not sample bytes); the engine has hard limits and never throws.
        var set = YaraRuleSet.LoadFolder(paths.Yara);
        YaraRules.Clear();
        foreach (var r in set.Rules.Where(r => !r.IsPrivate))
            YaraRules.Add(new YaraRuleRow(r.Name, $"{r.Origin}:{r.Line}", string.Join(" ", r.Tags), r.Meta.TryGetValue("description", out var d) ? d : ""));
        YaraErrors.Clear();
        foreach (var e in set.LoadErrors) YaraErrors.Add(e);
        YaraSummary = Loc.F("YaraSummary", set.RuleCount, set.Rules.Select(r => r.Origin).Distinct().Count());
        OnPropertyChanged(nameof(HasYaraErrors));
        OnPropertyChanged(nameof(YaraEnabled));
    }

    [RelayCommand] private void OpenYaraFolder() { Directory.CreateDirectory(paths.Yara); main.OpenFolder(paths.Yara); }

    [RelayCommand]
    private async Task CreateExampleYara()
    {
        Directory.CreateDirectory(paths.Yara);
        var path = Path.Combine(paths.Yara, "example.yar");
        if (!File.Exists(path)) await File.WriteAllTextAsync(path, ExampleYara);
        toasts.Show(ToastKind.Success, Loc.T("ExampleCreated"), Path.GetFileName(path));
        ReloadYara();
    }

    [RelayCommand] private void OpenAiSettings() => main.Navigate("Settings");

    [RelayCommand]
    private void AddWatch()
    {
        var value = NewValue.Trim();
        if (value.Length == 0 || NewType is null) return;
        var entry = new WatchlistEntry(NewType.Type, value, string.IsNullOrWhiteSpace(NewNote) ? null : NewNote.Trim());
        settings.Current.Detection.Watchlist.Add(entry);
        settings.Touch();
        Watchlist.Add(entry);
        NewValue = NewNote = string.Empty;
    }

    [RelayCommand]
    private void RemoveWatch(WatchlistEntry? entry)
    {
        if (entry is null) return;
        settings.Current.Detection.Watchlist.Remove(entry);
        settings.Touch();
        Watchlist.Remove(entry);
    }

    [RelayCommand] private void OpenRulesFolder() { Directory.CreateDirectory(paths.Rules); main.OpenFolder(paths.Rules); }

    [RelayCommand]
    private async Task CreateExamplePack()
    {
        Directory.CreateDirectory(paths.Rules);
        var path = Path.Combine(paths.Rules, "example-rules.json");
        if (!File.Exists(path)) await File.WriteAllTextAsync(path, JsonRulePack.Example);
        toasts.Show(ToastKind.Success, Loc.T("ExampleCreated"), Path.GetFileName(path));
        ReloadRules();
    }

    [RelayCommand] private void Reload() => ReloadRules();

    protected override void OnLanguageChanged() => _ = OnShownAsync();
}
