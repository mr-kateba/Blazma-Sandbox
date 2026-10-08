using System.Collections.ObjectModel;
using Blazma.Analysis.Rules;
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

/// <summary>
/// Intelligence that stays on this computer: the watchlist, detection rules and custom
/// rule packs. Local AI and community intelligence are shown as planned and disabled.
/// </summary>
public sealed partial class IntelligenceViewModel(MainViewModel main, SettingsService settings, AnalysisCoordinator coordinator, BlazmaPaths paths, ToastService toasts) : PageViewModel
{
    public override string NavKey => "Intelligence";

    public ObservableCollection<WatchlistEntry> Watchlist { get; } = [];
    public ObservableCollection<WatchTypeOption> WatchTypes { get; } = [];
    public ObservableCollection<RuleRow> Rules { get; } = [];
    public ObservableCollection<string> RuleErrors { get; } = [];

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
    }

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
