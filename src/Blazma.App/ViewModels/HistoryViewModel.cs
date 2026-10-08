using System.Collections.ObjectModel;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Findings;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Blazma.App.ViewModels;

public sealed record SortOption(string Key)
{
    public string Label => Loc.T("Sort" + Key);
    public override string ToString() => Label;
}

public sealed record VerdictFilter(Verdict? Value)
{
    public string Label => Value is { } v ? Fmt.Verdict(v) : Loc.T("AllVerdicts");
    public override string ToString() => Label;
}

public sealed partial class HistoryViewModel(MainViewModel main, IAnalysisRepository repository, SettingsService settings, ToastService toasts) : PageViewModel
{
    private List<AnalysisRow> _all = [];

    public override string NavKey => "History";

    public ObservableCollection<AnalysisRow> Items { get; } = [];
    public ObservableCollection<SortOption> Sorts { get; } = [new("Newest"), new("Oldest"), new("ScoreHigh"), new("ScoreLow"), new("Name")];
    public ObservableCollection<VerdictFilter> Verdicts { get; } = [new(null), new(Core.Findings.Verdict.CriticalBehavior), new(Core.Findings.Verdict.HighRiskBehavior), new(Core.Findings.Verdict.Suspicious), new(Core.Findings.Verdict.LowRisk)];

    [ObservableProperty] private string _search = string.Empty;
    [ObservableProperty] private SortOption? _sort;
    [ObservableProperty] private VerdictFilter? _verdict;
    [ObservableProperty] private bool _includeDemo = true;
    [ObservableProperty] private AnalysisRow? _selected;
    [ObservableProperty] private string _countText = string.Empty;

    public bool IsEmpty => Items.Count == 0;

    partial void OnSearchChanged(string value) => Apply();
    partial void OnSortChanged(SortOption? value) => Apply();
    partial void OnVerdictChanged(VerdictFilter? value) => Apply();
    partial void OnIncludeDemoChanged(bool value) => Apply();

    public override async Task OnShownAsync()
    {
        Sort ??= Sorts[0];
        Verdict ??= Verdicts[0];
        _all = (await repository.ListAsync(10_000, 0, CancellationToken.None)).Select(s => new AnalysisRow(s)).ToList();
        Apply();
    }

    private void Apply()
    {
        var q = Search.Trim();
        IEnumerable<AnalysisRow> rows = _all.Where(r =>
            (q.Length == 0 || r.FileName.Contains(q, StringComparison.OrdinalIgnoreCase) || r.Sha256.StartsWith(q, StringComparison.OrdinalIgnoreCase)) &&
            (Verdict?.Value is null || (r.IsCompleted && r.Verdict == Verdict.Value)) &&
            (IncludeDemo || !r.IsDemo));
        rows = (Sort?.Key ?? "Newest") switch
        {
            "Oldest" => rows.OrderBy(r => r.Summary.StartedAt),
            "ScoreHigh" => rows.OrderByDescending(r => r.Score),
            "ScoreLow" => rows.OrderBy(r => r.Score),
            "Name" => rows.OrderBy(r => r.FileName, StringComparer.OrdinalIgnoreCase),
            _ => rows.OrderByDescending(r => r.Summary.StartedAt),
        };
        Items.Clear();
        foreach (var r in rows) Items.Add(r);
        CountText = Loc.F("AnalysesCount", Items.Count);
        OnPropertyChanged(nameof(IsEmpty));
    }

    protected override void OnLanguageChanged()
    {
        var sort = Sort?.Key; var verdict = Verdict?.Value;
        Sorts.Clear(); foreach (var k in new[] { "Newest", "Oldest", "ScoreHigh", "ScoreLow", "Name" }) Sorts.Add(new(k));
        Verdicts.Clear(); foreach (var v in new Verdict?[] { null, Core.Findings.Verdict.CriticalBehavior, Core.Findings.Verdict.HighRiskBehavior, Core.Findings.Verdict.Suspicious, Core.Findings.Verdict.LowRisk }) Verdicts.Add(new(v));
        Sort = Sorts.First(s => s.Key == (sort ?? "Newest"));
        Verdict = Verdicts.First(v => v.Value == verdict);
        _ = OnShownAsync();
    }

    [RelayCommand] private Task Open(AnalysisRow? row) => row is null ? Task.CompletedTask : main.OpenReportAsync(row.Id);

    [RelayCommand]
    private async Task Delete(AnalysisRow? row)
    {
        if (row is null) return;
        if (settings.Current.General.ConfirmBeforeDelete &&
            !await main.Dialogs.ConfirmAsync(Loc.T("DeleteTitle"), Loc.F("DeleteBody", row.FileName), Loc.T("Delete"), danger: true)) return;
        await repository.DeleteAsync(row.Id, CancellationToken.None);
        toasts.Show(ToastKind.Info, Loc.T("Deleted"), row.FileName);
        await OnShownAsync();
    }

    [RelayCommand]
    private async Task Export(AnalysisRow? row)
    {
        if (row is null) return;
        var result = await repository.LoadAsync(row.Id, includeEvents: true, CancellationToken.None);
        if (result is not null) await main.Exports.ExportAsync(result, settings.Current.Reports.DefaultFormat);
    }

    [RelayCommand] private void Compare(AnalysisRow? row) { if (row is not null) main.OpenCompare(row.Id); }
}
