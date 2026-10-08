using System.Collections.ObjectModel;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Findings;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Blazma.App.ViewModels;

public sealed class AnalysisRow(AnalysisSummary s) : ObservableObject
{
    public AnalysisSummary Summary { get; } = s;
    public Guid Id => Summary.Id;
    public string FileName => Summary.FileName;
    public string Sha256Short => Fmt.ShortHash(Summary.Sha256);
    public string Sha256 => Summary.Sha256;
    public int Score => Summary.Score;
    public Verdict Verdict => Summary.Verdict;
    public bool IsCompleted => Summary.Stage == AnalysisStage.Completed;
    public bool IsDemo => Summary.IsDemo;
    public string Ago => Fmt.Ago(Summary.StartedAt);
    public string Date => Fmt.Date(Summary.StartedAt);
    public string Duration => Fmt.Duration(Summary.Duration);
    public string Status => Fmt.Stage(Summary.Stage);
    public string Provider => Fmt.Provider(Summary.ProviderId);
    public string ScoreText => IsCompleted ? Score.ToString(System.Globalization.CultureInfo.InvariantCulture) : "—";
}

public sealed partial class DashboardViewModel(MainViewModel main, IAnalysisRepository repository, SettingsService settings) : PageViewModel
{
    public override string NavKey => "Dashboard";
    public MainViewModel Main => main;

    public ObservableCollection<AnalysisRow> Recent { get; } = [];

    [ObservableProperty] private int _analysesToday;
    [ObservableProperty] private int _highRisk;
    [ObservableProperty] private int _suspicious;
    [ObservableProperty] private int _lowRisk;
    [ObservableProperty] private bool _isDragOver;

    public bool ShowToday => settings.Current.Dashboard.ShowAnalysesToday;
    public bool ShowHigh => settings.Current.Dashboard.ShowHighRisk;
    public bool ShowSuspicious => settings.Current.Dashboard.ShowSuspicious;
    public bool ShowLow => settings.Current.Dashboard.ShowLowRisk;
    public bool ShowSandbox => settings.Current.Dashboard.ShowSandboxStatus;
    public bool HasRecent => Recent.Count > 0;

    public override async Task OnShownAsync()
    {
        var stats = await repository.GetStatsAsync(DateTimeOffset.Now, CancellationToken.None);
        AnalysesToday = stats.AnalysesToday;
        HighRisk = stats.HighRisk;
        Suspicious = stats.Suspicious;
        LowRisk = stats.LowRisk;
        Recent.Clear();
        foreach (var s in await repository.ListAsync(Math.Clamp(settings.Current.Dashboard.RecentCount, 3, 30), 0, CancellationToken.None))
            Recent.Add(new AnalysisRow(s));
        OnPropertyChanged(nameof(HasRecent));
        OnPropertyChanged(nameof(ShowToday)); OnPropertyChanged(nameof(ShowHigh)); OnPropertyChanged(nameof(ShowSuspicious));
        OnPropertyChanged(nameof(ShowLow)); OnPropertyChanged(nameof(ShowSandbox));
    }

    protected override void OnLanguageChanged() => _ = OnShownAsync();

    public void SetDragOver(bool value) => IsDragOver = value;

    [RelayCommand] private Task SelectFile() => main.PickAndPrepareAsync();
    [RelayCommand] private Task TryDemo() => main.PrepareDemoAsync();
    [RelayCommand] private Task Open(AnalysisRow? row) => row is null ? Task.CompletedTask : main.OpenReportAsync(row.Id);
}
