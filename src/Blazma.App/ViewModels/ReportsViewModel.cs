using System.Collections.ObjectModel;
using Blazma.Analysis.Compare;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Abstractions;
using Blazma.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Blazma.App.ViewModels;

public sealed record DiffSection(string Title, IReadOnlyList<string> Added, IReadOnlyList<string> Removed)
{
    public bool HasAdded => Added.Count > 0;
    public bool HasRemoved => Removed.Count > 0;
    public bool Unchanged => Added.Count == 0 && Removed.Count == 0;
}

public sealed record ExportedFile(string Name, string Path, string When);

/// <summary>Reports: compare two analyses (e.g. version 1.2 vs 1.3 of an installer) and list exported reports.</summary>
public sealed partial class ReportsViewModel(MainViewModel main, IAnalysisRepository repository, SettingsService settings, BlazmaPaths paths) : PageViewModel
{
    public override string NavKey => "Reports";

    public ObservableCollection<AnalysisRow> Analyses { get; } = [];
    public ObservableCollection<DiffSection> Sections { get; } = [];
    public ObservableCollection<ExportedFile> Exports { get; } = [];

    [ObservableProperty] private AnalysisRow? _baseline;
    [ObservableProperty] private AnalysisRow? _target;
    [ObservableProperty] private bool _hasComparison;
    [ObservableProperty] private string _scoreDelta = string.Empty;
    [ObservableProperty] private string _scoreLine = string.Empty;
    [ObservableProperty] private bool _scoreUp;
    [ObservableProperty] private bool _sameSample;
    public Guid? Preselect { get; set; }

    public string ExportFolder => settings.Current.Reports.DefaultExportFolder ?? paths.Exports;

    public override async Task OnShownAsync()
    {
        Analyses.Clear();
        foreach (var s in await repository.ListAsync(500, 0, CancellationToken.None))
            if (s.Stage == Core.Analysis.AnalysisStage.Completed) Analyses.Add(new AnalysisRow(s));
        if (Preselect is { } id)
        {
            Target = Analyses.FirstOrDefault(a => a.Id == id);
            Baseline = Analyses.FirstOrDefault(a => a.Id != id && a.FileName.Equals(Target?.FileName, StringComparison.OrdinalIgnoreCase)) ?? Analyses.FirstOrDefault(a => a.Id != id);
            Preselect = null;
        }
        Exports.Clear();
        try
        {
            if (Directory.Exists(ExportFolder))
                foreach (var f in new DirectoryInfo(ExportFolder).EnumerateFiles().Where(f => f.Extension is ".html" or ".json" or ".csv").OrderByDescending(f => f.LastWriteTimeUtc).Take(50))
                    Exports.Add(new ExportedFile(f.Name, f.FullName, Fmt.Date(f.LastWriteTime)));
        }
        catch (IOException) { }
        if (Baseline is not null && Target is not null) await Compare();
    }

    [RelayCommand]
    private async Task Compare()
    {
        if (Baseline is null || Target is null || Baseline.Id == Target.Id) { HasComparison = false; return; }
        var a = await repository.LoadAsync(Baseline.Id, includeEvents: true, CancellationToken.None);
        var b = await repository.LoadAsync(Target.Id, includeEvents: true, CancellationToken.None);
        if (a is null || b is null) return;
        var c = AnalysisComparer.Compare(a, b);
        Sections.Clear();
        Sections.Add(new(Loc.T("CmpProcesses"), c.Processes.Added, c.Processes.Removed));
        Sections.Add(new(Loc.T("CmpConnections"), c.Endpoints.Added, c.Endpoints.Removed));
        Sections.Add(new(Loc.T("CmpDomains"), c.Domains.Added, c.Domains.Removed));
        Sections.Add(new(Loc.T("CmpPersistence"), c.Persistence.Added, c.Persistence.Removed));
        Sections.Add(new(Loc.T("CmpFiles"), c.DroppedFiles.Added, c.DroppedFiles.Removed));
        Sections.Add(new(Loc.T("CmpFindings"), c.Findings.Added, c.Findings.Removed));
        ScoreDelta = (c.ScoreDelta > 0 ? "+" : string.Empty) + c.ScoreDelta;
        ScoreUp = c.ScoreDelta > 0;
        ScoreLine = $"{c.BaseScore} → {c.TargetScore}";
        SameSample = c.SameSample;
        HasComparison = true;
    }

    [RelayCommand] private void Swap() { (Baseline, Target) = (Target, Baseline); _ = Compare(); }
    [RelayCommand] private void OpenFolder() => main.OpenFolder(ExportFolder);
    [RelayCommand] private void OpenExport(ExportedFile? file) { if (file is not null) main.OpenFolder(Path.GetDirectoryName(file.Path)!); }

    protected override void OnLanguageChanged() { if (HasComparison) _ = Compare(); }
}
