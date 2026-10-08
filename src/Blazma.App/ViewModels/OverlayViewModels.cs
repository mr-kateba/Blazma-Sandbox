using System.Collections.ObjectModel;
using Avalonia.Threading;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Abstractions;
using Blazma.Core.Settings;
using Blazma.Sandbox.Providers.WindowsSandbox;
using Blazma.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Blazma.App.ViewModels;

public sealed record PaletteCommand(string Id, string Title, string Shortcut, Func<Task> Run);

/// <summary>Ctrl+K: type to find any command.</summary>
public sealed partial class CommandPaletteViewModel(MainViewModel main) : ObservableObject
{
    private List<PaletteCommand> _all = [];

    [ObservableProperty] private bool _isOpen;
    [ObservableProperty] private string _query = string.Empty;
    [ObservableProperty] private PaletteCommand? _selected;
    public ObservableCollection<PaletteCommand> Items { get; } = [];

    partial void OnQueryChanged(string value) => Filter();

    public void Open()
    {
        _all = main.PaletteCommands();
        Query = string.Empty;
        Filter();
        IsOpen = true;
    }

    private void Filter()
    {
        Items.Clear();
        foreach (var c in _all.Where(c => Query.Length == 0 || c.Title.Contains(Query, StringComparison.OrdinalIgnoreCase) || c.Id.Contains(Query, StringComparison.OrdinalIgnoreCase)))
            Items.Add(c);
        Selected = Items.FirstOrDefault();
    }

    public void Move(int delta)
    {
        if (Items.Count == 0) return;
        var i = Selected is null ? 0 : Items.IndexOf(Selected);
        Selected = Items[(i + delta + Items.Count) % Items.Count];
    }

    [RelayCommand]
    public async Task Run(PaletteCommand? command)
    {
        command ??= Selected;
        if (command is null) return;
        IsOpen = false;
        await command.Run();
    }

    [RelayCommand] public void Close() => IsOpen = false;
}

public sealed record SearchResultRow(SearchHit Hit)
{
    public string Source => Loc.T("Src" + Hit.Source);
    public string Title => Hit.Title;
    public string Snippet => Hit.Snippet;
    public string File => Hit.FileName;
}

/// <summary>Global search across every stored analysis: processes, timeline, files, registry, network, indicators.</summary>
public sealed partial class SearchViewModel(MainViewModel main, IAnalysisRepository repository) : ObservableObject
{
    private CancellationTokenSource? _cts;

    [ObservableProperty] private string _query = string.Empty;
    [ObservableProperty] private bool _isOpen;
    [ObservableProperty] private bool _isSearching;
    public ObservableCollection<SearchResultRow> Results { get; } = [];
    public bool IsEmpty => !IsSearching && Results.Count == 0 && Query.Trim().Length > 0;

    partial void OnQueryChanged(string value)
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        if (value.Trim().Length < 2) { Results.Clear(); IsOpen = false; return; }
        IsOpen = true;
        _ = DebouncedSearch(value, token);
    }

    private async Task DebouncedSearch(string text, CancellationToken token)
    {
        try
        {
            await Task.Delay(250, token);
            IsSearching = true;
            var hits = await repository.SearchAsync(text, 60, token);
            if (token.IsCancellationRequested) return;
            Results.Clear();
            foreach (var h in hits) Results.Add(new SearchResultRow(h));
        }
        catch (OperationCanceledException) { }
        finally
        {
            IsSearching = false;
            OnPropertyChanged(nameof(IsEmpty));
        }
    }

    [RelayCommand]
    private async Task Open(SearchResultRow? row)
    {
        if (row is null) return;
        IsOpen = false;
        var tab = row.Hit.Source switch
        {
            SearchSource.Process => 2,
            SearchSource.File => 3,
            SearchSource.Registry => 4,
            SearchSource.Network => 5,
            SearchSource.Indicator => 7,
            SearchSource.Finding => 0,
            _ => 1,
        };
        await main.OpenReportAsync(row.Hit.AnalysisId, tab, row.Hit.EventSequence);
    }

    [RelayCommand] private void Close() => IsOpen = false;
}

/// <summary>First run: welcome, check the system, say exactly what is needed.</summary>
public sealed partial class OnboardingViewModel(MainViewModel main, AnalysisCoordinator coordinator, SettingsService settings, BlazmaPaths paths) : ObservableObject
{
    [ObservableProperty] private bool _isOpen;
    [ObservableProperty] private int _step;
    [ObservableProperty] private bool _isChecking;
    [ObservableProperty] private bool _ready;
    public ObservableCollection<CheckRow> Checks { get; } = [];
    public bool IsWelcome => Step == 0;
    public bool IsChecks => Step == 1;
    partial void OnStepChanged(int value) { OnPropertyChanged(nameof(IsWelcome)); OnPropertyChanged(nameof(IsChecks)); }

    public void Open() { Step = 0; IsOpen = true; }

    [RelayCommand]
    private async Task RunChecks()
    {
        Step = 1;
        IsChecking = true;
        Checks.Clear();
        var availability = await coordinator.Provider(WindowsSandboxProvider.ProviderId).CheckAvailabilityAsync(CancellationToken.None);
        foreach (var c in availability.Checks) Checks.Add(new CheckRow(c.Label.Get(Loc.Instance.Code), c.Detail.Get(Loc.Instance.Code), c.Passed));
        var storage = true;
        try { paths.EnsureCreated(); var p = Path.Combine(paths.Root, ".probe"); await File.WriteAllTextAsync(p, "ok"); File.Delete(p); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { storage = false; }
        Checks.Add(new CheckRow(Loc.T("Storage"), storage ? paths.Root : Loc.T("StorageNotWritable"), storage));
        Checks.Add(new CheckRow(Loc.T("Permissions"), Loc.T("PermissionsDetail"), true));
        Ready = availability.IsReady && storage;
        IsChecking = false;
    }

    [RelayCommand]
    private void Finish()
    {
        settings.Current.General.OnboardingCompleted = true;
        settings.Touch();
        IsOpen = false;
    }

    [RelayCommand]
    private async Task TryDemo()
    {
        Finish();
        await main.PrepareDemoAsync();
    }

    [RelayCommand] private void SetEnglish() => main.SetLanguage(AppLanguage.English);
    [RelayCommand] private void SetArabic() => main.SetLanguage(AppLanguage.Arabic);
}
