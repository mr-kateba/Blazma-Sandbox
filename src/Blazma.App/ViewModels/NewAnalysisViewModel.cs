using System.Collections.ObjectModel;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Samples;
using Blazma.Sandbox.Providers.Demo;
using Blazma.Sandbox.Providers.WindowsSandbox;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Blazma.App.ViewModels;

public sealed record InfoRow(string Label, string Value, bool Mono = false);

public sealed record CheckRow(string Label, string Detail, bool Passed);

public sealed record ProfileOption(AnalysisProfile Profile)
{
    public string Name => Loc.Instance.IsArabic ? Profile.NameAr : Profile.NameEn;
    public override string ToString() => Name;
}

public sealed record ProviderOption(string Id, string Name);

/// <summary>Preparation: show what the file is, choose how to analyze it, then start. Nothing runs before Start.</summary>
public sealed partial class NewAnalysisViewModel(MainViewModel main, AnalysisCoordinator coordinator, SettingsService settings) : PageViewModel
{
    public override string NavKey => "NewAnalysis";

    [ObservableProperty] private StaticReport? _report;
    [ObservableProperty] private string? _samplePath;
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string? _error;
    [ObservableProperty] private bool _isDemoSample;

    [ObservableProperty] private ProfileOption? _selectedProfile;
    [ObservableProperty] private double _durationSeconds = 120;
    [ObservableProperty] private bool _networkEnabled;
    [ObservableProperty] private bool _networkConsent;
    [ObservableProperty] private bool _captureProcesses = true;
    [ObservableProperty] private bool _captureFiles = true;
    [ObservableProperty] private bool _captureRegistry = true;
    [ObservableProperty] private bool _captureNetwork = true;
    [ObservableProperty] private bool _takeSnapshots = true;
    [ObservableProperty] private ProviderOption? _selectedProvider;
    [ObservableProperty] private bool _providerReady;
    [ObservableProperty] private bool _checkingProvider;
    [ObservableProperty] private string _newProfileName = string.Empty;

    public ObservableCollection<InfoRow> FileRows { get; } = [];
    public ObservableCollection<InfoRow> PeRows { get; } = [];
    public ObservableCollection<string> Warnings { get; } = [];
    public ObservableCollection<CheckRow> ProviderChecks { get; } = [];
    public ObservableCollection<ProfileOption> Profiles { get; } = [];
    public ObservableCollection<ProviderOption> Providers { get; } = [];

    public bool HasReport => Report is not null;
    public bool HasNoReport => Report is null && !IsLoading;
    public bool HasError => !string.IsNullOrEmpty(Error);
    public bool IsRunnable => Report?.Sample.IsExecutableKind == true;
    public string DurationText => Fmt.Duration(TimeSpan.FromSeconds(DurationSeconds));
    public bool CanStart => HasReport && IsRunnable && ProviderReady && (!NetworkEnabled || NetworkConsent) && !IsLoading;
    public bool ShowNetworkWarning => NetworkEnabled;

    partial void OnReportChanged(StaticReport? value) { BuildRows(); Notify(); }
    partial void OnIsLoadingChanged(bool value) => Notify();
    partial void OnErrorChanged(string? value) => OnPropertyChanged(nameof(HasError));
    partial void OnDurationSecondsChanged(double value) => OnPropertyChanged(nameof(DurationText));
    partial void OnNetworkEnabledChanged(bool value) { if (!value) NetworkConsent = false; Notify(); }
    partial void OnNetworkConsentChanged(bool value) => Notify();
    partial void OnProviderReadyChanged(bool value) => Notify();
    partial void OnSelectedProviderChanged(ProviderOption? value) => _ = CheckProviderAsync();
    partial void OnSelectedProfileChanged(ProfileOption? value)
    {
        if (value is null) return;
        var o = value.Profile.Options;
        DurationSeconds = o.Duration.TotalSeconds;
        CaptureProcesses = o.CaptureProcesses;
        CaptureFiles = o.CaptureFiles;
        CaptureRegistry = o.CaptureRegistry;
        CaptureNetwork = o.CaptureNetwork;
        TakeSnapshots = o.TakeSnapshots;
    }

    private void Notify()
    {
        OnPropertyChanged(nameof(HasReport)); OnPropertyChanged(nameof(HasNoReport)); OnPropertyChanged(nameof(IsRunnable));
        OnPropertyChanged(nameof(CanStart)); OnPropertyChanged(nameof(ShowNetworkWarning));
    }

    public override async Task OnShownAsync()
    {
        Profiles.Clear();
        foreach (var p in settings.Current.Analysis.AllProfiles) Profiles.Add(new ProfileOption(p));
        SelectedProfile ??= Profiles.FirstOrDefault(p => p.Profile.Id == settings.Current.Analysis.DefaultProfileId) ?? Profiles.FirstOrDefault();
        Providers.Clear();
        Providers.Add(new ProviderOption(WindowsSandboxProvider.ProviderId, "Windows Sandbox"));
        Providers.Add(new ProviderOption(DemoSandboxProvider.ProviderId, Loc.T("ProviderDemo")));
        var wanted = IsDemoSample ? DemoSandboxProvider.ProviderId : settings.Current.Analysis.ProviderId;
        SelectedProvider = Providers.FirstOrDefault(p => p.Id == wanted) ?? Providers[0];
        await CheckProviderAsync();
    }

    protected override void OnLanguageChanged()
    {
        BuildRows();
        var id = SelectedProfile?.Profile.Id;
        Profiles.Clear();
        foreach (var p in settings.Current.Analysis.AllProfiles) Profiles.Add(new ProfileOption(p));
        SelectedProfile = Profiles.FirstOrDefault(p => p.Profile.Id == id);
        _ = CheckProviderAsync();
    }

    public async Task LoadAsync(string path)
    {
        IsDemoSample = false;
        SamplePath = path;
        Report = null;
        Error = null;
        IsLoading = true;
        try
        {
            Report = await coordinator.AnalyzeStaticAsync(path, CancellationToken.None);
            if (!Report.Sample.IsExecutableKind) Error = Loc.T("NotRunnable");
        }
        catch (Exception ex)
        {
            Error = Loc.T("StaticFailed") + " " + ex.Message;
        }
        finally { IsLoading = false; }
    }

    public void LoadDemo()
    {
        IsDemoSample = true;
        SamplePath = null;
        Error = null;
        Report = AnalysisCoordinator.DemoSample();
    }

    private void BuildRows()
    {
        FileRows.Clear(); PeRows.Clear(); Warnings.Clear();
        if (Report is not { } r) return;
        var s = r.Sample;
        FileRows.Add(new(Loc.T("File"), s.FileName));
        FileRows.Add(new(Loc.T("Size"), $"{Fmt.Size(s.Size)} ({s.Size:N0} B)"));
        FileRows.Add(new(Loc.T("Type"), Loc.T("Kind" + s.Kind)));
        FileRows.Add(new("SHA-256", s.Sha256, true));
        FileRows.Add(new("SHA-1", s.Sha1, true));
        FileRows.Add(new(Loc.T("Signature"), r.Signature.Status switch
        {
            SignatureStatus.Valid => Loc.F("SignedBy", r.Signature.Publisher ?? "?"),
            SignatureStatus.Invalid => Loc.T("SignatureInvalid"),
            SignatureStatus.PresentUnverified => Loc.T("SignatureUnverified"),
            _ => Loc.T("SignatureNone"),
        }));
        if (r.Pe is { } pe)
        {
            FileRows.Add(new(Loc.T("Architecture"), pe.Machine));
            PeRows.Add(new(Loc.T("Subsystem"), pe.Subsystem));
            PeRows.Add(new(Loc.T("CompileTime"), (pe.CompileTimestamp?.ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture) ?? "—") + "  · " + Loc.T("CanBeForged")));
            PeRows.Add(new(".NET", pe.IsDotNet ? Loc.T("Yes") : Loc.T("No")));
            PeRows.Add(new(Loc.T("Sections"), string.Join("  ", pe.Sections.Select(x => $"{x.Name} ({x.Entropy:0.0})")), true));
            PeRows.Add(new(Loc.T("Imports"), Loc.F("ImportsSummary", pe.Imports.Count, pe.Imports.Sum(i => i.Functions.Count))));
            if (pe.Exports.Count > 0) PeRows.Add(new(Loc.T("Exports"), pe.Exports.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)));
            foreach (var key in new[] { "CompanyName", "FileDescription", "ProductName", "FileVersion", "OriginalFilename" })
                if (pe.VersionInfo.TryGetValue(key, out var v)) PeRows.Add(new(key, v));
            PeRows.Add(new(Loc.T("Entropy"), $"{r.Entropy:0.00} / 8"));
        }
        foreach (var w in r.Warnings) Warnings.Add(w);
        foreach (var str in r.Strings.Take(12)) Warnings.Add($"{Loc.T("String")} ({str.Kind}): {str.Value}");
    }

    private async Task CheckProviderAsync()
    {
        if (SelectedProvider is null) return;
        CheckingProvider = true;
        try
        {
            var availability = await coordinator.Provider(SelectedProvider.Id).CheckAvailabilityAsync(CancellationToken.None);
            ProviderChecks.Clear();
            foreach (var c in availability.Checks) ProviderChecks.Add(new CheckRow(c.Label.Get(Loc.Instance.Code), c.Detail.Get(Loc.Instance.Code), c.Passed));
            ProviderReady = availability.IsReady;
        }
        finally { CheckingProvider = false; }
    }

    private AnalysisOptions BuildOptions() => new()
    {
        Duration = TimeSpan.FromSeconds(DurationSeconds),
        Network = NetworkEnabled && NetworkConsent ? NetworkPolicy.Enabled : NetworkPolicy.Disabled,
        CaptureProcesses = CaptureProcesses,
        CaptureFiles = CaptureFiles,
        CaptureRegistry = CaptureRegistry,
        CaptureNetwork = CaptureNetwork,
        TakeSnapshots = TakeSnapshots,
        ProfileId = SelectedProfile?.Profile.Id ?? AnalysisProfile.StandardId,
    };

    [RelayCommand] private Task PickFile() => main.PickAndPrepareAsync();
    [RelayCommand] private Task Recheck() => CheckProviderAsync();

    [RelayCommand]
    private void SaveProfile()
    {
        var name = NewProfileName.Trim();
        if (name.Length == 0) return;
        var id = "custom-" + Guid.NewGuid().ToString("N")[..8];
        var profile = new AnalysisProfile(id, name, name, BuildOptions() with { ProfileId = id }, false);
        settings.Current.Analysis.CustomProfiles.Add(profile);
        settings.Touch();
        Profiles.Add(new ProfileOption(profile));
        SelectedProfile = Profiles[^1];
        NewProfileName = string.Empty;
    }

    [RelayCommand]
    private async Task Start()
    {
        if (Report is null || SelectedProvider is null || !CanStart) return;
        var provider = coordinator.Provider(SelectedProvider.Id);
        await main.StartAnalysisAsync(SamplePath ?? Report.Sample.FileName, Report, BuildOptions(), provider);
    }
}
