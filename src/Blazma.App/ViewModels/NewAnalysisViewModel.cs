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

/// <summary>One hash-reputation answer, shown before the run.</summary>
public sealed record ReputationRow(string Provider, string Verdict, string Detail, bool Bad, string? Link);

/// <summary>Preparation: show what the file is, choose how to analyze it, then start. Nothing runs before Start.</summary>
public sealed partial class NewAnalysisViewModel(MainViewModel main, AnalysisCoordinator coordinator, SettingsService settings, Blazma.Intelligence.Reputation.ReputationService reputation) : PageViewModel
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
    [ObservableProperty] private bool _networkSimulated = true;
    [ObservableProperty] private bool _networkConsent;
    [ObservableProperty] private bool _interactive;
    [ObservableProperty] private bool _simulateUser = true;
    [ObservableProperty] private bool _captureScreenshots = true;
    [ObservableProperty] private bool _collectDropped = true;
    [ObservableProperty] private bool _dumpMemory = true;
    [ObservableProperty] private bool _capturePcap;
    [ObservableProperty] private bool _checkingReputation;
    private IReadOnlyList<ReputationResult> _reputation = [];
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
    public ObservableCollection<ReputationRow> ReputationRows { get; } = [];

    public bool NetworkOffMode { get => !NetworkEnabled && !NetworkSimulated; set { if (value) { NetworkEnabled = false; NetworkSimulated = false; } } }
    public bool NetworkSimulatedMode { get => NetworkSimulated && !NetworkEnabled; set { if (value) { NetworkEnabled = false; NetworkSimulated = true; } } }
    public bool NetworkRealMode { get => NetworkEnabled; set { if (value) { NetworkSimulated = false; NetworkEnabled = true; } } }
    public bool CanLookupOnline => HasReport && !IsDemoSample && reputation.Providers.Any(p => p.IsRemote && p.IsConfigured);
    public bool HasReputation => ReputationRows.Count > 0;

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
    partial void OnNetworkEnabledChanged(bool value) { if (!value) { NetworkConsent = false; CapturePcap = false; } Notify(); NotifyNetwork(); }
    partial void OnNetworkSimulatedChanged(bool value) => NotifyNetwork();
    partial void OnInteractiveChanged(bool value) { if (value) SimulateUser = false; }
    private void NotifyNetwork()
    {
        OnPropertyChanged(nameof(NetworkOffMode)); OnPropertyChanged(nameof(NetworkSimulatedMode)); OnPropertyChanged(nameof(NetworkRealMode));
    }
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
        // A profile never switches the real network on by itself; that always needs consent here.
        NetworkEnabled = false;
        NetworkSimulated = o.Network == NetworkPolicy.Simulated;
        Interactive = o.Interactive;
        SimulateUser = o.SimulateUser;
        CaptureScreenshots = o.CaptureScreenshots;
        CollectDropped = o.CollectDroppedFiles;
        DumpMemory = o.DumpMemory;
    }

    private void Notify()
    {
        OnPropertyChanged(nameof(HasReport)); OnPropertyChanged(nameof(HasNoReport)); OnPropertyChanged(nameof(IsRunnable));
        OnPropertyChanged(nameof(CanStart)); OnPropertyChanged(nameof(ShowNetworkWarning)); OnPropertyChanged(nameof(CanLookupOnline));
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
        ClearReputation();
        try
        {
            Report = await coordinator.AnalyzeStaticAsync(path, CancellationToken.None);
            if (!Report.Sample.IsExecutableKind) Error = Loc.T("NotRunnable");
            await LookupAsync(includeRemote: settings.Current.Integrations.LookupAutomatically);
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
        ClearReputation();
        Report = AnalysisCoordinator.DemoSample();
    }

    private void ClearReputation()
    {
        _reputation = [];
        ReputationRows.Clear();
        OnPropertyChanged(nameof(HasReputation));
    }

    /// <summary>Hash-only lookups. Remote services are asked only when the user enabled them, and never for the demo.</summary>
    private async Task LookupAsync(bool includeRemote)
    {
        if (Report is null || IsDemoSample) return;
        CheckingReputation = true;
        try
        {
            _reputation = (await reputation.LookupAsync(Report.Sample.Sha256, includeRemote, CancellationToken.None))
                .Where(r => r.Verdict != ReputationVerdict.NotFound || r.ProviderId != "local-history").ToList();
            ReputationRows.Clear();
            foreach (var r in _reputation)
            {
                var detail = r.Error ?? string.Join(" · ", new[]
                {
                    r.Detections is { } d ? Loc.F("RepDetections", d, r.Engines ?? 0) : null,
                    r.Family is { Length: > 0 } f ? Loc.F("RepFamily", f) : null,
                    r.Tags.Count > 0 ? string.Join(", ", r.Tags.Take(4)) : null,
                }.Where(x => x is not null));
                ReputationRows.Add(new ReputationRow(r.ProviderName, Loc.T("Rep" + r.Verdict), detail,
                    r.Verdict is ReputationVerdict.Malicious or ReputationVerdict.Suspicious, r.Link));
            }
            OnPropertyChanged(nameof(HasReputation));
        }
        finally { CheckingReputation = false; }
    }

    [RelayCommand] private Task LookupOnline() => LookupAsync(includeRemote: true);
    [RelayCommand] private void OpenLink(string? url) => main.OpenUrl(url);

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
        Network = NetworkEnabled && NetworkConsent ? NetworkPolicy.Enabled : NetworkSimulated ? NetworkPolicy.Simulated : NetworkPolicy.Disabled,
        Interactive = Interactive,
        SimulateUser = SimulateUser && !Interactive,
        CaptureScreenshots = CaptureScreenshots,
        CollectDroppedFiles = CollectDropped,
        DumpMemory = DumpMemory,
        CapturePcap = CapturePcap && NetworkEnabled,
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
        await main.StartAnalysisAsync(SamplePath ?? Report.Sample.FileName, Report, BuildOptions(), provider, _reputation);
    }
}
