using System.Collections.ObjectModel;
using Blazma.App.Localization;
using Blazma.Analysis.Archives;
using Blazma.Analysis.Static;
using Blazma.Analysis.Url;
using Blazma.App.Services;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Samples;
using Blazma.Core.Text;
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

/// <summary>One file inside an archive. Only runnable entries can be analyzed.</summary>
public sealed record ArchiveEntryRow(ArchiveEntry Entry)
{
    public string Path => Entry.Path;
    public string Detail => $"{Fmt.Size(Entry.Size)} · {Loc.T("Kind" + Entry.Kind)}{(Entry.Encrypted ? " · " + Loc.T("Encrypted") : "")}";
    public bool Runnable => SampleInfo.IsRunnable(Entry.Kind);
    public double Dim => Runnable ? 1 : 0.5;
}

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
    [ObservableProperty] private string _urlText = string.Empty;
    [ObservableProperty] private string? _urlError;
    [ObservableProperty] private string _archivePassword = string.Empty;
    [ObservableProperty] private ArchiveEntryRow? _selectedArchiveEntry;
    [ObservableProperty] private bool _extracting;
    private string? _archivePath;
    private SampleInfo? _archiveSample;

    public ObservableCollection<InfoRow> FileRows { get; } = [];
    public ObservableCollection<InfoRow> PeRows { get; } = [];
    public ObservableCollection<string> Warnings { get; } = [];
    public ObservableCollection<CheckRow> ProviderChecks { get; } = [];
    public ObservableCollection<ProfileOption> Profiles { get; } = [];
    public ObservableCollection<ProviderOption> Providers { get; } = [];
    public ObservableCollection<ReputationRow> ReputationRows { get; } = [];
    public ObservableCollection<ArchiveEntryRow> ArchiveEntries { get; } = [];
    public ObservableCollection<InfoRow> UrlRows { get; } = [];
    public ObservableCollection<string> UrlNotes { get; } = [];

    public bool NetworkOffMode { get => !NetworkEnabled && !NetworkSimulated; set { if (value) { NetworkEnabled = false; NetworkSimulated = false; } } }
    public bool NetworkSimulatedMode { get => NetworkSimulated && !NetworkEnabled; set { if (value) { NetworkEnabled = false; NetworkSimulated = true; } } }
    public bool NetworkRealMode { get => NetworkEnabled; set { if (value) { NetworkSimulated = false; NetworkEnabled = true; } } }
    public bool CanLookupOnline => HasReport && !IsDemoSample && reputation.Providers.Any(p => p.IsRemote && p.IsConfigured);
    public bool HasReputation => ReputationRows.Count > 0;

    public bool HasReport => Report is not null;
    public bool HasNoReport => Report is null && !IsLoading;
    public bool HasError => !string.IsNullOrEmpty(Error);
    public bool IsRunnable => Report?.Sample.IsExecutableKind == true;
    public bool IsUrl => Report?.Sample.Kind == FileKind.Url;
    public bool ShowUrlInput => (Report is null || IsUrl) && !IsLoading;
    public bool IsArchive => Report?.Sample.Kind == FileKind.Archive && !IsLoading;
    public bool ArchiveNeedsPassword => IsArchive && Report?.Archive is null;
    public bool HasArchiveEntries => ArchiveEntries.Count > 0;
    public bool HasUrlError => !string.IsNullOrEmpty(UrlError);
    public bool CanAnalyzeEntry => SelectedArchiveEntry?.Runnable == true && !Extracting;
    public bool FromArchive => Report?.Sample.Origin is not null;
    public string OriginText => Report?.Sample.Origin is { } o ? Loc.F("FromArchive", o.EntryPath, o.ArchiveName) : "";
    public bool UrlNeedsNetwork => IsUrl && !NetworkEnabled;
    public string DurationText => Fmt.Duration(TimeSpan.FromSeconds(DurationSeconds));
    public bool CanStart => HasReport && IsRunnable && ProviderReady && (!NetworkEnabled || NetworkConsent) && !IsLoading && !UrlNeedsNetwork;
    public bool ShowNetworkWarning => NetworkEnabled;

    partial void OnReportChanged(StaticReport? value) { BuildRows(); Notify(); }
    partial void OnIsLoadingChanged(bool value) => Notify();
    partial void OnErrorChanged(string? value) => OnPropertyChanged(nameof(HasError));
    partial void OnUrlErrorChanged(string? value) => OnPropertyChanged(nameof(HasUrlError));
    partial void OnSelectedArchiveEntryChanged(ArchiveEntryRow? value) => OnPropertyChanged(nameof(CanAnalyzeEntry));
    partial void OnExtractingChanged(bool value) => OnPropertyChanged(nameof(CanAnalyzeEntry));
    partial void OnDurationSecondsChanged(double value) => OnPropertyChanged(nameof(DurationText));
    partial void OnNetworkEnabledChanged(bool value) { if (!value) { NetworkConsent = false; CapturePcap = false; } Notify(); NotifyNetwork(); _ = CheckProviderAsync(); }
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
        OnPropertyChanged(nameof(IsUrl)); OnPropertyChanged(nameof(IsArchive)); OnPropertyChanged(nameof(ArchiveNeedsPassword));
        OnPropertyChanged(nameof(HasArchiveEntries)); OnPropertyChanged(nameof(FromArchive)); OnPropertyChanged(nameof(OriginText));
        OnPropertyChanged(nameof(UrlNeedsNetwork)); OnPropertyChanged(nameof(ShowUrlInput));
    }

    public override async Task OnShownAsync()
    {
        Profiles.Clear();
        foreach (var p in settings.Current.Analysis.AllProfiles) Profiles.Add(new ProfileOption(p));
        SelectedProfile ??= Profiles.FirstOrDefault(p => p.Profile.Id == settings.Current.Analysis.DefaultProfileId) ?? Profiles.FirstOrDefault();
        Providers.Clear();
        Providers.Add(new ProviderOption(WindowsSandboxProvider.ProviderId, "Windows Sandbox"));
        Providers.Add(new ProviderOption("virtualbox", Loc.T("ProviderVirtualBox")));
        Providers.Add(new ProviderOption("hyperv", Loc.T("ProviderHyperV")));
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

    public Task LoadAsync(string path) => LoadAsync(path, null, null);

    private async Task LoadAsync(string path, string? archivePassword, ArchiveOrigin? origin)
    {
        IsDemoSample = false;
        SamplePath = path;
        Report = null;
        Error = null;
        UrlError = null;
        IsLoading = true;
        ClearReputation();
        if (origin is null) ArchivePassword = archivePassword ?? settings.Current.Analysis.DefaultArchivePassword;
        try
        {
            var report = await coordinator.AnalyzeStaticAsync(path, CancellationToken.None, archivePassword);
            if (origin is not null) report = report with { Sample = report.Sample with { Origin = origin } };
            Report = report;
            if (report.Sample.Kind == FileKind.Archive)
            {
                _archivePath = path;
                _archiveSample = report.Sample;
                Error = report.Archive is null ? Loc.T("ArchiveNeedsPassword") : Loc.T("ArchivePickEntry");
            }
            else if (!report.Sample.IsExecutableKind) Error = Loc.T("NotRunnable");
            await LookupAsync(includeRemote: settings.Current.Integrations.LookupAutomatically);
        }
        catch (Exception ex)
        {
            Error = Loc.T("StaticFailed") + " " + ex.Message;
        }
        finally { IsLoading = false; }
    }

    /// <summary>Re-lists the current archive with the password typed by the user.</summary>
    [RelayCommand]
    private Task RetryArchivePassword() =>
        _archivePath is null ? Task.CompletedTask : LoadAsync(_archivePath, ArchivePassword, null);

    /// <summary>Extracts the chosen entry in the helper process, then prepares it like any file.</summary>
    [RelayCommand]
    private async Task AnalyzeEntry()
    {
        if (_archivePath is null || _archiveSample is null || SelectedArchiveEntry is not { Runnable: true } row) return;
        Extracting = true;
        try
        {
            var encrypted = Report?.Archive?.Encrypted == true || row.Entry.Encrypted;
            IEnumerable<string?> passwords = encrypted
                ? new[] { ArchivePassword }.Concat(ArchiveReader.DefaultPasswords).Where(p => !string.IsNullOrEmpty(p)).Distinct(StringComparer.Ordinal)
                : [null];
            string? extracted = null;
            Exception? last = null;
            foreach (var password in passwords)
            {
                try { extracted = await coordinator.ExtractArchiveEntryAsync(_archivePath, row.Path, password, CancellationToken.None); break; }
                catch (InvalidOperationException ex) { last = ex; }
            }
            if (extracted is null) throw last ?? new InvalidOperationException();
            await LoadAsync(extracted, null, new ArchiveOrigin(_archiveSample.FileName, _archiveSample.Sha256, row.Path));
        }
        catch (Exception ex)
        {
            Error = Loc.T("ExtractFailed") + " " + ex.Message;
        }
        finally { Extracting = false; }
    }

    /// <summary>Prepares a web address: opened in the sandbox's browser, which needs the real network.</summary>
    [RelayCommand]
    private async Task AnalyzeUrl()
    {
        UrlError = null;
        if (!UrlAnalyzer.TryCreateSample(UrlText, out var sample, out LocalizedText? error) || sample is null)
        {
            UrlError = error?.Get(Loc.Instance.Code) ?? Loc.T("UrlInvalid");
            return;
        }
        IsDemoSample = false;
        Error = null;
        ClearReputation();
        _archivePath = null;
        SamplePath = await coordinator.WriteUrlSampleAsync(sample.Url!, CancellationToken.None);
        Report = new StaticReport
        {
            Sample = sample,
            Url = UrlAnalyzer.Analyze(sample.Url!),
            Artifacts = ArtifactExtractor.Extract([sample.Url!], sample.FileName),
        };
        NetworkRealMode = true;
        NotifyNetwork();
        await LookupAsync(includeRemote: settings.Current.Integrations.LookupAutomatically);
    }

    public void LoadDemo()
    {
        IsDemoSample = true;
        SamplePath = null;
        Error = null;
        _archivePath = null;
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
        FileRows.Clear(); PeRows.Clear(); Warnings.Clear(); ArchiveEntries.Clear(); UrlRows.Clear(); UrlNotes.Clear();
        SelectedArchiveEntry = null;
        if (Report is not { } r) return;
        if (r.Archive is { } archive)
        {
            foreach (var e in archive.Entries) ArchiveEntries.Add(new ArchiveEntryRow(e));
            SelectedArchiveEntry = ArchiveEntries.FirstOrDefault(e => e.Runnable);
            if (archive.LimitNote is { } note) Warnings.Add(note);
        }
        if (r.Url is { } url)
        {
            UrlRows.Add(new(Loc.T("UrlHost"), url.UnicodeHost is { } u ? $"{u}  ({url.Host})" : url.Host, true));
            UrlRows.Add(new(Loc.T("UrlAddress"), url.Url, true));
            if (url.LooksLike is { } brand) UrlNotes.Add(Loc.F("UrlLooksLike", brand));
            foreach (var n in url.Notes) UrlNotes.Add(n.Get(Loc.Instance.Code));
        }
        var s = r.Sample;
        FileRows.Add(new(Loc.T("File"), s.FileName));
        if (s.Origin is { } origin) FileRows.Add(new(Loc.T("ArchiveSource"), $"{origin.ArchiveName} → {origin.EntryPath}"));
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
        if (r.ImpHash is { } imp) PeRows.Add(new("Imphash", imp, true));
        if (r.Capabilities.Count > 0) PeRows.Add(new(Loc.T("CapabilitiesTitle"), string.Join(" · ", r.Capabilities.Take(6).Select(c => c.Name.Get(Loc.Instance.Code))) + (r.Capabilities.Count > 6 ? $" (+{r.Capabilities.Count - 6})" : "")));
        if (r.YaraMatches.Count > 0) PeRows.Add(new("YARA", string.Join(", ", r.YaraMatches.Select(m => m.Rule)), true));
        foreach (var w in r.Warnings) Warnings.Add(w);
        foreach (var str in r.Strings.Take(12)) Warnings.Add($"{Loc.T("String")} ({str.Kind}): {str.Value}");
    }

    private async Task CheckProviderAsync()
    {
        if (SelectedProvider is null) return;
        CheckingProvider = true;
        try
        {
            var network = NetworkEnabled ? NetworkPolicy.Enabled : NetworkSimulated ? NetworkPolicy.Simulated : NetworkPolicy.Disabled;
            var availability = await coordinator.Provider(SelectedProvider.Id).CheckAvailabilityAsync(network, CancellationToken.None);
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
