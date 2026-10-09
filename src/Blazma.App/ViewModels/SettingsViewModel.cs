using System.Collections.ObjectModel;
using Avalonia.Input;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Abstractions;
using Blazma.Core.Findings;
using Blazma.Core.Settings;
using Blazma.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Blazma.App.ViewModels;

public sealed record SettingsSection(string Key)
{
    public string Title => Loc.T("Set" + Key);
}

public sealed record EnumOption<T>(T Value, string LabelKey) where T : struct, Enum
{
    public string Label => Loc.T(LabelKey);
    public override string ToString() => Label;
}

public sealed partial class RuleOverrideRow : ObservableObject
{
    private readonly SettingsService _settings;
    public RuleOverrideRow(SettingsService settings, string id, string name, int defaultWeight, string origin)
    {
        _settings = settings;
        Id = id; Name = name; DefaultWeight = defaultWeight; Origin = origin;
        settings.Current.Detection.RuleOverrides.TryGetValue(id, out var o);
        _enabled = o?.Enabled ?? true;
        _weight = o?.Weight ?? defaultWeight;
    }
    public string Id { get; }
    public string Name { get; }
    public int DefaultWeight { get; }
    public string Origin { get; }
    [ObservableProperty] private bool _enabled;
    [ObservableProperty] private decimal _weight;
    partial void OnEnabledChanged(bool value) => Save();
    partial void OnWeightChanged(decimal value) => Save();
    private void Save()
    {
        var map = _settings.Current.Detection.RuleOverrides;
        var w = (int)Math.Clamp(Weight, 0, 50);
        if (Enabled && w == DefaultWeight) map.Remove(Id);
        else map[Id] = new RuleOverride { Enabled = Enabled, Weight = w == DefaultWeight ? null : w };
        _settings.Touch();
    }
}

public sealed partial class ShortcutRow : ObservableObject
{
    private readonly SettingsService _settings;
    public ShortcutRow(SettingsService settings, string command)
    {
        _settings = settings;
        Command = command;
        _gesture = settings.Current.Shortcuts.Get(command);
    }
    public string Command { get; }
    public string Title => Loc.T("Cmd" + Command);
    [ObservableProperty] private string _gesture;
    [ObservableProperty] private bool _invalid;
    partial void OnGestureChanged(string value)
    {
        try { KeyGesture.Parse(value); Invalid = false; _settings.Current.Shortcuts.Bindings[Command] = value; _settings.Touch(); }
        catch (Exception ex) when (ex is ArgumentException or FormatException) { Invalid = true; }
    }
}

/// <summary>Every customisation lives here, grouped into sections. Changes apply immediately and are saved automatically.</summary>
public sealed partial class SettingsViewModel : PageViewModel
{
    private readonly MainViewModel _main;
    private readonly SettingsService _settings;
    private readonly ThemeService _theme;
    private readonly AnalysisCoordinator _coordinator;
    private readonly IAnalysisRepository _repository;
    private readonly BlazmaPaths _paths;
    private readonly ISecretProtector _secrets;
    private readonly Blazma.Intelligence.Ai.LocalAiProvider _ai;

    public SettingsViewModel(MainViewModel main, SettingsService settings, ThemeService theme, AnalysisCoordinator coordinator, IAnalysisRepository repository, BlazmaPaths paths,
        ISecretProtector secrets, Blazma.Intelligence.Ai.LocalAiProvider ai)
    {
        _main = main; _settings = settings; _theme = theme; _coordinator = coordinator; _repository = repository; _paths = paths; _secrets = secrets; _ai = ai;
        Sections = new(new[] { "General", "Appearance", "Dashboard", "Analysis", "Detection", "Sandbox", "Network", "Integrations", "Privacy", "Reports", "Notifications", "Shortcuts", "AI", "Storage", "Language", "Advanced", "About" }.Select(k => new SettingsSection(k)));
        _selectedSection = Sections[0];
    }

    public override string NavKey => "Settings";
    private BlazmaSettings S => _settings.Current;
    private void Changed([System.Runtime.CompilerServices.CallerMemberName] string? name = null) { _settings.Touch(); OnPropertyChanged(name); }
    private void Appearance([System.Runtime.CompilerServices.CallerMemberName] string? name = null) { Changed(name); _theme.Apply(S.Appearance); _main.ApplyAppearance(); }

    public ObservableCollection<SettingsSection> Sections { get; }
    [ObservableProperty] private SettingsSection _selectedSection;
    public bool Is(string key) => SelectedSection.Key == key;
    partial void OnSelectedSectionChanged(SettingsSection value)
    {
        foreach (var k in Sections.Select(s => s.Key)) OnPropertyChanged("Show" + k);
    }
    public bool ShowGeneral => Is("General"); public bool ShowAppearance => Is("Appearance"); public bool ShowDashboard => Is("Dashboard");
    public bool ShowAnalysis => Is("Analysis"); public bool ShowDetection => Is("Detection"); public bool ShowSandbox => Is("Sandbox");
    public bool ShowNetwork => Is("Network"); public bool ShowPrivacy => Is("Privacy"); public bool ShowReports => Is("Reports");
    public bool ShowNotifications => Is("Notifications"); public bool ShowShortcuts => Is("Shortcuts"); public bool ShowAI => Is("AI");
    public bool ShowIntegrations => Is("Integrations");
    public bool ShowStorage => Is("Storage"); public bool ShowLanguage => Is("Language"); public bool ShowAdvanced => Is("Advanced"); public bool ShowAbout => Is("About");

    // General
    public bool RelativeTime { get => S.General.TimelineTime == TimeDisplay.Relative; set { S.General.TimelineTime = value ? TimeDisplay.Relative : TimeDisplay.Absolute; Changed(); } }
    public bool ShowMilliseconds { get => S.General.ShowMilliseconds; set { S.General.ShowMilliseconds = value; Changed(); } }
    public bool ConfirmBeforeDelete { get => S.General.ConfirmBeforeDelete; set { S.General.ConfirmBeforeDelete = value; Changed(); } }
    public bool ExplorerMenuSupported => ShellIntegration.IsSupported;
    public bool ExplorerContextMenu
    {
        get => S.General.ExplorerContextMenu;
        set
        {
            if (!ShellIntegration.Apply(value, Loc.T("ExplorerMenuText")) && value)
            {
                _main.Toasts.Show(ToastKind.Error, Loc.T("ExplorerMenuFailed"));
                OnPropertyChanged();
                return;
            }
            S.General.ExplorerContextMenu = value;
            Changed();
        }
    }
    [RelayCommand] private void ShowOnboarding() => _main.ShowOnboarding();

    // Appearance
    public IReadOnlyList<EnumOption<ThemeVariant>> Themes { get; } = [new(ThemeVariant.Dark, "ThemeDark"), new(ThemeVariant.Midnight, "ThemeMidnight"), new(ThemeVariant.Light, "ThemeLight")];
    public IReadOnlyList<EnumOption<AccentColor>> Accents { get; } = [new(AccentColor.BlazmaOrange, "AccentOrange"), new(AccentColor.Amber, "AccentAmber"), new(AccentColor.Ember, "AccentEmber")];
    public IReadOnlyList<EnumOption<Core.Settings.Density>> Densities { get; } = [new(Core.Settings.Density.Comfortable, "DensityComfortable"), new(Core.Settings.Density.Compact, "DensityCompact")];
    public EnumOption<ThemeVariant> Theme { get => Themes.First(t => t.Value == S.Appearance.Theme); set { if (value is null) return; S.Appearance.Theme = value.Value; Appearance(); } }
    public EnumOption<AccentColor> Accent { get => Accents.First(t => t.Value == S.Appearance.Accent); set { if (value is null) return; S.Appearance.Accent = value.Value; Appearance(); } }
    public EnumOption<Core.Settings.Density> Density { get => Densities.First(t => t.Value == S.Appearance.Density); set { if (value is null) return; S.Appearance.Density = value.Value; Appearance(); } }
    public double UiScale { get => S.Appearance.UiScalePercent; set { S.Appearance.UiScalePercent = (int)Math.Round(value / 5) * 5; Appearance(); OnPropertyChanged(nameof(UiScaleText)); } }
    public string UiScaleText => $"{S.Appearance.ClampedScale}%";
    public bool Animations { get => S.Appearance.Animations; set { S.Appearance.Animations = value; Appearance(); } }
    public bool ReducedMotion { get => S.Appearance.ReducedMotion; set { S.Appearance.ReducedMotion = value; Appearance(); } }
    public bool AccentGlow { get => S.Appearance.AccentGlow; set { S.Appearance.AccentGlow = value; Appearance(); } }
    public bool SidebarCollapsed { get => S.Appearance.SidebarCollapsed; set { S.Appearance.SidebarCollapsed = value; Appearance(); } }

    // Dashboard
    public bool DashToday { get => S.Dashboard.ShowAnalysesToday; set { S.Dashboard.ShowAnalysesToday = value; Changed(); } }
    public bool DashHigh { get => S.Dashboard.ShowHighRisk; set { S.Dashboard.ShowHighRisk = value; Changed(); } }
    public bool DashSuspicious { get => S.Dashboard.ShowSuspicious; set { S.Dashboard.ShowSuspicious = value; Changed(); } }
    public bool DashLow { get => S.Dashboard.ShowLowRisk; set { S.Dashboard.ShowLowRisk = value; Changed(); } }
    public bool DashSandbox { get => S.Dashboard.ShowSandboxStatus; set { S.Dashboard.ShowSandboxStatus = value; Changed(); } }
    public decimal RecentCount { get => S.Dashboard.RecentCount; set { S.Dashboard.RecentCount = (int)Math.Clamp(value, 3, 30); Changed(); } }

    // Analysis
    public ObservableCollection<ProfileOption> Profiles { get; } = [];
    public ProfileOption? DefaultProfile { get => Profiles.FirstOrDefault(p => p.Profile.Id == S.Analysis.DefaultProfileId); set { if (value is null) return; S.Analysis.DefaultProfileId = value.Profile.Id; Changed(); } }
    public bool StopWhenTreeExits { get => S.Analysis.StopWhenTreeExits; set { S.Analysis.StopWhenTreeExits = value; Changed(); } }
    public IReadOnlyList<ProviderOption> Environments => [new("windows-sandbox", "Windows Sandbox"), new("virtualbox", Loc.T("ProviderVirtualBox")), new("hyperv", Loc.T("ProviderHyperV")), new("demo", Loc.T("ProviderDemo"))];
    public ProviderOption? DefaultEnvironment
    {
        get => Environments.FirstOrDefault(e => e.Id == S.Analysis.ProviderId) ?? Environments[0];
        set { if (value is null) return; S.Analysis.ProviderId = value.Id; Changed(); }
    }

    // Virtual machines
    public string VBoxManagePath { get => S.VirtualMachines.VBoxManagePath ?? string.Empty; set { S.VirtualMachines.VBoxManagePath = string.IsNullOrWhiteSpace(value) ? null : value.Trim(); Changed(); } }
    public string VirtualBoxVm { get => S.VirtualMachines.VirtualBoxVm; set { S.VirtualMachines.VirtualBoxVm = value.Trim(); Changed(); } }
    public string VirtualBoxSnapshot { get => S.VirtualMachines.VirtualBoxSnapshot; set { S.VirtualMachines.VirtualBoxSnapshot = value.Trim(); Changed(); } }
    public bool VirtualBoxHeadless { get => S.VirtualMachines.VirtualBoxDisplay == VmDisplay.Headless; set { S.VirtualMachines.VirtualBoxDisplay = value ? VmDisplay.Headless : VmDisplay.Window; Changed(); } }
    public string HyperVVm { get => S.VirtualMachines.HyperVVm; set { S.VirtualMachines.HyperVVm = value.Trim(); Changed(); } }
    public string HyperVCheckpoint { get => S.VirtualMachines.HyperVCheckpoint; set { S.VirtualMachines.HyperVCheckpoint = value.Trim(); Changed(); } }
    public string GuestUser { get => S.VirtualMachines.GuestUser; set { S.VirtualMachines.GuestUser = value.Trim(); Changed(); } }
    public string GuestWorkFolder { get => S.VirtualMachines.GuestWorkFolder; set { S.VirtualMachines.GuestWorkFolder = value.Trim(); Changed(); } }
    public bool RequireDisconnected { get => S.VirtualMachines.RequireDisconnectedNetwork; set { S.VirtualMachines.RequireDisconnectedNetwork = value; Changed(); } }
    public bool HasGuestPassword => !string.IsNullOrEmpty(S.VirtualMachines.GuestPassword);
    [ObservableProperty] private string _guestPasswordInput = string.Empty;

    [RelayCommand]
    private void SaveGuestPassword()
    {
        if (GuestPasswordInput.Length == 0) return;
        S.VirtualMachines.GuestPassword = _secrets.Protect(GuestPasswordInput);
        GuestPasswordInput = string.Empty;
        Changed(nameof(HasGuestPassword));
    }
    [RelayCommand]
    private void DeleteProfile(ProfileOption? p)
    {
        if (p is null || p.Profile.BuiltIn) return;
        S.Analysis.CustomProfiles.RemoveAll(x => x.Id == p.Profile.Id);
        if (S.Analysis.DefaultProfileId == p.Profile.Id) S.Analysis.DefaultProfileId = Core.Analysis.AnalysisProfile.StandardId;
        Changed(nameof(Profiles)); LoadProfiles();
    }

    // Detection
    public ObservableCollection<RuleOverrideRow> RuleRows { get; } = [];
    public decimal ThresholdSuspicious { get => S.Detection.Thresholds.Suspicious; set => SetThresholds(new RiskThresholds((int)value, S.Detection.Thresholds.High, S.Detection.Thresholds.Critical)); }
    public decimal ThresholdHigh { get => S.Detection.Thresholds.High; set => SetThresholds(new RiskThresholds(S.Detection.Thresholds.Suspicious, (int)value, S.Detection.Thresholds.Critical)); }
    public decimal ThresholdCritical { get => S.Detection.Thresholds.Critical; set => SetThresholds(new RiskThresholds(S.Detection.Thresholds.Suspicious, S.Detection.Thresholds.High, (int)value)); }
    [ObservableProperty] private bool _thresholdsInvalid;
    private void SetThresholds(RiskThresholds t)
    {
        ThresholdsInvalid = !t.IsValid;
        if (!t.IsValid) return;
        S.Detection.Thresholds = t;
        Changed(nameof(ThresholdSuspicious)); OnPropertyChanged(nameof(ThresholdHigh)); OnPropertyChanged(nameof(ThresholdCritical));
    }
    public bool SuppressNoise { get => S.Detection.SuppressBackgroundNoise; set { S.Detection.SuppressBackgroundNoise = value; Changed(); } }
    public bool CustomRulePacks { get => S.Detection.EnableCustomRulePacks; set { S.Detection.EnableCustomRulePacks = value; Changed(); LoadRules(); } }
    public string NoiseAllowlist { get => string.Join(Environment.NewLine, S.Detection.NoiseAllowlist); set { S.Detection.NoiseAllowlist = Lines(value); Changed(); } }
    public string TrustedPublishers { get => string.Join(Environment.NewLine, S.Detection.TrustedPublishers); set { S.Detection.TrustedPublishers = Lines(value); Changed(); } }
    [RelayCommand] private void ResetRules() { S.Detection.RuleOverrides.Clear(); _settings.Touch(); LoadRules(); }

    // Sandbox & network
    public decimal SandboxMemory { get => S.Advanced.SandboxMemoryMb; set { S.Advanced.SandboxMemoryMb = (int)Math.Clamp(value, 2048, 32768); Changed(); } }
    public decimal HeartbeatTimeout { get => S.Advanced.AgentHeartbeatTimeoutSeconds; set { S.Advanced.AgentHeartbeatTimeoutSeconds = (int)Math.Clamp(value, 5, 120); Changed(); } }
    public decimal OutboxQuotaMb { get => S.Advanced.OutboxQuotaBytes / (1024 * 1024); set { S.Advanced.OutboxQuotaBytes = (long)Math.Clamp(value, 16, 4096) * 1024 * 1024; Changed(); } }
    [RelayCommand] private void OpenSecurityCenter() => _main.Navigate("Sandbox");

    // Online lookups: hash only, opt-in, keys encrypted at rest
    public bool VirusTotalEnabled { get => S.Integrations.VirusTotalEnabled; set { S.Integrations.VirusTotalEnabled = value; Changed(); } }
    public bool MalwareBazaarEnabled { get => S.Integrations.MalwareBazaarEnabled; set { S.Integrations.MalwareBazaarEnabled = value; Changed(); } }
    public bool LookupAutomatically { get => S.Integrations.LookupAutomatically; set { S.Integrations.LookupAutomatically = value; Changed(); } }
    public bool HasVirusTotalKey => !string.IsNullOrEmpty(S.Integrations.VirusTotalApiKey);
    public bool HasMalwareBazaarKey => !string.IsNullOrEmpty(S.Integrations.MalwareBazaarApiKey);
    public bool SecretsAreWeak => !_secrets.IsStrong;
    [ObservableProperty] private string _virusTotalKeyInput = string.Empty;
    [ObservableProperty] private string _malwareBazaarKeyInput = string.Empty;

    [RelayCommand]
    private void SaveVirusTotalKey()
    {
        if (VirusTotalKeyInput.Trim() is not { Length: > 0 } key) return;
        S.Integrations.VirusTotalApiKey = _secrets.Protect(key);
        VirusTotalKeyInput = string.Empty;
        Changed(nameof(HasVirusTotalKey));
    }

    [RelayCommand]
    private void SaveMalwareBazaarKey()
    {
        if (MalwareBazaarKeyInput.Trim() is not { Length: > 0 } key) return;
        S.Integrations.MalwareBazaarApiKey = _secrets.Protect(key);
        MalwareBazaarKeyInput = string.Empty;
        Changed(nameof(HasMalwareBazaarKey));
    }

    [RelayCommand] private void ForgetVirusTotalKey() { S.Integrations.VirusTotalApiKey = null; Changed(nameof(HasVirusTotalKey)); }
    [RelayCommand] private void ForgetMalwareBazaarKey() { S.Integrations.MalwareBazaarApiKey = null; Changed(nameof(HasMalwareBazaarKey)); }

    // Local AI
    public IReadOnlyList<EnumOption<AiProviderKind>> AiKinds { get; } = [new(AiProviderKind.Ollama, "AiOllama"), new(AiProviderKind.OpenAiCompatible, "AiOpenAiCompatible")];
    public bool AiEnabled { get => S.Ai.Enabled; set { S.Ai.Enabled = value; Changed(); } }
    public EnumOption<AiProviderKind> AiKind
    {
        get => AiKinds.First(k => k.Value == S.Ai.Provider);
        set
        {
            if (value is null || value.Value == S.Ai.Provider) return;
            S.Ai.Provider = value.Value;
            // Each kind has its usual local port; switch only if the user kept the other default.
            if (S.Ai.LocalEndpoint is "http://127.0.0.1:11434" or "http://127.0.0.1:1234")
                S.Ai.LocalEndpoint = value.Value == AiProviderKind.Ollama ? "http://127.0.0.1:11434" : "http://127.0.0.1:1234";
            Changed(); OnPropertyChanged(nameof(AiEndpoint));
        }
    }
    public string AiEndpoint { get => S.Ai.LocalEndpoint; set { S.Ai.LocalEndpoint = value.Trim(); Changed(); } }
    public string AiModel { get => S.Ai.Model; set { S.Ai.Model = value.Trim(); Changed(); } }
    public bool AiAllowRemote { get => S.Ai.AllowRemoteEndpoint; set { S.Ai.AllowRemoteEndpoint = value; Changed(); } }
    [ObservableProperty] private string? _aiTestResult;
    [ObservableProperty] private bool _aiTesting;
    public ObservableCollection<string> AiModels { get; } = [];

    [RelayCommand]
    private async Task TestAi()
    {
        AiTesting = true;
        AiTestResult = null;
        try
        {
            var result = await _ai.TestConnectionAsync();
            AiModels.Clear();
            foreach (var m in result.Models.Take(50)) AiModels.Add(m);
            AiTestResult = result.Success ? Loc.F("AiConnected", result.Models.Count) : result.Error?.Get(Loc.Instance.Code) ?? Loc.T("AiNotConnected");
        }
        finally { AiTesting = false; }
    }

    // Privacy
    public bool RedactExports { get => S.Privacy.RedactExports; set { S.Privacy.RedactExports = value; Changed(); } }

    // Reports
    public IReadOnlyList<EnumOption<ReportFormat>> Formats { get; } = [new(ReportFormat.Html, "FormatHtml"), new(ReportFormat.Pdf, "FormatPdf"), new(ReportFormat.Json, "FormatJson")];
    public EnumOption<ReportFormat> DefaultFormat { get => Formats.First(f => f.Value == S.Reports.DefaultFormat); set { if (value is null) return; S.Reports.DefaultFormat = value.Value; Changed(); } }
    public bool IncludeRawEvents { get => S.Reports.IncludeRawEvents; set { S.Reports.IncludeRawEvents = value; Changed(); } }
    public bool IncludeTimeline { get => S.Reports.IncludeTimeline; set { S.Reports.IncludeTimeline = value; Changed(); } }
    public bool IncludeStatic { get => S.Reports.IncludeStaticDetails; set { S.Reports.IncludeStaticDetails = value; Changed(); } }
    public bool IncludeIndicators { get => S.Reports.IncludeIndicators; set { S.Reports.IncludeIndicators = value; Changed(); } }
    public decimal TimelineLimit { get => S.Reports.TimelineSummaryLimit; set { S.Reports.TimelineSummaryLimit = (int)Math.Clamp(value, 20, 5000); Changed(); } }

    // Notifications
    public bool NotifyCompleted { get => S.Notifications.AnalysisCompleted; set { S.Notifications.AnalysisCompleted = value; Changed(); } }
    public bool NotifyFailed { get => S.Notifications.AnalysisFailed; set { S.Notifications.AnalysisFailed = value; Changed(); } }
    public bool NotifyHighRisk { get => S.Notifications.HighRiskDetected; set { S.Notifications.HighRiskDetected = value; Changed(); } }
    public bool NotifyExported { get => S.Notifications.ReportExported; set { S.Notifications.ReportExported = value; Changed(); } }
    public decimal ToastSeconds { get => S.Notifications.ToastSeconds; set { S.Notifications.ToastSeconds = (int)Math.Clamp(value, 2, 20); Changed(); } }

    // Shortcuts
    public ObservableCollection<ShortcutRow> Shortcuts { get; } = [];
    [RelayCommand] private void ResetShortcuts() { S.Shortcuts.Bindings = new(ShortcutSettings.Defaults); _settings.Touch(); LoadShortcuts(); }

    // Storage
    public decimal RetentionDays { get => S.Storage.RetentionDays; set { S.Storage.RetentionDays = (int)Math.Clamp(value, 0, 3650); Changed(); } }
    public decimal MaxEvents { get => S.Storage.MaxEventsPerAnalysis; set { S.Storage.MaxEventsPerAnalysis = (int)Math.Clamp(value, 10_000, 2_000_000); Changed(); } }
    public string DataFolder => _paths.Root;
    public string DatabaseSize => File.Exists(_paths.Database) ? Fmt.Size(new FileInfo(_paths.Database).Length) : "—";
    [RelayCommand] private void OpenDataFolder() => _main.OpenFolder(_paths.Root);
    [RelayCommand]
    private async Task ClearHistory()
    {
        if (!await _main.Dialogs.ConfirmAsync(Loc.T("ClearHistoryTitle"), Loc.T("ClearHistoryBody"), Loc.T("ClearHistory"), danger: true)) return;
        var removed = await _repository.PurgeOlderThanAsync(DateTimeOffset.MaxValue, CancellationToken.None);
        _main.Toasts.Show(ToastKind.Info, Loc.F("RemovedAnalyses", removed));
        OnPropertyChanged(nameof(DatabaseSize));
    }

    // Language
    public bool English { get => S.General.Language == AppLanguage.English; set { if (value) _main.SetLanguage(AppLanguage.English); } }
    public bool Arabic { get => S.General.Language == AppLanguage.Arabic; set { if (value) _main.SetLanguage(AppLanguage.Arabic); } }

    // Advanced
    public IReadOnlyList<EnumOption<LogLevelSetting>> LogLevels { get; } = [new(LogLevelSetting.Debug, "LogDebug"), new(LogLevelSetting.Information, "LogInformation"), new(LogLevelSetting.Warning, "LogWarning"), new(LogLevelSetting.Error, "LogError")];
    public EnumOption<LogLevelSetting> LogLevel { get => LogLevels.First(l => l.Value == S.Advanced.LogLevel); set { if (value is null) return; S.Advanced.LogLevel = value.Value; Changed(); } }
    public double DemoSpeed { get => S.Advanced.DemoSpeed; set { S.Advanced.DemoSpeed = Math.Clamp(Math.Round(value, 1), 0.5, 10); Changed(); OnPropertyChanged(nameof(DemoSpeedText)); } }
    public string DemoSpeedText => $"×{S.Advanced.DemoSpeed:0.0}";
    public string LogsFolder => _paths.Logs;
    [RelayCommand] private void OpenLogs() => _main.OpenFolder(_paths.Logs);
    [RelayCommand] private void OpenDeveloper() => _main.OpenUrl("https://github.com/mr-kateba");
    [RelayCommand]
    private async Task ResetAll()
    {
        if (!await _main.Dialogs.ConfirmAsync(Loc.T("ResetTitle"), Loc.T("ResetBody"), Loc.T("Reset"), danger: true)) return;
        _settings.Reset();
        _theme.Apply(S.Appearance);
        _main.ApplyAppearance();
        await OnShownAsync();
        foreach (var p in GetType().GetProperties()) OnPropertyChanged(p.Name);
    }

    // About
    public string Version => typeof(SettingsViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.1.0";

    public override Task OnShownAsync()
    {
        LoadProfiles(); LoadRules(); LoadShortcuts();
        OnPropertyChanged(nameof(DatabaseSize));
        return Task.CompletedTask;
    }

    private void LoadProfiles()
    {
        Profiles.Clear();
        foreach (var p in S.Analysis.AllProfiles) Profiles.Add(new ProfileOption(p));
        OnPropertyChanged(nameof(DefaultProfile));
    }

    private void LoadRules()
    {
        RuleRows.Clear();
        foreach (var r in _coordinator.BuildRuleEngine().Rules)
            RuleRows.Add(new RuleOverrideRow(_settings, r.Metadata.Id, r.Metadata.Name.Get(Loc.Instance.Code), r.Metadata.Weight, r.Metadata.Origin));
    }

    private void LoadShortcuts()
    {
        Shortcuts.Clear();
        foreach (var c in ShortcutSettings.Defaults.Keys) Shortcuts.Add(new ShortcutRow(_settings, c));
    }

    private static List<string> Lines(string text) => text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    protected override void OnLanguageChanged()
    {
        _ = OnShownAsync();
        foreach (var p in GetType().GetProperties()) OnPropertyChanged(p.Name);
    }
}
