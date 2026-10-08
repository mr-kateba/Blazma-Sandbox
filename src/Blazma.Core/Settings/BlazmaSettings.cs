using Blazma.Core.Analysis;
using Blazma.Core.Findings;

namespace Blazma.Core.Settings;

/// <summary>
/// Everything the user can customise. Persisted as one JSON document. Every section has
/// safe defaults; anything that would weaken isolation defaults to off.
/// </summary>
public sealed class BlazmaSettings
{
    public const int CurrentVersion = 1;

    public int Version { get; set; } = CurrentVersion;
    public GeneralSettings General { get; set; } = new();
    public AppearanceSettings Appearance { get; set; } = new();
    public DashboardSettings Dashboard { get; set; } = new();
    public AnalysisSettings Analysis { get; set; } = new();
    public DetectionSettings Detection { get; set; } = new();
    public PrivacySettings Privacy { get; set; } = new();
    public ReportSettings Reports { get; set; } = new();
    public NotificationSettings Notifications { get; set; } = new();
    public StorageSettings Storage { get; set; } = new();
    public ShortcutSettings Shortcuts { get; set; } = new();
    public AiSettings Ai { get; set; } = new();
    public AdvancedSettings Advanced { get; set; } = new();
}

public enum AppLanguage { English, Arabic }

public enum TimeDisplay { Relative, Absolute }

public sealed class GeneralSettings
{
    public AppLanguage Language { get; set; } = AppLanguage.English;
    public TimeDisplay TimelineTime { get; set; } = TimeDisplay.Relative;
    public bool ShowMilliseconds { get; set; } = true;
    public bool Use24HourClock { get; set; } = true;
    public bool ConfirmBeforeDelete { get; set; } = true;
    public bool OnboardingCompleted { get; set; }
}

/// <summary>Theme variants follow the Blazma family: Dark (default), Midnight, Light.</summary>
public enum ThemeVariant { Dark, Midnight, Light }

/// <summary>Blazma orange is the family identity and the default; the others are personal choices.</summary>
/// <summary>Accent choices, all taken from the Blazma family palette (the orange and the two ends of the logo gradient).</summary>
public enum AccentColor { BlazmaOrange, Amber, Ember }

public enum Density { Comfortable, Compact }

public sealed class AppearanceSettings
{
    public ThemeVariant Theme { get; set; } = ThemeVariant.Dark;
    public AccentColor Accent { get; set; } = AccentColor.BlazmaOrange;
    public Density Density { get; set; } = Density.Comfortable;

    /// <summary>Whole-UI scale in percent (90-130).</summary>
    public int UiScalePercent { get; set; } = 100;

    public bool Animations { get; set; } = true;
    public bool ReducedMotion { get; set; }
    public bool SidebarCollapsed { get; set; }

    /// <summary>Soft accent glow around primary elements. Off keeps the UI completely flat.</summary>
    public bool AccentGlow { get; set; } = true;

    public int ClampedScale => Math.Clamp(UiScalePercent, 90, 130);
}

public sealed class DashboardSettings
{
    public bool ShowAnalysesToday { get; set; } = true;
    public bool ShowHighRisk { get; set; } = true;
    public bool ShowSuspicious { get; set; } = true;
    public bool ShowLowRisk { get; set; } = true;
    public bool ShowSandboxStatus { get; set; } = true;
    public int RecentCount { get; set; } = 8;
}

public sealed class AnalysisSettings
{
    public string DefaultProfileId { get; set; } = AnalysisProfile.StandardId;
    public List<AnalysisProfile> CustomProfiles { get; set; } = [];

    /// <summary>The provider used for new analyses. "windows-sandbox" or "demo".</summary>
    public string ProviderId { get; set; } = "windows-sandbox";

    /// <summary>Stop the sample early once it and all its children have exited.</summary>
    public bool StopWhenTreeExits { get; set; } = true;

    public IEnumerable<AnalysisProfile> AllProfiles => AnalysisProfile.BuiltIns.Concat(CustomProfiles);

    public AnalysisProfile ResolveProfile(string? id) =>
        AllProfiles.FirstOrDefault(p => p.Id == id) ?? AnalysisProfile.BuiltIns[1];
}

/// <summary>Per-rule customisation: switch a rule off or change how much it counts.</summary>
public sealed class RuleOverride
{
    public bool Enabled { get; set; } = true;

    /// <summary>Replaces the rule's default weight when set (0-50).</summary>
    public int? Weight { get; set; }
}

public enum WatchlistEntryType { Sha256, Domain, IpAddress, FilePath, ProcessName }

/// <summary>An indicator the user wants flagged whenever it appears. Stays local.</summary>
public sealed record WatchlistEntry(WatchlistEntryType Type, string Value, string? Note = null);

public sealed class DetectionSettings
{
    public RiskThresholds Thresholds { get; set; } = RiskThresholds.Default;
    public Dictionary<string, RuleOverride> RuleOverrides { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Load extra JSON rule packs from the user's rules folder.</summary>
    public bool EnableCustomRulePacks { get; set; } = true;

    public List<WatchlistEntry> Watchlist { get; set; } = [];

    /// <summary>Hide background activity that is not part of the sample's process tree.</summary>
    public bool SuppressBackgroundNoise { get; set; } = true;

    /// <summary>Extra process names or path prefixes the user considers noise.</summary>
    public List<string> NoiseAllowlist { get; set; } = [];

    /// <summary>Publishers whose signed child processes are treated as lower-risk context.</summary>
    public List<string> TrustedPublishers { get; set; } = [];
}

public sealed class PrivacySettings
{
    /// <summary>Replace the user name, machine name and profile path in exported reports.</summary>
    public bool RedactExports { get; set; } = true;

    /// <summary>Opt-in only. Nothing is ever shared unless this is on and the user confirms per report.</summary>
    public bool CommunitySharingEnabled { get; set; }

    // Telemetry and automatic uploads are not settings: Blazma has neither.
}

public enum ReportFormat { Html, Json }

public sealed class ReportSettings
{
    public ReportFormat DefaultFormat { get; set; } = ReportFormat.Html;
    public bool IncludeRawEvents { get; set; }
    public bool IncludeTimeline { get; set; } = true;
    public bool IncludeStaticDetails { get; set; } = true;
    public bool IncludeIndicators { get; set; } = true;
    public int TimelineSummaryLimit { get; set; } = 200;
    public string? DefaultExportFolder { get; set; }
}

public sealed class NotificationSettings
{
    public bool AnalysisCompleted { get; set; } = true;
    public bool AnalysisFailed { get; set; } = true;
    public bool HighRiskDetected { get; set; } = true;
    public bool ReportExported { get; set; } = true;
    public int ToastSeconds { get; set; } = 5;
}

public sealed class StorageSettings
{
    /// <summary>0 keeps analyses forever.</summary>
    public int RetentionDays { get; set; }

    /// <summary>Hard cap on stored events per analysis; extra events are counted, not stored.</summary>
    public int MaxEventsPerAnalysis { get; set; } = 250_000;
}

/// <summary>Key gestures in Avalonia's KeyGesture text format, editable by the user.</summary>
public sealed class ShortcutSettings
{
    public Dictionary<string, string> Bindings { get; set; } = new(Defaults);

    public static IReadOnlyDictionary<string, string> Defaults { get; } = new Dictionary<string, string>
    {
        ["NewAnalysis"] = "Ctrl+N",
        ["CommandPalette"] = "Ctrl+K",
        ["Search"] = "Ctrl+F",
        ["OpenHistory"] = "Ctrl+H",
        ["OpenSettings"] = "Ctrl+OemComma",
        ["ExportReport"] = "Ctrl+E",
        ["ToggleSidebar"] = "Ctrl+B",
        ["SwitchLanguage"] = "Ctrl+Shift+L",
    };

    public string Get(string command) =>
        Bindings.TryGetValue(command, out var g) && !string.IsNullOrWhiteSpace(g) ? g : Defaults.GetValueOrDefault(command, string.Empty);
}

public sealed class AiSettings
{
    /// <summary>Planned. No AI provider ships in this version; Ask Blazma answers from rules and data only.</summary>
    public bool Enabled { get; set; }

    public string? LocalEndpoint { get; set; }
}

public enum LogLevelSetting { Debug, Information, Warning, Error }

public sealed class AdvancedSettings
{
    public LogLevelSetting LogLevel { get; set; } = LogLevelSetting.Information;

    /// <summary>Seconds without a heartbeat before monitoring is reported as interrupted.</summary>
    public int AgentHeartbeatTimeoutSeconds { get; set; } = 15;

    /// <summary>Maximum bytes the sandbox may write back to the host per analysis.</summary>
    public long OutboxQuotaBytes { get; set; } = 512L * 1024 * 1024;

    public int SandboxMemoryMb { get; set; } = 4096;

    /// <summary>Speed of the demo provider (1 = real-time pacing).</summary>
    public double DemoSpeed { get; set; } = 1.0;
}
