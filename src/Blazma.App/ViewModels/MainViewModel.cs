using System.Collections.ObjectModel;
using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Samples;
using Blazma.Core.Settings;
using Blazma.Sandbox.Providers.Demo;
using Blazma.Sandbox.Providers.WindowsSandbox;
using Blazma.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;

namespace Blazma.App.ViewModels;

public sealed partial class NavItem(string key, string iconKey, Action<string> navigate) : ObservableObject
{
    public string Key { get; } = key;
    public string IconKey { get; } = iconKey;
    public string Title => Loc.T("Nav" + Key);
    [ObservableProperty] private bool _isActive;
    [RelayCommand] private void Go() => navigate(Key);
    public void Refresh() => OnPropertyChanged(nameof(Title));
}

/// <summary>The shell: navigation, overlays (dialogs, palette, search, onboarding, toasts) and app-wide actions.</summary>
public sealed partial class MainViewModel : ViewModelBase
{
    private readonly IServiceProvider _services;
    private readonly SettingsService _settings;
    private readonly AnalysisCoordinator _coordinator;
    private readonly ILogger<MainViewModel> _logger;
    private readonly Dictionary<string, PageViewModel> _pages = [];
    private (string Path, StaticReport Report, AnalysisOptions Options, string ProviderId)? _last;

    public MainViewModel(IServiceProvider services, SettingsService settings, AnalysisCoordinator coordinator, DialogService dialogs, ToastService toasts,
        ExportService exports, IAnalysisRepository repository, ThemeService theme, BlazmaPaths paths, ILogger<MainViewModel> logger)
    {
        _services = services;
        _settings = settings;
        _coordinator = coordinator;
        _logger = logger;
        Dialogs = dialogs;
        Toasts = toasts;
        Exports = exports;
        Repository = repository;
        Theme = theme;
        Paths = paths;
        Nav =
        [
            new NavItem("Dashboard", "IconDashboard", Navigate),
            new NavItem("NewAnalysis", "IconNew", Navigate),
            new NavItem("History", "IconHistory", Navigate),
            new NavItem("Reports", "IconReports", Navigate),
            new NavItem("Intelligence", "IconIntel", Navigate),
            new NavItem("Sandbox", "IconSandbox", Navigate),
            new NavItem("Settings", "IconSettings", Navigate),
        ];
        Palette = new CommandPaletteViewModel(this);
        Search = new SearchViewModel(this, repository);
        Onboarding = new OnboardingViewModel(this, coordinator, settings, paths);
        _sidebarCollapsed = settings.Current.Appearance.SidebarCollapsed;
    }

    public DialogService Dialogs { get; }
    public ToastService Toasts { get; }
    public ExportService Exports { get; }
    public IAnalysisRepository Repository { get; }
    public ThemeService Theme { get; }
    public BlazmaPaths Paths { get; }
    public ObservableCollection<NavItem> Nav { get; }
    public CommandPaletteViewModel Palette { get; }
    public SearchViewModel Search { get; }
    public OnboardingViewModel Onboarding { get; }
    public SettingsService Settings => _settings;

    [ObservableProperty] private PageViewModel? _currentPage;
    [ObservableProperty] private bool _sidebarCollapsed;
    [ObservableProperty] private string _sandboxStatus = string.Empty;
    [ObservableProperty] private bool _sandboxReady;
    [ObservableProperty] private bool _analysisRunning;
    [ObservableProperty] private double _uiScale = 1;
    [ObservableProperty] private bool _motion = true;

    public string Version => "v" + (typeof(MainViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.1.0");
    public string SystemStatus => Loc.T("SystemOk");
    public bool SidebarExpanded => !SidebarCollapsed;
    public double SidebarWidth => SidebarCollapsed ? 68 : 232;
    partial void OnSidebarCollapsedChanged(bool value) { OnPropertyChanged(nameof(SidebarExpanded)); OnPropertyChanged(nameof(SidebarWidth)); }

    public T Page<T>() where T : PageViewModel
    {
        var key = typeof(T).Name;
        if (!_pages.TryGetValue(key, out var page))
        {
            page = Microsoft.Extensions.DependencyInjection.ActivatorUtilities.CreateInstance<T>(_services, this);
            _pages[key] = page;
        }
        return (T)page;
    }

    public async Task InitializeAsync()
    {
        ApplyAppearance();
        Navigate("Dashboard");
        await RefreshSandboxStatusAsync();
        if (!_settings.Current.General.OnboardingCompleted) Onboarding.Open();
        if (_settings.Current.Storage.RetentionDays > 0)
            await Repository.PurgeOlderThanAsync(DateTimeOffset.Now.AddDays(-_settings.Current.Storage.RetentionDays), CancellationToken.None);
    }

    public async Task RefreshSandboxStatusAsync()
    {
        ProviderAvailability availability;
        try
        {
            availability = await _coordinator.Provider(WindowsSandboxProvider.ProviderId).CheckAvailabilityAsync(CancellationToken.None);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // A status badge must never turn the end of an analysis (or a language switch) into an error.
            _logger.LogWarning(ex, "Could not check the Windows Sandbox status");
            SandboxReady = false;
            SandboxStatus = Loc.T("SandboxNeedsSetup");
            return;
        }
        SandboxReady = availability.IsReady;
        SandboxStatus = availability.Readiness switch
        {
            ProviderReadiness.Ready => Loc.T("SandboxReady"),
            ProviderReadiness.NotSupported => Loc.T("SandboxNotSupported"),
            ProviderReadiness.Unavailable => Loc.T("SandboxBusy"),
            _ => Loc.T("SandboxNeedsSetup"),
        };
    }

    public void ApplyAppearance()
    {
        var a = _settings.Current.Appearance;
        UiScale = a.ClampedScale / 100.0;
        Motion = a.Animations && !a.ReducedMotion;
        SidebarCollapsed = a.SidebarCollapsed;
    }

    public void Navigate(string key)
    {
        PageViewModel page = key switch
        {
            "Dashboard" => Page<DashboardViewModel>(),
            "NewAnalysis" => AnalysisRunning ? Page<LiveAnalysisViewModel>() : Page<NewAnalysisViewModel>(),
            "History" => Page<HistoryViewModel>(),
            "Reports" => Page<ReportsViewModel>(),
            "Intelligence" => Page<IntelligenceViewModel>(),
            "Sandbox" => Page<SecurityCenterViewModel>(),
            "Settings" => Page<SettingsViewModel>(),
            _ => Page<DashboardViewModel>(),
        };
        Show(page);
    }

    private void Show(PageViewModel page)
    {
        CurrentPage = page;
        foreach (var n in Nav) n.IsActive = n.Key == page.NavKey;
        _ = SafeAsync(page.OnShownAsync);
    }

    /// <summary>Background work never takes the app down: failures become a dialog.</summary>
    public async Task SafeAsync(Func<Task> work)
    {
        try { await work(); }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled UI operation failure");
            await Dialogs.ErrorAsync(Loc.T("UnexpectedTitle"), ex.Message, ex.GetType().FullName, canRetry: false);
        }
    }

    public async Task PickAndPrepareAsync()
    {
        var path = await _services.GetRequiredServiceSafe<FileDialogService>().PickSampleAsync();
        if (path is not null) await PrepareFileAsync(path);
    }

    public async Task PrepareFileAsync(string path)
    {
        if (AnalysisRunning) { Toasts.Show(ToastKind.Warning, Loc.T("AlreadyRunning")); Navigate("NewAnalysis"); return; }
        var page = Page<NewAnalysisViewModel>();
        Show(page);
        await page.LoadAsync(path);
    }

    public async Task PrepareDemoAsync()
    {
        if (AnalysisRunning) { Toasts.Show(ToastKind.Warning, Loc.T("AlreadyRunning")); Navigate("NewAnalysis"); return; }
        var page = Page<NewAnalysisViewModel>();
        page.LoadDemo();
        Show(page);
        await Task.CompletedTask;
    }

    public async Task StartAnalysisAsync(string path, StaticReport report, AnalysisOptions options, ISandboxProvider provider, IReadOnlyList<ReputationResult>? reputation = null)
    {
        _last = (path, report, options, provider.Id);
        ActiveAnalysis active;
        try
        {
            active = _coordinator.Start(path, report, options, provider, reputation);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogError(ex, "The analysis of {FileName} could not start", report.Sample.FileName);
            await Dialogs.ErrorAsync(Loc.T("AnalysisStartFailedTitle"), LiveAnalysisViewModel.FailureText(ex), ex.GetType().FullName, canRetry: false);
            return;
        }
        AnalysisRunning = true;
        var live = Page<LiveAnalysisViewModel>();
        live.Attach(active);
        Show(live);
        try { await active.Completion; } catch { /* reported by the live page */ }
        finally { AnalysisRunning = false; await RefreshSandboxStatusAsync(); }
    }

    public async Task RetryLastAsync()
    {
        if (_last is not { } l) return;
        await StartAnalysisAsync(l.Path, l.Report, l.Options, _coordinator.Provider(l.ProviderId));
    }

    public async Task OpenReportAsync(Guid id, int tab = 0, long? focusSequence = null)
    {
        var page = Page<ReportViewModel>();
        Show(page);
        await page.LoadAsync(id, tab, focusSequence);
    }

    public void OpenCompare(Guid id)
    {
        var page = Page<ReportsViewModel>();
        page.Preselect = id;
        Show(page);
    }

    public async Task CopyAsync(string text)
    {
        var top = (Avalonia.Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow;
        if (top?.Clipboard is { } clipboard)
        {
            await Avalonia.Input.Platform.ClipboardExtensions.SetTextAsync(clipboard, text);
            Toasts.Show(ToastKind.Info, Loc.T("Copied"));
        }
    }

    public void OpenFolder(string folder)
    {
        try
        {
            Directory.CreateDirectory(folder);
            // Opens a folder in the file manager. Never used for anything from the sandbox output.
            Process.Start(new ProcessStartInfo(OperatingSystem.IsWindows() ? "explorer.exe" : "xdg-open", $"\"{folder}\"") { UseShellExecute = false });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException)
        {
            Toasts.Show(ToastKind.Warning, Loc.T("OpenFolderFailed"), folder);
        }
    }

    public void SetLanguage(AppLanguage language)
    {
        _settings.Current.General.Language = language;
        _settings.Touch();
        Loc.Instance.SetLanguage(language);
    }

    protected override void OnLanguageChanged()
    {
        foreach (var n in Nav) n.Refresh();
        OnPropertyChanged(nameof(SystemStatus));
        _ = RefreshSandboxStatusAsync();
    }

    [RelayCommand] private void ToggleSidebar() { _settings.Current.Appearance.SidebarCollapsed = !SidebarCollapsed; _settings.Touch(); ApplyAppearance(); }
    [RelayCommand] private void SwitchLanguage() => SetLanguage(Loc.Instance.IsArabic ? AppLanguage.English : AppLanguage.Arabic);
    [RelayCommand]
    private void CycleTheme()
    {
        var a = _settings.Current.Appearance;
        a.Theme = a.Theme switch { ThemeVariant.Dark => ThemeVariant.Midnight, ThemeVariant.Midnight => ThemeVariant.Light, _ => ThemeVariant.Dark };
        _settings.Touch();
        Theme.Apply(a);
        ApplyAppearance();
        Toasts.Show(ToastKind.Info, Loc.T("Theme" + a.Theme));
    }
    [RelayCommand] private void OpenPalette() => Palette.Open();
    [RelayCommand] private void ShowOnboardingCmd() => ShowOnboarding();
    public void ShowOnboarding() => Onboarding.Open();
    [RelayCommand] private Task NewAnalysis() => PickAndPrepareAsync();
    [RelayCommand] private void Go(string key) => Navigate(key);
    [RelayCommand] private void OpenGitHub() => OpenUrl("https://github.com/mr-kateba/Blazma-Sandbox");

    [RelayCommand]
    private async Task ExportCurrent()
    {
        if (CurrentPage is ReportViewModel { Result: { } r }) await Exports.ExportAsync(r, _settings.Current.Reports.DefaultFormat);
        else Toasts.Show(ToastKind.Info, Loc.T("OpenReportFirst"));
    }

    /// <summary>Escape closes the top-most overlay.</summary>
    public bool CloseOverlay()
    {
        if (Dialogs.Current is not null) { Dialogs.CancelCurrent(); return true; }
        if (Palette.IsOpen) { Palette.IsOpen = false; return true; }
        if (Search.IsOpen) { Search.IsOpen = false; return true; }
        if (CurrentPage is ReportViewModel { SelectedFinding: not null } report) { report.SelectedFinding = null; return true; }
        return false;
    }

    /// <summary>Opens a web page in the user's browser. Only https addresses; never anything taken from a sample.</summary>
    public void OpenUrl(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps) return;
        try { Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true }); }
        catch (System.ComponentModel.Win32Exception) { }
    }

    public List<PaletteCommand> PaletteCommands()
    {
        string K(string id) => _settings.Current.Shortcuts.Get(id).Replace("OemComma", ",", StringComparison.Ordinal).Replace("OemPeriod", ".", StringComparison.Ordinal);
        return
        [
            new("new", Loc.T("CmdNewAnalysis"), K("NewAnalysis"), PickAndPrepareAsync),
            new("demo", Loc.T("CmdRunDemo"), string.Empty, PrepareDemoAsync),
            new("history", Loc.T("CmdOpenHistory"), K("OpenHistory"), () => { Navigate("History"); return Task.CompletedTask; }),
            new("hash", Loc.T("CmdSearchHash"), K("Search"), () => { SearchFocusRequested?.Invoke(this, EventArgs.Empty); return Task.CompletedTask; }),
            new("compare", Loc.T("CmdCompare"), string.Empty, () => { Navigate("Reports"); return Task.CompletedTask; }),
            new("export", Loc.T("CmdExportReport"), K("ExportReport"), ExportCurrent),
            new("settings", Loc.T("CmdOpenSettings"), K("OpenSettings"), () => { Navigate("Settings"); return Task.CompletedTask; }),
            new("security", Loc.T("CmdSecurityCenter"), string.Empty, () => { Navigate("Sandbox"); return Task.CompletedTask; }),
            new("intel", Loc.T("CmdWatchlist"), string.Empty, () => { Navigate("Intelligence"); return Task.CompletedTask; }),
            new("lang", Loc.T("CmdSwitchLanguage"), K("SwitchLanguage"), () => { SwitchLanguage(); return Task.CompletedTask; }),
            new("theme", Loc.T("CmdSwitchTheme"), string.Empty, () => { CycleTheme(); return Task.CompletedTask; }),
            new("sidebar", Loc.T("CmdToggleSidebar"), K("ToggleSidebar"), () => { ToggleSidebar(); return Task.CompletedTask; }),
            new("onboarding", Loc.T("CmdOnboarding"), string.Empty, () => { ShowOnboarding(); return Task.CompletedTask; }),
        ];
    }

    public event EventHandler? SearchFocusRequested;
}

internal static class ServiceProviderExtensions
{
    public static T GetRequiredServiceSafe<T>(this IServiceProvider sp) where T : notnull =>
        (T)(sp.GetService(typeof(T)) ?? throw new InvalidOperationException($"{typeof(T).Name} is not registered."));
}
