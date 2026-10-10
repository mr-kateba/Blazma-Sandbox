using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Controls.Templates;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.App.ViewModels;
using Blazma.App.Views;
using Blazma.Core.Abstractions;
using Blazma.Core.Settings;
using Blazma.Intelligence;
using Blazma.Intelligence.Ai;
using Blazma.Intelligence.Net;
using Blazma.Intelligence.Reputation;
using Blazma.Storage;
using Blazma.Storage.Secrets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Formatting.Compact;

namespace Blazma.App;

public partial class App : Application
{
    private static Serilog.Core.Logger? _log;
    private static string? _logsFolder;

    public static IServiceProvider? Services { get; private set; }

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    /// <summary>Configures services. Exposed so the screenshot tool and tests can build the same graph.</summary>
    /// <summary>Set by Program when this process owns the single-instance lock.</summary>
    internal static SingleInstance? Instance { get; set; }

    public static ServiceProvider BuildServices(BlazmaPaths paths)
    {
        paths.EnsureCreated();
        var store = new SettingsStore(paths);
        var settings = store.Load();
        _logsFolder = paths.Logs;
        _log = new LoggerConfiguration()
            .MinimumLevel.Is(settings.Advanced.LogLevel switch
            {
                LogLevelSetting.Debug => Serilog.Events.LogEventLevel.Debug,
                LogLevelSetting.Warning => Serilog.Events.LogEventLevel.Warning,
                LogLevelSetting.Error => Serilog.Events.LogEventLevel.Error,
                _ => Serilog.Events.LogEventLevel.Information,
            })
            // Structured JSON logs. Never sample contents, never secrets.
            .WriteTo.File(new CompactJsonFormatter(), Path.Combine(paths.Logs, "blazma-.log"), rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14)
            .CreateLogger();

        var services = new ServiceCollection();
        services.AddLogging(b => b.ClearProviders().AddSerilog(_log, dispose: false));
        services.AddSingleton(paths);
        services.AddSingleton(store);
        services.AddSingleton<SettingsService>();
        services.AddSingleton<ThemeService>();
        services.AddSingleton<ToastService>();
        services.AddSingleton<DialogService>();
        services.AddSingleton<FileDialogService>();
        services.AddSingleton<ExportService>();
        services.AddSingleton<IAnalysisRepository>(sp => new SqliteAnalysisRepository(paths.Database, sp.GetRequiredService<ILogger<SqliteAnalysisRepository>>()) { ArtifactsRoot = paths.Artifacts });
        services.AddSingleton<AnalysisCoordinator>();

        // Online lookups (opt-in, hash only) and local AI (loopback only by default). Settings are read on every call.
        services.AddSingleton<ISecretProtector>(_ => SecretProtector.CreateDefault());
        services.AddSingleton(sp =>
        {
            var current = sp.GetRequiredService<SettingsService>();
            var secrets = sp.GetRequiredService<ISecretProtector>();
            var http = IntegrationHttp.CreateClient();
            return new ReputationService(
            [
                new LocalHistoryReputationProvider(sp.GetRequiredService<IAnalysisRepository>()),
                new VirusTotalReputationProvider(http, () => current.Current.Integrations, secrets),
                new MalwareBazaarReputationProvider(http, () => current.Current.Integrations, secrets),
            ]);
        });
        services.AddSingleton(sp =>
        {
            var current = sp.GetRequiredService<SettingsService>();
            return new LocalAiProvider(IntegrationHttp.CreateClient(useProxy: false), () => current.Current.Ai);
        });
        services.AddSingleton<MainViewModel>();
        return services.BuildServiceProvider();
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var splash = new SplashWindow();
            desktop.MainWindow = splash;
            splash.Show();
            Dispatcher.UIThread.Post(async () => await StartAsync(desktop, splash), DispatcherPriority.Background);
        }
        base.OnFrameworkInitializationCompleted();
    }

    private static async Task StartAsync(IClassicDesktopStyleApplicationLifetime desktop, SplashWindow splash)
    {
        var started = DateTime.UtcNow;
        try
        {
            var services = BuildServices(new BlazmaPaths());
            Services = services;
            var settings = services.GetRequiredService<SettingsService>();
            Loc.Instance.SetLanguage(settings.Current.General.Language);
            services.GetRequiredService<ThemeService>().Apply(settings.Current.Appearance);
            await services.GetRequiredService<IAnalysisRepository>().InitializeAsync(CancellationToken.None);

            var main = services.GetRequiredService<MainViewModel>();
            Dispatcher.UIThread.UnhandledException += (_, e) =>
            {
                LogFatal(e.Exception, "UI thread");
                e.Handled = true;
                _ = main.Dialogs.ErrorAsync(Loc.T("UnexpectedTitle"), e.Exception.Message, e.Exception.GetType().FullName, canRetry: false);
            };

            // A brief splash only: it stays exactly as long as initialisation takes, plus a short minimum.
            var elapsed = DateTime.UtcNow - started;
            if (elapsed < TimeSpan.FromMilliseconds(500)) await Task.Delay(TimeSpan.FromMilliseconds(500) - elapsed);

            var window = new MainWindow { DataContext = main };
            desktop.MainWindow = window;
            desktop.ShutdownRequested += async (_, _) => await settings.SaveNowAsync();
            window.Show();
            splash.Close();
            await main.InitializeAsync();

            // Keep the Explorer entry pointing at this copy of Blazma (it may have been moved or updated).
            if (settings.Current.General.ExplorerContextMenu) ShellIntegration.Apply(true, Loc.T("ExplorerMenuText"));
            if (ShellIntegration.StartupFile(desktop.Args ?? []) is { } file) await main.PrepareFileAsync(file);

            // Files sent by a second launch (Explorer menu, drag onto the exe) open here.
            Instance?.Listen(file => Dispatcher.UIThread.Post(async () =>
            {
                if (window.WindowState == WindowState.Minimized) window.WindowState = WindowState.Normal;
                window.Activate();
                if (file is not null) await main.PrepareFileAsync(file);
            }));
        }
        catch (Exception ex)
        {
            LogFatal(ex, "Startup");
            splash.ShowError(ex.Message);
        }
    }

    /// <summary>
    /// Records an exception nothing else handled. Besides the structured log, the full exception
    /// (type, message, stack and every inner exception) goes synchronously to its own
    /// <c>crash-*.txt</c> next to the logs, so a crash that ends the process still leaves evidence.
    /// When the process is ending, the log is closed so everything buffered reaches the disk.
    /// </summary>
    internal static void LogFatal(Exception? ex, string source, bool terminating = false)
    {
        if (ex is null) return;
        try { _log?.Fatal(ex, "Unhandled exception ({Source}, terminating: {Terminating})", source, terminating); }
        catch (Exception) { /* logging must never add a second failure */ }
        WriteCrashFile(ex, source, terminating);
        if (terminating)
        {
            try { _log?.Dispose(); }
            catch (Exception) { /* the process is ending anyway */ }
        }
    }

    /// <summary>A failed background task that nothing awaited: logged, never fatal.</summary>
    internal static void LogUnobserved(Exception? ex)
    {
        if (ex is null) return;
        try { _log?.Error(ex, "Unobserved background task failure"); }
        catch (Exception) { /* logging must never add a second failure */ }
    }

    internal static string? WriteCrashFile(Exception ex, string source, bool terminating, string? folder = null)
    {
        try
        {
            folder ??= _logsFolder ?? new BlazmaPaths().Logs;
            Directory.CreateDirectory(folder);
            var now = DateTimeOffset.Now;
            var path = Path.Combine(folder, $"crash-{now:yyyyMMdd-HHmmss-fff}-{Environment.ProcessId}.txt");
            var text = string.Join(Environment.NewLine,
                $"Blazma Sandbox {typeof(App).Assembly.GetName().Version?.ToString(3)}",
                $"Time: {now:O}",
                $"Source: {source}{(terminating ? " (process terminating)" : string.Empty)}",
                $"OS: {Environment.OSVersion.VersionString} ({System.Runtime.InteropServices.RuntimeInformation.OSArchitecture})",
                $".NET: {Environment.Version}",
                string.Empty,
                ex.ToString(),
                string.Empty);
            using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
            using (var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false)))
            {
                writer.Write(text);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }
            return path;
        }
        catch (Exception)
        {
            return null; // nowhere left to report to
        }
    }
}

/// <summary>Finds the view for a view model by name: FooViewModel → FooView.</summary>
public sealed class ViewLocator : IDataTemplate
{
    public Control? Build(object? data)
    {
        if (data is null) return null;
        var name = data.GetType().FullName!.Replace("ViewModels", "Views", StringComparison.Ordinal).Replace("ViewModel", "View", StringComparison.Ordinal);
        var type = Type.GetType(name);
        return type is null ? new TextBlock { Text = "Missing view: " + name } : (Control)Activator.CreateInstance(type)!;
    }

    public bool Match(object? data) => data is PageViewModel;
}
