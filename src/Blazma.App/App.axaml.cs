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
using Blazma.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Formatting.Compact;

namespace Blazma.App;

public partial class App : Application
{
    private static Serilog.Core.Logger? _log;

    public static IServiceProvider? Services { get; private set; }

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    /// <summary>Configures services. Exposed so the screenshot tool and tests can build the same graph.</summary>
    public static ServiceProvider BuildServices(BlazmaPaths paths)
    {
        paths.EnsureCreated();
        var store = new SettingsStore(paths);
        var settings = store.Load();
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
        services.AddSingleton<IAnalysisRepository>(sp => new SqliteAnalysisRepository(paths.Database, sp.GetRequiredService<ILogger<SqliteAnalysisRepository>>()));
        services.AddSingleton<AnalysisCoordinator>();
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
                LogFatal(e.Exception);
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
        }
        catch (Exception ex)
        {
            LogFatal(ex);
            splash.ShowError(ex.Message);
        }
    }

    internal static void LogFatal(Exception? ex)
    {
        if (ex is null) return;
        _log?.Fatal(ex, "Unhandled exception");
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
