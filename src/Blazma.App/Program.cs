using Avalonia;
using Blazma.App.Services;

namespace Blazma.App;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        // The same executable doubles as the isolated static-analysis helper, so a parser
        // problem caused by a hostile file stays in a short-lived separate process.
        if (args.Length == 2 && args[0] == AnalysisCoordinator.StaticWorkerFlag)
            return AnalysisCoordinator.RunStaticWorkerAsync(args[1]).GetAwaiter().GetResult();

        AppDomain.CurrentDomain.UnhandledException += (_, e) => App.LogFatal(e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) => { App.LogFatal(e.Exception); e.SetObserved(); };
        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();
}
