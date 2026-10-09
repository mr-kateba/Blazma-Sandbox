using Avalonia;
using Blazma.Analysis.Static;
using Blazma.Storage;

namespace Blazma.App;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        // The same executable doubles as the isolated static-analysis helper, so a parser
        // problem caused by a hostile file stays in a short-lived separate process.
        if (StaticWorker.IsWorkerInvocation(args))
            return StaticWorker.RunAsync(args, BlazmaJson.Options).GetAwaiter().GetResult();

        AppDomain.CurrentDomain.UnhandledException += (_, e) => App.LogFatal(e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) => { App.LogFatal(e.Exception); e.SetObserved(); };
        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();
}
