using Avalonia;
using Avalonia.Headless;
using Avalonia.Threading;
using Blazma.App;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.App.ViewModels;
using Blazma.App.Views;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Settings;
using Blazma.Sandbox.Providers.Demo;
using Blazma.Storage;
using Microsoft.Extensions.DependencyInjection;

var output = args.Length > 0 ? args[0] : "screenshots";
var language = args.Length > 1 && args[1] == "ar" ? AppLanguage.Arabic : AppLanguage.English;
var only = args.Length > 2 ? args[2] : null;
var theme = args.Length > 3 ? Enum.Parse<ThemeVariant>(args[3]) : ThemeVariant.Dark;
Directory.CreateDirectory(output);

AppBuilder.Configure<App>()
    .UseSkia()
    .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
    .SetupWithoutStarting();

var dataRoot = Directory.CreateTempSubdirectory("blazma-shots");
var services = App.BuildServices(new BlazmaPaths(dataRoot.FullName));
var settings = services.GetRequiredService<SettingsService>();
settings.Current.General.OnboardingCompleted = true;
settings.Current.General.Language = language;
settings.Current.Appearance.Theme = theme;
settings.Current.Advanced.DemoSpeed = 0;
Loc.Instance.SetLanguage(language);
services.GetRequiredService<ThemeService>().Apply(settings.Current.Appearance);
var repo = services.GetRequiredService<IAnalysisRepository>();
Run(repo.InitializeAsync(CancellationToken.None));

// Realistic history: a few demo analyses through the real pipeline.
var coordinator = services.GetRequiredService<AnalysisCoordinator>();
Guid main = Guid.Empty;
foreach (var name in new[] { "viewer-tool.exe", "contoso-tool-1.2.exe", "setup.exe" })
{
    var active = coordinator.Start(name, AnalysisCoordinator.DemoSample(name), new AnalysisOptions(), new DemoSandboxProvider(TimeProvider.System, 0));
    while (active.Events.Reader.TryRead(out _)) { }
    main = Pump(active.Completion).AnalysisId;
}

// An example YARA rule so the Intelligence page and the report show real matches.
var paths = services.GetRequiredService<BlazmaPaths>();
Directory.CreateDirectory(paths.Yara);
File.WriteAllText(Path.Combine(paths.Yara, "example.yar"), IntelligenceViewModel.ExampleYara);

var vm = services.GetRequiredService<MainViewModel>();
var window = new MainWindow { DataContext = vm, Width = 1440, Height = 900 };
window.Show();
Run(vm.InitializeAsync());

void Shot(string name, Func<Task>? setup = null)
{
    if (only is not null && !name.Contains(only, StringComparison.OrdinalIgnoreCase)) return;
    if (setup is not null) Run(setup());
    for (var i = 0; i < 12; i++) { Dispatcher.UIThread.RunJobs(); AvaloniaHeadlessPlatform.ForceRenderTimerTick(); Thread.Sleep(30); }
    var frame = window.CaptureRenderedFrame();
    var file = Path.Combine(output, $"{name}-{(language == AppLanguage.Arabic ? "ar" : "en")}.png");
    #pragma warning disable CS0618
    frame?.Save(file);
#pragma warning restore CS0618
    Console.WriteLine(file);
}

Shot("01-dashboard", () => { vm.Navigate("Dashboard"); return Task.CompletedTask; });
Shot("02-new-analysis", () => vm.PrepareDemoAsync());
Shot("03-report-overview", () => vm.OpenReportAsync(main, 0));
Shot("04-report-timeline", () => vm.OpenReportAsync(main, 1));
Shot("05-report-processes", () => vm.OpenReportAsync(main, 2));
Shot("06-report-network", () => vm.OpenReportAsync(main, 5));
Shot("07-report-persistence", () => vm.OpenReportAsync(main, 6));
Shot("08-report-changes", () => vm.OpenReportAsync(main, 8));
Shot("09-report-ask", async () =>
{
    await vm.OpenReportAsync(main, 10);
    var report = vm.Page<ReportViewModel>();
    report.AskCommand.Execute(language == AppLanguage.Arabic ? "لماذا الدرجة مرتفعة؟" : "Why is the score high?");
});
Shot("10-finding-panel", async () =>
{
    await vm.OpenReportAsync(main, 0);
    var report = vm.Page<ReportViewModel>();
    report.SelectedFinding = report.Findings.FirstOrDefault();
});
Shot("11-history", () => { vm.Navigate("History"); return Task.CompletedTask; });
Shot("12-compare", () => { vm.OpenCompare(main); return Task.CompletedTask; });
Shot("13-intelligence", () => { vm.Navigate("Intelligence"); return Task.CompletedTask; });
Shot("14-security-center", () => { vm.Navigate("Sandbox"); return Task.CompletedTask; });
Shot("15-settings-appearance", () =>
{
    vm.Navigate("Settings");
    var s = vm.Page<SettingsViewModel>();
    s.SelectedSection = s.Sections.First(x => x.Key == "Appearance");
    return Task.CompletedTask;
});
Shot("16-settings-detection", () =>
{
    var s = vm.Page<SettingsViewModel>();
    s.SelectedSection = s.Sections.First(x => x.Key == "Detection");
    return Task.CompletedTask;
});
Shot("20-report-screenshots", () => vm.OpenReportAsync(main, 11));
Shot("21-report-artifacts", () => vm.OpenReportAsync(main, 12));
Shot("22-report-code", () => vm.OpenReportAsync(main, 13));
Shot("23-report-attack", () => vm.OpenReportAsync(main, 14));
Shot("24-settings-integrations", () =>
{
    vm.Navigate("Settings");
    var s = vm.Page<SettingsViewModel>();
    s.SelectedSection = s.Sections.First(x => x.Key == "Integrations");
    return Task.CompletedTask;
});
Shot("25-settings-ai", () =>
{
    var s = vm.Page<SettingsViewModel>();
    s.SelectedSection = s.Sections.First(x => x.Key == "AI");
    return Task.CompletedTask;
});

Shot("17-palette", () => { vm.Navigate("Dashboard"); vm.Palette.Open(); return Task.CompletedTask; });
Shot("18-onboarding", () => { vm.Palette.Close(); vm.ShowOnboarding(); return Task.CompletedTask; });
Shot("19-live", async () =>
{
    vm.Onboarding.IsOpen = false;
    settings.Current.Advanced.DemoSpeed = 1;
    var active = coordinator.Start("setup.exe", AnalysisCoordinator.DemoSample(), new AnalysisOptions(), new DemoSandboxProvider(TimeProvider.System, 1));
    var live = vm.Page<LiveAnalysisViewModel>();
    live.Attach(active);
    vm.CurrentPage = live;
    var until = DateTime.UtcNow.AddSeconds(5);
    while (DateTime.UtcNow < until) { Dispatcher.UIThread.RunJobs(); Thread.Sleep(20); }
    await Task.CompletedTask;
});

window.Close();
return 0;

static T Pump<T>(Task<T> task)
{
    while (!task.IsCompleted) { Dispatcher.UIThread.RunJobs(); Thread.Sleep(5); }
    return task.GetAwaiter().GetResult();
}

static void Run(Task task)
{
    while (!task.IsCompleted) { Dispatcher.UIThread.RunJobs(); Thread.Sleep(5); }
    task.GetAwaiter().GetResult();
}
