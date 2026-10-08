using System.Diagnostics;
using System.Text.Json;
using System.Threading.Channels;
using Blazma.Analysis.Engine;
using Blazma.Analysis.Pipeline;
using Blazma.Analysis.Rules;
using Blazma.Analysis.Static;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Samples;
using Blazma.Sandbox.Providers.Demo;
using Blazma.Sandbox.Providers.WindowsSandbox;
using Blazma.Storage;
using Microsoft.Extensions.Logging;

namespace Blazma.App.Services;

/// <summary>A running analysis, observed by the Live screen.</summary>
public sealed class ActiveAnalysis
{
    public required string FileName { get; init; }
    public required Channel<AnalysisEvent> Events { get; init; }
    public required Task<AnalysisResult> Completion { get; init; }
    public required CancellationTokenSource Cancellation { get; init; }
    public required bool IsDemo { get; init; }
    public event EventHandler<AnalysisProgress>? Progress;
    internal void Raise(AnalysisProgress p) => Progress?.Invoke(this, p);
    public AnalysisProgress? Last { get; internal set; }
}

/// <summary>
/// Application-level orchestration: static analysis in an isolated helper process,
/// provider selection, the analysis runner, and rule loading.
/// </summary>
public sealed class AnalysisCoordinator(
    SettingsService settings,
    IAnalysisRepository repository,
    BlazmaPaths paths,
    ILoggerFactory loggers)
{
    public ActiveAnalysis? Active { get; private set; }
    public IReadOnlyList<string> RulePackErrors { get; private set; } = [];

    public event EventHandler? ActiveChanged;

    public static string StaticWorkerFlag => "--static-worker";

    /// <summary>The rule engine with built-in rules plus the user's rule packs (if enabled).</summary>
    public RuleEngine BuildRuleEngine()
    {
        var rules = RuleEngine.BuiltInRules().ToList();
        if (settings.Current.Detection.EnableCustomRulePacks)
        {
            var (custom, errors) = RuleEngine.LoadRulePacks(paths.Rules);
            rules.AddRange(custom);
            RulePackErrors = errors;
        }
        else RulePackErrors = [];
        return new RuleEngine(rules, loggers.CreateLogger<RuleEngine>());
    }

    public ISandboxProvider Provider(string? id = null) => (id ?? settings.Current.Analysis.ProviderId) switch
    {
        DemoSandboxProvider.ProviderId => new DemoSandboxProvider(TimeProvider.System, settings.Current.Advanced.DemoSpeed),
        _ => new WindowsSandboxProvider(new WindowsSandboxOptions
        {
            WorkRoot = paths.Work,
            AgentFolder = Path.Combine(AppContext.BaseDirectory, "agent"),
            MemoryMb = settings.Current.Advanced.SandboxMemoryMb,
            OutboxQuotaBytes = settings.Current.Advanced.OutboxQuotaBytes,
            HeartbeatTimeout = TimeSpan.FromSeconds(settings.Current.Advanced.AgentHeartbeatTimeoutSeconds),
            StopWhenTreeExits = settings.Current.Analysis.StopWhenTreeExits,
        }, loggers),
    };

    /// <summary>
    /// Runs static analysis in a separate copy of this executable so a parser bug triggered
    /// by a hostile file cannot reach the UI process. Never executes the sample.
    /// </summary>
    public async Task<StaticReport> AnalyzeStaticAsync(string path, CancellationToken ct)
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot locate the Blazma executable.");
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        if (Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            psi.ArgumentList.Add(typeof(AnalysisCoordinator).Assembly.Location);
        psi.ArgumentList.Add(StaticWorkerFlag);
        psi.ArgumentList.Add(path);

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("The static analysis helper did not start.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(90));
        try
        {
            var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token);
            if (process.ExitCode != 0) throw new InvalidOperationException((await stderr).Trim());
            return JsonSerializer.Deserialize<StaticReport>(await stdout, BlazmaJson.Options) ?? throw new InvalidDataException("Empty static report.");
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            throw;
        }
    }

    /// <summary>Entry point used by the helper process (see Program.Main).</summary>
    public static async Task<int> RunStaticWorkerAsync(string path)
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(80));
            var report = await new StaticAnalyzer().AnalyzeAsync(path, cts.Token);
            await using var stdout = Console.OpenStandardOutput();
            await JsonSerializer.SerializeAsync(stdout, report, BlazmaJson.Options, cts.Token);
            return 0;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync(ex.Message);
            return 1;
        }
    }

    /// <summary>A synthetic sample for the demo analysis (nothing is read from disk or run).</summary>
    public static StaticReport DemoSample(string fileName = "setup.exe") => new()
    {
        Sample = new SampleInfo
        {
            FileName = fileName,
            Size = 15_413_248,
            Sha256 = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("blazma-demo:" + fileName))),
            Sha1 = Convert.ToHexStringLower(System.Security.Cryptography.SHA1.HashData(System.Text.Encoding.UTF8.GetBytes("blazma-demo:" + fileName))),
            Kind = FileKind.Executable,
        },
        Pe = new PeInfo
        {
            Machine = "x64",
            Is64Bit = true,
            IsDll = false,
            Subsystem = "Windows GUI",
            IsDotNet = false,
            CompileTimestamp = new DateTimeOffset(2026, 9, 14, 8, 21, 0, TimeSpan.Zero),
            Sections =
            [
                new PeSection(".text", 1_204_224, 1_204_736, 6.42, true, false),
                new PeSection(".rdata", 402_112, 402_432, 5.11, false, false),
                new PeSection(".data", 28_160, 9_216, 2.88, false, true),
                new PeSection(".rsrc", 13_651_000, 13_651_456, 7.94, false, false),
            ],
            Imports = [new PeImport("KERNEL32.dll", ["CreateFileW", "WriteFile", "CreateProcessW"]), new PeImport("ADVAPI32.dll", ["RegSetValueExW"]), new PeImport("WININET.dll", ["InternetOpenW"])],
            VersionInfo = new Dictionary<string, string> { ["CompanyName"] = "Contoso Update (demo)", ["FileDescription"] = "Setup", ["FileVersion"] = "1.3.0" },
            ResourceCount = 14,
            HasOverlay = true,
        },
        Signature = new SignatureInfo(SignatureStatus.NotSigned),
        Entropy = 7.61,
        Warnings = ["Demo sample: these values are synthetic."],
    };

    public ActiveAnalysis Start(string samplePath, StaticReport report, AnalysisOptions options, ISandboxProvider provider)
    {
        if (Active is { Completion.IsCompleted: false }) throw new InvalidOperationException("An analysis is already running.");
        var engine = new AnalysisEngine(BuildRuleEngine());
        var runner = new AnalysisRunner(engine, repository, TimeProvider.System, loggers.CreateLogger<AnalysisRunner>());
        var channel = Channel.CreateUnbounded<AnalysisEvent>(new UnboundedChannelOptions { SingleReader = true });
        var cts = new CancellationTokenSource();
        ActiveAnalysis? active = null;
        var progress = new Progress<AnalysisProgress>(p => { if (active is not null) { active.Last = p; active.Raise(p); } });
        var request = new AnalysisRequest
        {
            SamplePath = samplePath,
            Static = report,
            Options = options,
            EngineSettings = EngineSettings.From(settings.Current.Detection),
            MaxEvents = settings.Current.Storage.MaxEventsPerAnalysis,
        };
        var task = Task.Run(() => runner.RunAsync(request, provider, progress, channel.Writer, cts.Token));
        active = new ActiveAnalysis { FileName = report.Sample.FileName, Events = channel, Completion = task, Cancellation = cts, IsDemo = provider.IsDemo };
        Active = active;
        ActiveChanged?.Invoke(this, EventArgs.Empty);
        return active;
    }
}
