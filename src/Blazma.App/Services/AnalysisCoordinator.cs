using System.Threading.Channels;
using Avalonia.Threading;
using Blazma.Analysis.Engine;
using Blazma.Analysis.Pipeline;
using Blazma.Analysis.Rules;
using Blazma.Analysis.Static;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Samples;
using Blazma.Sandbox.Providers;
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

    /// <summary>Extend or finish the run while it is analyzing (when the provider supports it).</summary>
    public required AnalysisControl Control { get; init; }

    /// <summary>Raised on the UI thread with the newest progress (intermediate updates may be skipped).</summary>
    public event EventHandler<AnalysisProgress>? Progress;
    internal void Raise(AnalysisProgress p) => Progress?.Invoke(this, p);
    public AnalysisProgress? Last { get; internal set; }
}

/// <summary>
/// Hands progress to the UI thread keeping only the newest value. The runner reports after every
/// signal from the sandbox (thousands a second in a busy run); posting each one would flood the
/// dispatcher and freeze the window, so at most one delivery is queued at a time and the latest
/// value (including the final stage) is always the one delivered.
/// </summary>
internal sealed class LatestProgress<T>(Action<T> deliver, Action<Action> post) : IProgress<T> where T : class
{
    private T? _latest;
    private int _queued;

    public void Report(T value)
    {
        Volatile.Write(ref _latest, value);
        if (Interlocked.Exchange(ref _queued, 1) == 0) post(Deliver);
    }

    private void Deliver()
    {
        Volatile.Write(ref _queued, 0);
        if (Interlocked.Exchange(ref _latest, null) is { } value) deliver(value);
    }
}

/// <summary>
/// Application-level orchestration: static analysis in an isolated helper process,
/// provider selection, the analysis runner, and rule loading.
/// </summary>
public sealed class AnalysisCoordinator(
    SettingsService settings,
    IAnalysisRepository repository,
    BlazmaPaths paths,
    ILoggerFactory loggers,
    ISecretProtector secrets)
{
    private readonly ILogger _logger = loggers.CreateLogger<AnalysisCoordinator>();

    public ActiveAnalysis? Active { get; private set; }
    public IReadOnlyList<string> RulePackErrors { get; private set; } = [];

    public event EventHandler? ActiveChanged;

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

    public ISandboxProvider Provider(string? id = null) =>
        SandboxProviders.Create(id, settings.Current, paths.Work, SandboxProviders.DefaultAgentFolder, secrets, loggers);

    /// <summary>The helper options that follow the user's detection settings.</summary>
    public StaticWorkerOptions StaticOptions(string? archivePassword = null) => new(
        settings.Current.Detection.EnableCapabilities,
        settings.Current.Detection.EnableYara ? paths.Yara : null,
        archivePassword ?? settings.Current.Analysis.DefaultArchivePassword);

    /// <summary>
    /// Runs static analysis in a separate copy of this executable so a parser bug triggered
    /// by a hostile file cannot reach the UI process. Never executes the sample.
    /// </summary>
    public Task<StaticReport> AnalyzeStaticAsync(string path, CancellationToken ct, string? archivePassword = null) =>
        StaticWorker.AnalyzeAsync(path, StaticOptions(archivePassword), BlazmaJson.Options, "BlazmaSandbox.dll", ct);

    /// <summary>Extracts one archive entry in the helper process into a fresh folder under the work folder.</summary>
    public Task<string> ExtractArchiveEntryAsync(string archivePath, string entryPath, string? password, CancellationToken ct) =>
        StaticWorker.ExtractAsync(archivePath, entryPath, password, Path.Combine(paths.Work, "extracted", Guid.NewGuid().ToString("N")), "BlazmaSandbox.dll", ct);

    /// <summary>A URL sample is a small text file holding the address; its hashes are of that text.</summary>
    public async Task<string> WriteUrlSampleAsync(string url, CancellationToken ct)
    {
        var folder = Path.Combine(paths.Work, "urls");
        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, Guid.NewGuid().ToString("N") + ".url.txt");
        await File.WriteAllTextAsync(path, url, new System.Text.UTF8Encoding(false), ct);
        return path;
    }

    /// <summary>A synthetic sample for the demo analysis (nothing is read from disk or run).</summary>
    public static StaticReport DemoSample(string fileName = "setup.exe") => new()
    {
        Sample = new SampleInfo
        {
            FileName = fileName,
            Size = 15_413_248,
            Sha256 = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("blazma-demo:" + fileName))),
#pragma warning disable CA5350 // SHA-1 is reported as an identifier, the same as real samples; it is never used for security
            Sha1 = Convert.ToHexStringLower(System.Security.Cryptography.SHA1.HashData(System.Text.Encoding.UTF8.GetBytes("blazma-demo:" + fileName))),
#pragma warning restore CA5350
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
        ImpHash = "c3d1a2b9e8f70a65d4b3c2e1f0a9b8c7",
        Capabilities = DemoCapabilities(),
        Artifacts =
        [
            new ExtractedArtifact(ArtifactKind.Url, "https://updates.contoso-cdn.example/check", fileName),
            new ExtractedArtifact(ArtifactKind.Domain, "updates.contoso-cdn.example", fileName),
            new ExtractedArtifact(ArtifactKind.UserAgent, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ContosoUpdater/2.1", fileName),
            new ExtractedArtifact(ArtifactKind.MutexName, "Global\\ContosoUpdaterSingleton", fileName),
        ],
    };

    /// <summary>Real catalog entries with synthetic evidence, so the demo shows the Code tab.</summary>
    private static IReadOnlyList<Capability> DemoCapabilities()
    {
        var evidence = new Dictionary<string, string[]>
        {
            ["CAP-PER-001"] = ["import: advapi32!RegSetValueExW", "string: Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
            ["CAP-PER-004"] = ["string: schtasks /create"],
            ["CAP-EXE-004"] = ["import: urlmon!URLDownloadToFileW", "import: shell32!ShellExecuteW"],
            ["CAP-INJ-001"] = ["import: kernel32!VirtualAllocEx", "import: kernel32!WriteProcessMemory", "import: kernel32!CreateRemoteThread"],
            ["CAP-ANA-001"] = ["import: kernel32!IsDebuggerPresent"],
        };
        return CapabilityDetector.Catalog.Where(c => evidence.ContainsKey(c.Id)).Select(c => c with { Evidence = evidence[c.Id] }).ToList();
    }

    public ActiveAnalysis Start(string samplePath, StaticReport report, AnalysisOptions options, ISandboxProvider provider, IReadOnlyList<ReputationResult>? reputation = null)
    {
        if (Active is { Completion.IsCompleted: false }) throw new InvalidOperationException("An analysis is already running.");
        var engine = new AnalysisEngine(BuildRuleEngine());
        var runner = new AnalysisRunner(engine, repository, TimeProvider.System, loggers.CreateLogger<AnalysisRunner>());
        var channel = Channel.CreateUnbounded<AnalysisEvent>(new UnboundedChannelOptions { SingleReader = true });
        var cts = new CancellationTokenSource();
        ActiveAnalysis? active = null;
        var progress = new LatestProgress<AnalysisProgress>(p => { if (active is not null) { active.Last = p; active.Raise(p); } },
            deliver => Dispatcher.UIThread.Post(deliver, DispatcherPriority.Background));
        var request = new AnalysisRequest
        {
            SamplePath = samplePath,
            Static = report,
            Options = options,
            EngineSettings = EngineSettings.From(settings.Current.Detection),
            MaxEvents = settings.Current.Storage.MaxEventsPerAnalysis,
            ArtifactsRoot = paths.Artifacts,
            Inspector = new StaticWorkerInspector(this),
            Reputation = reputation ?? [],
            Control = new AnalysisControl(),
        };
        _logger.LogInformation("Starting analysis of {FileName} (SHA-256 {Sha256}) with provider {Provider}: profile {Profile}, duration {Duration}, network {Network}",
            report.Sample.FileName, report.Sample.Sha256, provider.Id, options.ProfileId, options.Duration, options.Network);
        var task = Task.Run(() => RunAndLogAsync(runner, request, provider, progress, channel.Writer, cts.Token));
        active = new ActiveAnalysis { FileName = report.Sample.FileName, Events = channel, Completion = task, Cancellation = cts, IsDemo = provider.IsDemo, Control = request.Control };
        Active = active;
        ActiveChanged?.Invoke(this, EventArgs.Empty);
        return active;
    }

    /// <summary>The outcome of every run goes to the log, so a log file tells the whole story (the runner logs each stage change).</summary>
    private async Task<AnalysisResult> RunAndLogAsync(AnalysisRunner runner, AnalysisRequest request, ISandboxProvider provider,
        IProgress<AnalysisProgress> progress, ChannelWriter<AnalysisEvent> events, CancellationToken ct)
    {
        var file = request.Static.Sample.FileName;
        try
        {
            var result = await runner.RunAsync(request, provider, progress, events, ct).ConfigureAwait(false);
            _logger.LogInformation("Analysis {AnalysisId} of {FileName} completed: score {Score}, verdict {Verdict}, {EventCount} events, monitoring interrupted: {Interrupted}",
                result.AnalysisId, file, result.Risk.Score, result.Risk.Verdict, result.Events.Count, result.MonitoringInterrupted);
            return result;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            _logger.LogInformation("Analysis of {FileName} was cancelled by the user", file);
            throw;
        }
        catch (AnalysisFailedException ex)
        {
            _logger.LogError(ex, "Analysis of {FileName} failed: {Reason}", file, ex.Reason);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Analysis of {FileName} failed unexpectedly: {Reason}", file, ex.Message);
            throw;
        }
    }

    /// <summary>Dropped files and memory dumps are as hostile as the sample: they get the same out-of-process static analysis.</summary>
    private sealed class StaticWorkerInspector(AnalysisCoordinator owner) : IArtifactInspector
    {
        public async Task<StaticReport?> InspectAsync(string path, string displayName, CancellationToken cancellationToken)
        {
            try
            {
                return await owner.AnalyzeStaticAsync(path, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // The helper's own time limit, not the user: one slow artifact must not fail the whole analysis.
                owner._logger.LogWarning("Static analysis of the artifact {Name} timed out; it is kept without analysis", displayName);
                return null;
            }
        }
    }
}
