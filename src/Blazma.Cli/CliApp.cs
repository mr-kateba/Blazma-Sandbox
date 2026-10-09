using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Blazma.Analysis.Engine;
using Blazma.Analysis.Pipeline;
using Blazma.Analysis.Rules;
using Blazma.Analysis.Static;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Findings;
using Blazma.Core.Samples;
using Blazma.Core.Settings;
using Blazma.Intelligence;
using Blazma.Intelligence.Net;
using Blazma.Intelligence.Reputation;
using Blazma.Reporting;
using Blazma.Reporting.Interop;
using Blazma.Sandbox.Providers;
using Blazma.Storage;
using Blazma.Storage.Secrets;

namespace Blazma.Cli;

/// <summary>
/// The "blazma" command line. Output goes to the given writers so the commands can be tested;
/// results are saved to the same history as the desktop app.
/// </summary>
public sealed class CliApp(TextWriter stdout, TextWriter stderr)
{
    /// <summary>Static analysis; replaced in tests (the default starts an isolated helper process).</summary>
    internal Func<string, StaticWorkerOptions, CancellationToken, Task<StaticReport>> AnalyzeStatic { get; init; } =
        (path, options, ct) => StaticWorker.AnalyzeAsync(path, options, BlazmaJson.Options, "blazma.dll", ct);

    /// <summary>Hook for tests to replace the analysis environment.</summary>
    internal Func<string?, BlazmaSettings, BlazmaPaths, ISandboxProvider>? ProviderFactory { get; init; }

    private static readonly JsonSerializerOptions PrettyJson = new(BlazmaJson.Options) { WriteIndented = true };

    public async Task<int> RunAsync(IReadOnlyList<string> args, CancellationToken cancellationToken)
    {
        var (command, error) = CommandLine.Parse(args);
        if (command is null)
        {
            await stderr.WriteLineAsync(error);
            await stderr.WriteLineAsync("Run \"blazma help\" for usage.");
            return ExitCodes.Usage;
        }
        if (command.Flag("help")) return await HelpAsync();
        try
        {
            return command.Verb switch
            {
                "help" => await HelpAsync(),
                "version" => await VersionAsync(),
                "static" => await StaticAsync(command, cancellationToken),
                "analyze" => await AnalyzeAsync(command, cancellationToken),
                "batch" => await BatchAsync(command, cancellationToken),
                "list" => await ListAsync(command, cancellationToken),
                "export" => await ExportAsync(command, cancellationToken),
                "envs" => await EnvironmentsAsync(command, cancellationToken),
                _ => await UsageErrorAsync($"Unknown command \"{command.Verb}\"."),
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await stderr.WriteLineAsync("Cancelled.");
            return ExitCodes.Cancelled;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or InvalidDataException)
        {
            await stderr.WriteLineAsync("Error: " + ex.Message);
            return ExitCodes.Error;
        }
    }

    // ---- help ------------------------------------------------------------------------------

    internal const string HelpText = """
        Blazma Sandbox - behavior analysis of Windows files in an isolated environment.

        Usage:
          blazma static  <file> [--json]
              Hashes, type, PE details, imphash, capabilities and YARA matches. Never runs the file.
          blazma analyze <file> [options]
              Runs the file in the analysis environment and prints the verdict.
          blazma batch   <folder> [options] [--recursive] [--summary results.csv]
              Analyzes every file in a folder, one after another.
          blazma list    [--limit 20] [--json]
              Recent analyses from the history (shared with the desktop app).
          blazma export  <analysis-id> --format html|json|stix|misp|sigma|yara --out <path>
              Writes a saved analysis in another format. The id can be shortened.
          blazma envs    [--json]
              Which analysis environments are ready on this computer.

        Analysis options:
          --env windows-sandbox|virtualbox|hyperv|demo   (default: from settings)
          --profile quick|standard|deep|interactive      (default: standard)
          --network simulated|offline|internet           (default: simulated)
          --allow-internet      required with --network internet; the sample can reach real servers
          --duration <seconds>  override the profile's run time (15-1800)
          --report <path>       also write a report (.html or .json by extension)
          --lookup              hash-only reputation lookup with the services enabled in settings
          --pcap                record the sandbox's network traffic (pcapng)
          --no-screenshots      do not capture the sandbox screen
          --lang en|ar          language of findings in the output (default: en)
          --json                machine-readable output on stdout
          --data <folder>       use another data folder (default: the app's)

        Exit codes:
          0 low risk / done   10 suspicious   20 high-risk behavior   30 critical behavior
          1 error   2 usage   3 environment not ready   4 cancelled
          A score is evidence for a person to review, not proof that a file is malicious.
        """;

    private async Task<int> HelpAsync()
    {
        await stdout.WriteLineAsync(HelpText);
        return ExitCodes.Ok;
    }

    private async Task<int> VersionAsync()
    {
        var version = typeof(CliApp).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";
        var plus = version.IndexOf('+');
        await stdout.WriteLineAsync("Blazma Sandbox " + (plus > 0 ? version[..plus] : version));
        return ExitCodes.Ok;
    }

    private async Task<int> UsageErrorAsync(string message)
    {
        await stderr.WriteLineAsync(message);
        await stderr.WriteLineAsync("Run \"blazma help\" for usage.");
        return ExitCodes.Usage;
    }

    // ---- context ---------------------------------------------------------------------------

    private sealed record Context(BlazmaPaths Paths, BlazmaSettings Settings, SqliteAnalysisRepository Repository) : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private static async Task<Context> OpenAsync(CommandLine command, CancellationToken ct)
    {
        var root = command.Option("data") ?? Environment.GetEnvironmentVariable("BLAZMA_DATA");
        var paths = new BlazmaPaths(string.IsNullOrWhiteSpace(root) ? null : Path.GetFullPath(root));
        paths.EnsureCreated();
        using var store = new SettingsStore(paths);
        var settings = store.Load();
        var repository = new SqliteAnalysisRepository(paths.Database) { ArtifactsRoot = paths.Artifacts };
        await repository.InitializeAsync(ct);
        return new Context(paths, settings, repository);
    }

    private static StaticWorkerOptions StaticOptions(Context c) => new(
        c.Settings.Detection.EnableCapabilities,
        c.Settings.Detection.EnableYara ? c.Paths.Yara : null);

    private static string Language(CommandLine command) =>
        (command.Option("lang") ?? "en").StartsWith("ar", StringComparison.OrdinalIgnoreCase) ? "ar" : "en";

    // ---- static ----------------------------------------------------------------------------

    private async Task<int> StaticAsync(CommandLine command, CancellationToken ct)
    {
        if (command.Positionals.Count != 1) return await UsageErrorAsync("static needs exactly one file.");
        var path = Path.GetFullPath(command.Positionals[0]);
        if (!File.Exists(path)) return await UsageErrorAsync("File not found: " + path);
        await using var c = await OpenAsync(command, ct);
        var report = await AnalyzeStatic(path, StaticOptions(c), ct);
        if (command.Flag("json"))
        {
            await stdout.WriteLineAsync(JsonSerializer.Serialize(report, PrettyJson));
            return ExitCodes.Ok;
        }
        await stdout.WriteLineAsync(StaticSummary(report, Language(command)));
        return ExitCodes.Ok;
    }

    internal static string StaticSummary(StaticReport report, string language)
    {
        var sb = new StringBuilder();
        var s = report.Sample;
        sb.AppendLine(CultureInfo.InvariantCulture, $"File      {s.FileName}  ({s.Size:N0} bytes, {s.Kind})");
        sb.AppendLine(CultureInfo.InvariantCulture, $"SHA-256   {s.Sha256}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"SHA-1     {s.Sha1}");
        if (report.ImpHash is { } imp) sb.AppendLine(CultureInfo.InvariantCulture, $"Imphash   {imp}");
        if (report.Pe is { } pe)
            sb.AppendLine(CultureInfo.InvariantCulture, $"PE        {pe.Machine}, {(pe.IsDll ? "DLL" : "EXE")}, {pe.Subsystem}{(pe.IsDotNet ? ", .NET" : "")}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"Signature {report.Signature.Status}{(report.Signature.Publisher is { } p ? " (" + p + ")" : "")}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"Entropy   {report.Entropy:0.00}");
        if (report.Capabilities.Count > 0)
        {
            sb.AppendLine().AppendLine(CultureInfo.InvariantCulture, $"Capabilities ({report.Capabilities.Count})");
            foreach (var cap in report.Capabilities) sb.AppendLine(CultureInfo.InvariantCulture, $"  {cap.Id,-12} {cap.Name.Get(language)}");
        }
        if (report.YaraMatches.Count > 0)
        {
            sb.AppendLine().AppendLine(CultureInfo.InvariantCulture, $"YARA ({report.YaraMatches.Count})");
            foreach (var m in report.YaraMatches) sb.AppendLine(CultureInfo.InvariantCulture, $"  {m.Rule}  [{m.Source}]");
        }
        if (report.Strings.Count > 0)
        {
            sb.AppendLine().AppendLine(CultureInfo.InvariantCulture, $"Interesting strings ({report.Strings.Count})");
            foreach (var str in report.Strings.Take(20)) sb.AppendLine(CultureInfo.InvariantCulture, $"  {str.Kind,-12} {str.Value}");
        }
        foreach (var w in report.Warnings) sb.AppendLine("Warning: " + w);
        return sb.ToString().TrimEnd();
    }

    // ---- analyze / batch -------------------------------------------------------------------

    private sealed record RunPlan(AnalysisOptions Options, string? ProviderId, string? ReportPath, bool Lookup);

    private async Task<(RunPlan? Plan, int Exit)> PlanAsync(CommandLine command, Context c)
    {
        var profileId = command.Option("profile") ?? AnalysisProfile.StandardId;
        var profile = AnalysisProfile.BuiltIns.FirstOrDefault(p => p.Id.Equals(profileId, StringComparison.OrdinalIgnoreCase));
        if (profile is null) return (null, await UsageErrorAsync($"Unknown profile \"{profileId}\"."));
        var options = profile.Options;

        switch ((command.Option("network") ?? "simulated").ToLowerInvariant())
        {
            case "simulated": options = options with { Network = NetworkPolicy.Simulated }; break;
            case "offline" or "disabled" or "none": options = options with { Network = NetworkPolicy.Disabled }; break;
            case "internet" or "enabled" or "real":
                if (!command.Flag("allow-internet"))
                    return (null, await UsageErrorAsync("--network internet lets the sample reach real servers. Add --allow-internet to confirm."));
                options = options with { Network = NetworkPolicy.Enabled };
                break;
            default: return (null, await UsageErrorAsync("--network must be simulated, offline or internet."));
        }
        if (command.Option("duration") is { } d)
        {
            if (!int.TryParse(d, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds) || seconds <= 0)
                return (null, await UsageErrorAsync("--duration must be a number of seconds."));
            options = options with { Duration = TimeSpan.FromSeconds(seconds) };
        }
        if (command.Flag("interactive")) options = options with { Interactive = true };
        if (command.Flag("pcap")) options = options with { CapturePcap = true };
        if (command.Flag("no-screenshots")) options = options with { CaptureScreenshots = false };

        var env = command.Option("env");
        if (env is not null && !SandboxProviders.Ids.Contains(env, StringComparer.OrdinalIgnoreCase))
            return (null, await UsageErrorAsync($"Unknown environment \"{env}\". Use one of: {string.Join(", ", SandboxProviders.Ids)}."));

        var reportPath = command.Option("report");
        if (reportPath is not null && ReportExporterFor(reportPath) is null)
            return (null, await UsageErrorAsync("--report must end in .html or .json."));

        return (new RunPlan(options.Normalized(), env?.ToLowerInvariant(), reportPath, command.Flag("lookup")), ExitCodes.Ok);
    }

    private ISandboxProvider Provider(RunPlan plan, Context c) =>
        ProviderFactory?.Invoke(plan.ProviderId, c.Settings, c.Paths)
        ?? SandboxProviders.Create(plan.ProviderId, c.Settings, c.Paths.Work, SandboxProviders.DefaultAgentFolder, SecretProtector.CreateDefault());

    private async Task<int> AnalyzeAsync(CommandLine command, CancellationToken ct)
    {
        if (command.Positionals.Count != 1) return await UsageErrorAsync("analyze needs exactly one file.");
        var path = Path.GetFullPath(command.Positionals[0]);
        if (!File.Exists(path)) return await UsageErrorAsync("File not found: " + path);
        await using var c = await OpenAsync(command, ct);
        var (plan, exit) = await PlanAsync(command, c);
        if (plan is null) return exit;

        var provider = Provider(plan, c);
        if (!await EnsureReadyAsync(provider, plan.Options.Network, ct)) return ExitCodes.EnvironmentNotReady;

        var result = await RunOneAsync(path, plan, provider, c, command.Flag("json"), ct);
        if (result is null) return ExitCodes.Error;
        if (command.Flag("json"))
            await stdout.WriteLineAsync(JsonSerializer.Serialize(Summary(result, Language(command)), PrettyJson));
        else
            await stdout.WriteLineAsync(ResultSummary(result, Language(command)));
        return OutcomeCode(result);
    }

    private async Task<int> BatchAsync(CommandLine command, CancellationToken ct)
    {
        if (command.Positionals.Count != 1) return await UsageErrorAsync("batch needs exactly one folder.");
        var folder = Path.GetFullPath(command.Positionals[0]);
        if (!Directory.Exists(folder)) return await UsageErrorAsync("Folder not found: " + folder);
        await using var c = await OpenAsync(command, ct);
        var (plan, exit) = await PlanAsync(command, c);
        if (plan is null) return exit;
        if (plan.ReportPath is not null) return await UsageErrorAsync("--report is for one file; use \"blazma export\" after a batch.");

        var files = Directory.EnumerateFiles(folder, "*", command.Flag("recursive") ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (files.Count == 0) return await UsageErrorAsync("The folder has no files.");

        var provider = Provider(plan, c);
        if (!await EnsureReadyAsync(provider, plan.Options.Network, ct)) return ExitCodes.EnvironmentNotReady;

        var language = Language(command);
        var rows = new List<BatchRow>();
        var combined = ExitCodes.Ok;
        for (var i = 0; i < files.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var file = files[i];
            if (!command.Flag("json")) await stderr.WriteLineAsync($"[{i + 1}/{files.Count}] {Path.GetRelativePath(folder, file)}");
            AnalysisResult? result = null;
            string? failure = null;
            try
            {
                result = await RunOneAsync(file, plan, provider, c, quiet: true, ct);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or InvalidDataException)
            {
                failure = ex.Message;
            }
            var code = result is null ? ExitCodes.Error : OutcomeCode(result);
            combined = ExitCodes.Combine(combined, code);
            rows.Add(new BatchRow(Path.GetRelativePath(folder, file), result, failure ?? result?.FailureReason));
            if (!command.Flag("json"))
                await stdout.WriteLineAsync(result is null ? $"  failed: {failure}" : "  " + OneLine(result));
        }

        if (command.Option("summary") is { } csv) await File.WriteAllTextAsync(csv, BatchCsv(rows), ct);
        if (command.Flag("json"))
            await stdout.WriteLineAsync(JsonSerializer.Serialize(rows.Select(r => new
            {
                file = r.File,
                result = r.Result is null ? null : Summary(r.Result, language),
                error = r.Error,
            }), PrettyJson));
        return combined;
    }

    private sealed record BatchRow(string File, AnalysisResult? Result, string? Error);

    internal static string BatchCsv(IEnumerable<(string File, string? Sha256, int? Score, string? Verdict, string? Id, string? Error)> rows)
    {
        var sb = new StringBuilder("file,sha256,score,verdict,analysis_id,error\n");
        foreach (var r in rows)
            sb.Append(Csv(r.File)).Append(',').Append(r.Sha256).Append(',').Append(r.Score?.ToString(CultureInfo.InvariantCulture))
              .Append(',').Append(r.Verdict).Append(',').Append(r.Id).Append(',').Append(Csv(r.Error)).Append('\n');
        return sb.ToString();
    }

    private static string BatchCsv(IEnumerable<BatchRow> rows) => BatchCsv(rows.Select(r => (
        r.File,
        r.Result?.Sample.Sha256,
        r.Result is null ? (int?)null : r.Result.Risk.Score,
        r.Result?.Risk.Verdict.ToString(),
        r.Result?.AnalysisId.ToString("N"),
        r.Error)));

    /// <summary>Quotes a CSV field and neutralizes spreadsheet formulas (a file name is attacker-controlled).</summary>
    internal static string Csv(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        if (value[0] is '=' or '+' or '-' or '@' or '\t' or '\r') value = "'" + value;
        return value.IndexOfAny([',', '"', '\n', '\r']) >= 0 || value.StartsWith('\'') ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
    }

    private async Task<bool> EnsureReadyAsync(ISandboxProvider provider, NetworkPolicy network, CancellationToken ct)
    {
        var availability = await provider.CheckAvailabilityAsync(network, ct);
        if (availability.IsReady) return true;
        await stderr.WriteLineAsync($"The analysis environment \"{provider.DisplayName}\" is not ready ({availability.Readiness}):");
        foreach (var check in availability.Checks.Where(x => !x.Passed))
            await stderr.WriteLineAsync($"  - {check.Label.En}: {check.Detail.En}");
        return false;
    }

    private async Task<AnalysisResult?> RunOneAsync(string path, RunPlan plan, ISandboxProvider provider, Context c, bool quiet, CancellationToken ct)
    {
        var report = await AnalyzeStatic(path, StaticOptions(c), ct);

        IReadOnlyList<ReputationResult> reputation = [];
        if (plan.Lookup)
        {
            var secrets = SecretProtector.CreateDefault();
            using var http = IntegrationHttp.CreateClient();
            var service = new ReputationService(
            [
                new LocalHistoryReputationProvider(c.Repository),
                new VirusTotalReputationProvider(http, () => c.Settings.Integrations, secrets),
                new MalwareBazaarReputationProvider(http, () => c.Settings.Integrations, secrets),
            ]);
            reputation = await service.LookupAsync(report.Sample.Sha256, includeRemote: true, ct);
        }

        var rules = RuleEngine.BuiltInRules().ToList();
        if (c.Settings.Detection.EnableCustomRulePacks)
        {
            var (custom, errors) = RuleEngine.LoadRulePacks(c.Paths.Rules);
            rules.AddRange(custom);
            foreach (var e in errors) await stderr.WriteLineAsync("Rule pack: " + e);
        }
        var runner = new AnalysisRunner(new AnalysisEngine(new RuleEngine(rules)), c.Repository, TimeProvider.System);
        var request = new AnalysisRequest
        {
            SamplePath = path,
            Static = report,
            Options = plan.Options,
            EngineSettings = EngineSettings.From(c.Settings.Detection),
            MaxEvents = c.Settings.Storage.MaxEventsPerAnalysis,
            ArtifactsRoot = c.Paths.Artifacts,
            Inspector = new Inspector(this, StaticOptions(c)),
            Reputation = reputation,
        };

        var lastStage = (AnalysisStage?)null;
        var progress = new SyncProgress(p =>
        {
            if (quiet || p.Stage == lastStage) return;
            lastStage = p.Stage;
            stderr.WriteLine($"  {p.Stage}{(p.Message is { } m ? ": " + m : "")}");
        });

        AnalysisResult result;
        try
        {
            result = await runner.RunAsync(request, provider, progress, null, ct);
        }
        catch (AnalysisFailedException ex)
        {
            await stderr.WriteLineAsync("Analysis failed: " + ex.Reason);
            return null;
        }

        if (plan.ReportPath is { } reportPath)
        {
            var exporter = ReportExporterFor(reportPath)!;
            var r = c.Settings.Reports;
            var options = new ExportOptions("en", c.Settings.Privacy.RedactExports, r.IncludeRawEvents, r.IncludeTimeline, r.IncludeStaticDetails, r.IncludeIndicators, r.TimelineSummaryLimit);
            await using var stream = File.Create(reportPath);
            await exporter.ExportAsync(result, stream, options, ct);
            if (!quiet) await stderr.WriteLineAsync("Report written to " + Path.GetFullPath(reportPath));
        }
        return result;
    }

    private sealed class Inspector(CliApp owner, StaticWorkerOptions options) : IArtifactInspector
    {
        public async Task<StaticReport?> InspectAsync(string path, string displayName, CancellationToken cancellationToken) =>
            await owner.AnalyzeStatic(path, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reports progress on the caller's thread (Progress&lt;T&gt; would post to the thread pool).</summary>
    private sealed class SyncProgress(Action<AnalysisProgress> report) : IProgress<AnalysisProgress>
    {
        public void Report(AnalysisProgress value) => report(value);
    }

    private static IReportExporter? ReportExporterFor(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".html" or ".htm" => new HtmlReportExporter(),
        ".json" => new JsonReportExporter(),
        _ => null,
    };

    internal static int OutcomeCode(AnalysisResult result) =>
        result.FinalStage == AnalysisStage.Failed ? ExitCodes.Error : ExitCodes.For(result.Risk.Verdict);

    private static string VerdictText(Verdict v, string language) => (v, language) switch
    {
        (Verdict.LowRisk, "ar") => "خطورة منخفضة",
        (Verdict.Suspicious, "ar") => "مريب",
        (Verdict.HighRiskBehavior, "ar") => "سلوك عالي الخطورة",
        (Verdict.CriticalBehavior, "ar") => "سلوك حرج",
        (Verdict.LowRisk, _) => "Low risk",
        (Verdict.Suspicious, _) => "Suspicious",
        (Verdict.HighRiskBehavior, _) => "High-risk behavior",
        (Verdict.CriticalBehavior, _) => "Critical behavior",
        _ => v.ToString(),
    };

    private static string OneLine(AnalysisResult r) =>
        $"{r.Risk.Score,3}/100  {VerdictText(r.Risk.Verdict, "en"),-18}  {r.Findings.Count} findings  id {r.AnalysisId.ToString("N")[..8]}{(r.IsDemo ? "  (DEMO)" : "")}";

    internal static string ResultSummary(AnalysisResult r, string language)
    {
        var sb = new StringBuilder();
        if (r.IsDemo) sb.AppendLine("DEMO - simulated events, not a real analysis of this file.").AppendLine();
        sb.AppendLine(CultureInfo.InvariantCulture, $"File      {r.Sample.FileName}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"SHA-256   {r.Sample.Sha256}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"Score     {r.Risk.Score}/100 - {VerdictText(r.Risk.Verdict, language)}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"Run       {r.ProviderId}, {r.Options.Network}, {r.Duration?.TotalSeconds ?? 0:0}s, {r.Events.Count:N0} events, {r.AllProcesses.Count()} processes");
        sb.AppendLine(CultureInfo.InvariantCulture, $"ID        {r.AnalysisId:N}");
        if (r.FinalStage == AnalysisStage.Failed) sb.AppendLine("Failed    " + r.FailureReason);
        if (r.MonitoringInterrupted) sb.AppendLine("Warning   monitoring was interrupted; the picture may be incomplete.");
        foreach (var rep in r.Reputation.Where(x => x.Verdict is ReputationVerdict.Malicious or ReputationVerdict.Suspicious))
            sb.AppendLine(CultureInfo.InvariantCulture, $"Lookup    {rep.ProviderName}: {rep.Verdict}{(rep.Detections is { } d ? $" ({d}/{rep.Engines})" : "")}{(rep.Family is { } f ? " " + f : "")}");

        if (r.Findings.Count > 0)
        {
            sb.AppendLine().AppendLine(CultureInfo.InvariantCulture, $"Findings ({r.Findings.Count})");
            foreach (var f in r.Findings.OrderByDescending(f => f.Points).Take(15))
            {
                var attack = f.AttackTechniques.Count > 0 ? "  [" + string.Join(", ", f.AttackTechniques) + "]" : "";
                sb.AppendLine(CultureInfo.InvariantCulture, $"  +{f.Points,-3} {f.Severity,-8} {f.Title.Get(language)}{attack}");
            }
            if (r.Findings.Count > 15) sb.AppendLine(CultureInfo.InvariantCulture, $"  ... and {r.Findings.Count - 15} more");
        }
        var network = r.Indicators.Count;
        if (network > 0) sb.AppendLine().AppendLine(CultureInfo.InvariantCulture, $"Indicators: {network} (use \"blazma export {r.AnalysisId.ToString("N")[..8]} --format stix\")");
        sb.AppendLine().Append(language == "ar" ? RiskAssessment.DisclaimerAr : RiskAssessment.Disclaimer);
        return sb.ToString();
    }

    internal static object Summary(AnalysisResult r, string language) => new
    {
        id = r.AnalysisId.ToString("N"),
        file = r.Sample.FileName,
        sha256 = r.Sample.Sha256,
        demo = r.IsDemo,
        environment = r.ProviderId,
        network = r.Options.Network.ToString(),
        stage = r.FinalStage.ToString(),
        failure = r.FailureReason,
        score = r.Risk.Score,
        verdict = r.Risk.Verdict.ToString(),
        exitCode = OutcomeCode(r),
        events = r.Events.Count,
        processes = r.AllProcesses.Count(),
        findings = r.Findings.OrderByDescending(f => f.Points).Select(f => new
        {
            rule = f.RuleId,
            title = f.Title.Get(language),
            severity = f.Severity.ToString(),
            points = f.Points,
            attack = f.AttackTechniques,
        }),
        indicators = r.Indicators.Count,
        reputation = r.Reputation.Select(x => new { provider = x.ProviderId, verdict = x.Verdict.ToString(), x.Detections, x.Engines, x.Family }),
    };

    // ---- list / export / envs --------------------------------------------------------------

    private async Task<int> ListAsync(CommandLine command, CancellationToken ct)
    {
        var limit = 20;
        if (command.Option("limit") is { } l && (!int.TryParse(l, NumberStyles.Integer, CultureInfo.InvariantCulture, out limit) || limit is < 1 or > 1000))
            return await UsageErrorAsync("--limit must be between 1 and 1000.");
        await using var c = await OpenAsync(command, ct);
        var items = await c.Repository.ListAsync(limit, 0, ct);
        if (command.Flag("json"))
        {
            await stdout.WriteLineAsync(JsonSerializer.Serialize(items, PrettyJson));
            return ExitCodes.Ok;
        }
        if (items.Count == 0)
        {
            await stdout.WriteLineAsync("No analyses yet.");
            return ExitCodes.Ok;
        }
        foreach (var s in items)
            await stdout.WriteLineAsync(string.Create(CultureInfo.InvariantCulture,
                $"{s.Id.ToString("N")[..8]}  {s.StartedAt.LocalDateTime:yyyy-MM-dd HH:mm}  {s.Score,3}  {VerdictText(s.Verdict, "en"),-18}  {s.FileName}{(s.IsDemo ? "  (DEMO)" : "")}"));
        return ExitCodes.Ok;
    }

    private async Task<int> ExportAsync(CommandLine command, CancellationToken ct)
    {
        if (command.Positionals.Count != 1) return await UsageErrorAsync("export needs an analysis id.");
        var format = command.Option("format")?.ToLowerInvariant();
        var output = command.Option("out");
        if (format is null || output is null) return await UsageErrorAsync("export needs --format and --out.");
        if (format is not ("html" or "json" or "stix" or "misp" or "sigma" or "yara"))
            return await UsageErrorAsync("--format must be html, json, stix, misp, sigma or yara.");

        await using var c = await OpenAsync(command, ct);
        var id = await ResolveIdAsync(c.Repository, command.Positionals[0], ct);
        if (id is null) return await UsageErrorAsync("No single saved analysis matches \"" + command.Positionals[0] + "\".");
        var result = await c.Repository.LoadAsync(id.Value, includeEvents: true, ct)
            ?? throw new InvalidDataException("The analysis could not be loaded.");

        var r = c.Settings.Reports;
        var options = new ExportOptions(Language(command), c.Settings.Privacy.RedactExports, r.IncludeRawEvents, r.IncludeTimeline, r.IncludeStaticDetails, r.IncludeIndicators, r.TimelineSummaryLimit);
        string? text = format switch
        {
            "sigma" => new SigmaGenerator().Generate(result, options),
            "yara" => new YaraRuleGenerator().Generate(result, options),
            _ => null,
        };
        if (format is "sigma" or "yara" && string.IsNullOrWhiteSpace(text))
        {
            await stderr.WriteLineAsync("Nothing to export: the analysis has no observations this format can describe.");
            return ExitCodes.Ok;
        }

        await using (var stream = File.Create(output))
        {
            switch (format)
            {
                case "html": await new HtmlReportExporter().ExportAsync(result, stream, options, ct); break;
                case "json": await new JsonReportExporter().ExportAsync(result, stream, options, ct); break;
                case "stix": await new StixExporter().ExportAsync(result, stream, options, ct); break;
                case "misp": await new MispExporter().ExportAsync(result, stream, options, ct); break;
                default: await stream.WriteAsync(Encoding.UTF8.GetBytes(text!), ct); break;
            }
        }
        await stdout.WriteLineAsync("Written " + Path.GetFullPath(output));
        return ExitCodes.Ok;
    }

    internal static async Task<Guid?> ResolveIdAsync(IAnalysisRepository repository, string text, CancellationToken ct)
    {
        if (Guid.TryParse(text, out var full)) return full;
        var prefix = text.Trim().Replace("-", "").ToLowerInvariant();
        if (prefix.Length < 4 || !prefix.All(Uri.IsHexDigit)) return null;
        var matches = (await repository.ListAsync(10_000, 0, ct))
            .Where(s => s.Id.ToString("N").StartsWith(prefix, StringComparison.Ordinal))
            .Take(2)
            .ToList();
        return matches.Count == 1 ? matches[0].Id : null;
    }

    private async Task<int> EnvironmentsAsync(CommandLine command, CancellationToken ct)
    {
        await using var c = await OpenAsync(command, ct);
        var rows = new List<object>();
        foreach (var id in SandboxProviders.Ids)
        {
            var provider = ProviderFactory?.Invoke(id, c.Settings, c.Paths)
                ?? SandboxProviders.Create(id, c.Settings, c.Paths.Work, SandboxProviders.DefaultAgentFolder, SecretProtector.CreateDefault());
            var a = await provider.CheckAvailabilityAsync(NetworkPolicy.Simulated, ct);
            var isDefault = id.Equals(c.Settings.Analysis.ProviderId, StringComparison.OrdinalIgnoreCase);
            if (command.Flag("json"))
            {
                rows.Add(new { id, name = provider.DisplayName, readiness = a.Readiness.ToString(), isDefault, failed = a.Checks.Where(x => !x.Passed).Select(x => x.Label.En) });
                continue;
            }
            await stdout.WriteLineAsync($"{(isDefault ? "*" : " ")} {id,-16} {a.Readiness,-13} {provider.DisplayName}");
            foreach (var check in a.Checks.Where(x => !x.Passed))
                await stdout.WriteLineAsync($"      - {check.Label.En}: {check.Detail.En}");
        }
        if (command.Flag("json")) await stdout.WriteLineAsync(JsonSerializer.Serialize(rows, PrettyJson));
        return ExitCodes.Ok;
    }
}
