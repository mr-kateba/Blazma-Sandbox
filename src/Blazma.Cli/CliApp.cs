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
using Blazma.Core.Events;
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

    /// <summary>Archive extraction; replaced in tests (the default uses the isolated helper process).</summary>
    internal Func<string, string, string?, string, CancellationToken, Task<string>> ExtractEntry { get; init; } =
        (archive, entry, password, folder, ct) => StaticWorker.ExtractAsync(archive, entry, password, folder, "blazma.dll", ct);

    /// <summary>Hook for tests to replace the analysis environment.</summary>
    internal Func<string?, BlazmaSettings, BlazmaPaths, ISandboxProvider>? ProviderFactory { get; init; }

    private static readonly JsonSerializerOptions PrettyJson = new(BlazmaJson.Options) { WriteIndented = true };

    /// <summary>Arabic unless "--lang en" was given: most users read Arabic.</summary>
    private bool _ar = true;

    private string L(string en, string ar) => _ar ? ar : en;

    private static string L(bool arabic, string en, string ar) => arabic ? ar : en;

    /// <summary>Reads --lang before parsing so even a parse error is shown in the user's language.</summary>
    internal static bool WantsArabic(IReadOnlyList<string> args)
    {
        for (var i = 0; i < args.Count; i++)
        {
            var a = args[i];
            string? value = a.StartsWith("--lang=", StringComparison.OrdinalIgnoreCase) ? a[7..]
                : a.Equals("--lang", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Count ? args[i + 1] : null;
            if (value is not null) return !value.StartsWith("en", StringComparison.OrdinalIgnoreCase);
        }
        return true;
    }

    public async Task<int> RunAsync(IReadOnlyList<string> args, CancellationToken cancellationToken)
    {
        _ar = WantsArabic(args);
        var (command, error) = CommandLine.Parse(args);
        if (command is null)
        {
            await stderr.WriteLineAsync(_ar ? CommandLine.Arabic(error) : error);
            await stderr.WriteLineAsync(L("Run \"blazma help\" for usage.", "اكتب \"blazma help\" لعرض طريقة الاستخدام."));
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
                _ => await UsageErrorAsync(L($"Unknown command \"{command.Verb}\".", $"أمر غير معروف: \"{command.Verb}\".")),
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await stderr.WriteLineAsync(L("Cancelled.", "أُلغي."));
            return ExitCodes.Cancelled;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or InvalidDataException)
        {
            await stderr.WriteLineAsync(L("Error: ", "خطأ: ") + ex.Message);
            return ExitCodes.Error;
        }
    }

    // ---- help ------------------------------------------------------------------------------

    internal const string HelpTextAr = """
        Blazma Sandbox - تحليل سلوك ملفات Windows داخل بيئة معزولة.

        طريقة الاستخدام:
          blazma static  <file> [--json] [--password <p>]
              البصمات والنوع وتفاصيل PE وimphash والقدرات ومطابقات YARA والملفات داخل
              الملف المضغوط. لا يشغّل الملف أبدًا.
          blazma analyze <file> [options]
              يشغّل الملف داخل بيئة التحليل ويعرض الحكم.
          blazma batch   <folder> [options] [--recursive] [--summary results.csv]
              يحلل كل ملفات المجلد واحدًا بعد الآخر.
          blazma list    [--limit 20] [--json]
              آخر التحليلات من السجل (نفس سجل البرنامج).
          blazma export  <analysis-id> --format html|pdf|json|stix|misp|sigma|yara --out <path>
              يصدّر تحليلًا محفوظًا بصيغة أخرى. يكفي جزء من رقم التحليل.
          blazma envs    [--json]
              بيئات التحليل الجاهزة على هذا الجهاز.

        خيارات التحليل:
          --entry <path>        للملف المضغوط: الملف الذي بداخله المراد تحليله
          --password <p>        كلمة مرور الملف المضغوط (الافتراضي من الإعدادات، ثم infected/malware/virus)
          --env windows-sandbox|virtualbox|hyperv|demo   (الافتراضي من الإعدادات)
          --profile quick|standard|deep|interactive      (الافتراضي standard)
          --network simulated|offline|internet           (الافتراضي simulated: إنترنت وهمي)
          --allow-internet      مطلوب مع --network internet؛ يستطيع الملف الوصول لخوادم حقيقية
          --duration <seconds>  مدة التشغيل بدل مدة الملف التعريفي (15-1800)
          --report <path>       يكتب تقريرًا أيضًا (.html أو .pdf أو .json حسب الامتداد)
          --lookup              فحص السمعة بالبصمة فقط عبر الخدمات المفعّلة في الإعدادات
          --pcap                يسجّل حركة الشبكة داخل البيئة (pcapng)
          --no-screenshots      بدون لقطات لشاشة البيئة
          --lang ar|en          لغة المخرجات (الافتراضي ar)
          --json                مخرجات JSON للبرامج
          --data <folder>       مجلد بيانات آخر (الافتراضي مجلد البرنامج)

        رموز الخروج:
          0 خطورة منخفضة / تم   10 مريب   20 سلوك عالي الخطورة   30 سلوك حرج
          1 خطأ   2 استخدام خاطئ   3 البيئة غير جاهزة   4 أُلغي
          الدرجة دليل يراجعه شخص، وليست إثباتًا أن الملف خبيث.
        """;

    internal const string HelpText = """
        Blazma Sandbox - behavior analysis of Windows files in an isolated environment.

        Usage:
          blazma static  <file> [--json] [--password <p>]
              Hashes, type, PE details, imphash, capabilities, YARA matches and the files
              inside an archive. Never runs the file.
          blazma analyze <file> [options]
              Runs the file in the analysis environment and prints the verdict.
          blazma batch   <folder> [options] [--recursive] [--summary results.csv]
              Analyzes every file in a folder, one after another.
          blazma list    [--limit 20] [--json]
              Recent analyses from the history (shared with the desktop app).
          blazma export  <analysis-id> --format html|pdf|json|stix|misp|sigma|yara --out <path>
              Writes a saved analysis in another format. The id can be shortened.
          blazma envs    [--json]
              Which analysis environments are ready on this computer.

        Analysis options:
          --entry <path>        for an archive: the file inside it to analyze
          --password <p>        archive password (default: from settings, then infected/malware/virus)
          --env windows-sandbox|virtualbox|hyperv|demo   (default: from settings)
          --profile quick|standard|deep|interactive      (default: standard)
          --network simulated|offline|internet           (default: simulated)
          --allow-internet      required with --network internet; the sample can reach real servers
          --duration <seconds>  override the profile's run time (15-1800)
          --report <path>       also write a report (.html, .pdf or .json by extension)
          --lookup              hash-only reputation lookup with the services enabled in settings
          --pcap                record the sandbox's network traffic (pcapng)
          --no-screenshots      do not capture the sandbox screen
          --lang ar|en          language of the output (default: ar)
          --json                machine-readable output on stdout
          --data <folder>       use another data folder (default: the app's)

        Exit codes:
          0 low risk / done   10 suspicious   20 high-risk behavior   30 critical behavior
          1 error   2 usage   3 environment not ready   4 cancelled
          A score is evidence for a person to review, not proof that a file is malicious.
        """;

    private async Task<int> HelpAsync()
    {
        await stdout.WriteLineAsync(_ar ? HelpTextAr : HelpText);
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
        await stderr.WriteLineAsync(L("Run \"blazma help\" for usage.", "اكتب \"blazma help\" لعرض طريقة الاستخدام."));
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

    private static StaticWorkerOptions StaticOptions(Context c, string? archivePassword = null) => new(
        c.Settings.Detection.EnableCapabilities,
        c.Settings.Detection.EnableYara ? c.Paths.Yara : null,
        archivePassword ?? c.Settings.Analysis.DefaultArchivePassword);

    private static string Language(CommandLine command) =>
        (command.Option("lang") ?? "ar").StartsWith("en", StringComparison.OrdinalIgnoreCase) ? "en" : "ar";

    // ---- static ----------------------------------------------------------------------------

    private async Task<int> StaticAsync(CommandLine command, CancellationToken ct)
    {
        if (command.Positionals.Count != 1) return await UsageErrorAsync(L("static needs exactly one file.", "الأمر static يحتاج ملفًا واحدًا."));
        var path = Path.GetFullPath(command.Positionals[0]);
        if (!File.Exists(path)) return await UsageErrorAsync(L("File not found: ", "الملف غير موجود: ") + path);
        await using var c = await OpenAsync(command, ct);
        var report = await AnalyzeStatic(path, StaticOptions(c, command.Option("password")), ct);
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
        var ar = language == "ar";
        sb.AppendLine(CultureInfo.InvariantCulture, $"{L(ar, "File     ", "الملف    ")} {s.FileName}  ({s.Size:N0} {L(ar, "bytes", "بايت")}, {s.Kind})");
        sb.AppendLine(CultureInfo.InvariantCulture, $"SHA-256   {s.Sha256}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"SHA-1     {s.Sha1}");
        if (report.ImpHash is { } imp) sb.AppendLine(CultureInfo.InvariantCulture, $"Imphash   {imp}");
        if (report.Pe is { } pe)
            sb.AppendLine(CultureInfo.InvariantCulture, $"PE        {pe.Machine}, {(pe.IsDll ? "DLL" : "EXE")}, {pe.Subsystem}{(pe.IsDotNet ? ", .NET" : "")}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"{L(ar, "Signature", "التوقيع  ")} {report.Signature.Status}{(report.Signature.Publisher is { } p ? " (" + p + ")" : "")}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"{L(ar, "Entropy  ", "الإنتروبي")} {report.Entropy:0.00}");
        if (report.Capabilities.Count > 0)
        {
            sb.AppendLine().AppendLine(CultureInfo.InvariantCulture, $"{L(ar, "Capabilities", "قدرات الكود")} ({report.Capabilities.Count})");
            foreach (var cap in report.Capabilities) sb.AppendLine(CultureInfo.InvariantCulture, $"  {cap.Id,-12} {cap.Name.Get(language)}");
        }
        if (report.YaraMatches.Count > 0)
        {
            sb.AppendLine().AppendLine(CultureInfo.InvariantCulture, $"YARA ({report.YaraMatches.Count})");
            foreach (var m in report.YaraMatches) sb.AppendLine(CultureInfo.InvariantCulture, $"  {m.Rule}  [{m.Source}]");
        }
        if (report.Strings.Count > 0)
        {
            sb.AppendLine().AppendLine(CultureInfo.InvariantCulture, $"{L(ar, "Interesting strings", "نصوص مهمة")} ({report.Strings.Count})");
            foreach (var str in report.Strings.Take(20)) sb.AppendLine(CultureInfo.InvariantCulture, $"  {str.Kind,-12} {str.Value}");
        }
        if (report.Archive is { } archive)
        {
            sb.AppendLine().AppendLine(L(ar, $"Archive {archive.Format}{(archive.Encrypted ? ", encrypted" : "")} ({archive.Entries.Count} files; analyze one with --entry)", $"ملف مضغوط {archive.Format}{(archive.Encrypted ? "، مشفّر" : "")} ({archive.Entries.Count} ملف؛ حلّل أحدها بالخيار --entry)"));
            foreach (var e in archive.Entries.Take(50))
                sb.AppendLine(CultureInfo.InvariantCulture, $"  {(SampleInfo.IsRunnable(e.Kind) ? "*" : " ")} {e.Size,12:N0}  {e.Kind,-11} {e.Path}");
            if (archive.Entries.Count > 50) sb.AppendLine(L(ar, $"  ... and {archive.Entries.Count - 50} more", $"  ... و{archive.Entries.Count - 50} غيرها"));
            if (archive.LimitNote is { } note) sb.AppendLine("  " + note);
        }
        if (report.Artifacts.Count > 0)
        {
            sb.AppendLine().AppendLine(CultureInfo.InvariantCulture, $"{L(ar, "Extracted values", "قيم مستخرجة")} ({report.Artifacts.Count})");
            foreach (var a in report.Artifacts.Take(20)) sb.AppendLine(CultureInfo.InvariantCulture, $"  {a.Kind,-14} {a.Value}");
        }
        foreach (var w in report.Warnings) sb.AppendLine(L(ar, "Warning: ", "تنبيه: ") + w);
        return sb.ToString().TrimEnd();
    }

    // ---- analyze / batch -------------------------------------------------------------------

    private sealed record RunPlan(AnalysisOptions Options, string? ProviderId, string? ReportPath, bool Lookup);

    private async Task<(RunPlan? Plan, int Exit)> PlanAsync(CommandLine command, Context c)
    {
        var profileId = command.Option("profile") ?? AnalysisProfile.StandardId;
        var profile = AnalysisProfile.BuiltIns.FirstOrDefault(p => p.Id.Equals(profileId, StringComparison.OrdinalIgnoreCase));
        if (profile is null) return (null, await UsageErrorAsync(L($"Unknown profile \"{profileId}\".", $"ملف تعريفي غير معروف: \"{profileId}\".")));
        var options = profile.Options;

        switch ((command.Option("network") ?? "simulated").ToLowerInvariant())
        {
            case "simulated": options = options with { Network = NetworkPolicy.Simulated }; break;
            case "offline" or "disabled" or "none": options = options with { Network = NetworkPolicy.Disabled }; break;
            case "internet" or "enabled" or "real":
                if (!command.Flag("allow-internet"))
                    return (null, await UsageErrorAsync(L("--network internet lets the sample reach real servers. Add --allow-internet to confirm.", "الخيار --network internet يسمح للملف بالوصول لخوادم حقيقية. أضف --allow-internet للتأكيد.")));
                options = options with { Network = NetworkPolicy.Enabled };
                break;
            default: return (null, await UsageErrorAsync(L("--network must be simulated, offline or internet.", "قيمة --network يجب أن تكون simulated أو offline أو internet.")));
        }
        if (command.Option("duration") is { } d)
        {
            if (!int.TryParse(d, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds) || seconds <= 0)
                return (null, await UsageErrorAsync(L("--duration must be a number of seconds.", "قيمة --duration يجب أن تكون عدد ثوانٍ.")));
            options = options with { Duration = TimeSpan.FromSeconds(seconds) };
        }
        if (command.Flag("interactive")) options = options with { Interactive = true };
        if (command.Flag("pcap")) options = options with { CapturePcap = true };
        if (command.Flag("no-screenshots")) options = options with { CaptureScreenshots = false };

        var env = command.Option("env");
        if (env is not null && !SandboxProviders.Ids.Contains(env, StringComparer.OrdinalIgnoreCase))
            return (null, await UsageErrorAsync(L($"Unknown environment \"{env}\". Use one of: {string.Join(", ", SandboxProviders.Ids)}.", $"بيئة غير معروفة: \"{env}\". استخدم إحدى: {string.Join("، ", SandboxProviders.Ids)}.")));

        var reportPath = command.Option("report");
        if (reportPath is not null && ReportExporterFor(reportPath) is null)
            return (null, await UsageErrorAsync(L("--report must end in .html, .pdf or .json.", "قيمة --report يجب أن تنتهي بـ ‎.html أو ‎.pdf أو ‎.json.")));

        return (new RunPlan(options.Normalized(), env?.ToLowerInvariant(), reportPath, command.Flag("lookup")), ExitCodes.Ok);
    }

    private ISandboxProvider Provider(RunPlan plan, Context c) =>
        ProviderFactory?.Invoke(plan.ProviderId, c.Settings, c.Paths)
        ?? SandboxProviders.Create(plan.ProviderId, c.Settings, c.Paths.Work, SandboxProviders.DefaultAgentFolder, SecretProtector.CreateDefault());

    private async Task<int> AnalyzeAsync(CommandLine command, CancellationToken ct)
    {
        if (command.Positionals.Count != 1) return await UsageErrorAsync(L("analyze needs exactly one file.", "الأمر analyze يحتاج ملفًا واحدًا."));
        var path = Path.GetFullPath(command.Positionals[0]);
        if (!File.Exists(path)) return await UsageErrorAsync(L("File not found: ", "الملف غير موجود: ") + path);
        await using var c = await OpenAsync(command, ct);
        var (plan, exit) = await PlanAsync(command, c);
        if (plan is null) return exit;

        var provider = Provider(plan, c);
        if (!await EnsureReadyAsync(provider, plan.Options.Network, ct)) return ExitCodes.EnvironmentNotReady;

        ArchiveOrigin? origin = null;
        if (command.Option("entry") is { } entry)
        {
            var archive = await AnalyzeStatic(path, StaticOptions(c, command.Option("password")), ct);
            if (archive.Sample.Kind != FileKind.Archive) return await UsageErrorAsync(L("--entry is only for archives.", "الخيار --entry للملفات المضغوطة فقط."));
            var match = archive.Archive?.Entries.FirstOrDefault(e => e.Path == entry);
            if (match is null) return await UsageErrorAsync(archive.Archive is null
                ? L("The archive could not be opened; give the right --password.", "تعذّر فتح الملف المضغوط؛ اكتب كلمة المرور الصحيحة بالخيار --password.")
                : L($"The archive has no file \"{entry}\". Run \"blazma static\" to list it.", $"لا يوجد ملف باسم \"{entry}\" داخل الملف المضغوط. اكتب \"blazma static\" لعرض محتواه."));
            var folder = Path.Combine(c.Paths.Work, "extracted", Guid.NewGuid().ToString("N"));
            origin = new ArchiveOrigin(archive.Sample.FileName, archive.Sample.Sha256, entry);
            path = await ExtractWithPasswordsAsync(path, entry, archive.Archive!.Encrypted || match.Encrypted ? PasswordCandidates(c, command.Option("password")) : [null], folder, ct);
        }

        var result = await RunOneAsync(path, plan, provider, c, command.Flag("json"), ct, origin);
        if (result is null) return ExitCodes.Error;
        if (command.Flag("json"))
            await stdout.WriteLineAsync(JsonSerializer.Serialize(Summary(result, Language(command)), PrettyJson));
        else
            await stdout.WriteLineAsync(ResultSummary(result, Language(command)));
        return OutcomeCode(result);
    }

    private async Task<int> BatchAsync(CommandLine command, CancellationToken ct)
    {
        if (command.Positionals.Count != 1) return await UsageErrorAsync(L("batch needs exactly one folder.", "الأمر batch يحتاج مجلدًا واحدًا."));
        var folder = Path.GetFullPath(command.Positionals[0]);
        if (!Directory.Exists(folder)) return await UsageErrorAsync(L("Folder not found: ", "المجلد غير موجود: ") + folder);
        await using var c = await OpenAsync(command, ct);
        var (plan, exit) = await PlanAsync(command, c);
        if (plan is null) return exit;
        if (plan.ReportPath is not null) return await UsageErrorAsync(L("--report is for one file; use \"blazma export\" after a batch.", "الخيار --report لملف واحد؛ استخدم \"blazma export\" بعد التحليل الجماعي."));

        var files = Directory.EnumerateFiles(folder, "*", command.Flag("recursive") ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (files.Count == 0) return await UsageErrorAsync(L("The folder has no files.", "المجلد لا يحتوي ملفات."));

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
                await stdout.WriteLineAsync(result is null ? L($"  failed: {failure}", $"  فشل: {failure}") : "  " + OneLine(result, _ar ? "ar" : "en"));
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
        await stderr.WriteLineAsync(L($"The analysis environment \"{provider.DisplayName}\" is not ready ({availability.Readiness}):", $"بيئة التحليل \"{provider.DisplayName}\" غير جاهزة ({availability.Readiness}):"));
        foreach (var check in availability.Checks.Where(x => !x.Passed))
            await stderr.WriteLineAsync($"  - {check.Label.Get(_ar ? "ar" : "en")}: {check.Detail.Get(_ar ? "ar" : "en")}");
        return false;
    }

    /// <summary>The typed password first, then the settings default and the common sample passwords.</summary>
    private static IReadOnlyList<string?> PasswordCandidates(Context c, string? typed) =>
        new[] { typed, c.Settings.Analysis.DefaultArchivePassword }
            .Concat(Blazma.Analysis.Archives.ArchiveReader.DefaultPasswords)
            .Where(p => !string.IsNullOrEmpty(p))
            .Distinct(StringComparer.Ordinal)
            .ToList();

    private async Task<string> ExtractWithPasswordsAsync(string archive, string entry, IReadOnlyList<string?> passwords, string folder, CancellationToken ct)
    {
        InvalidOperationException? last = null;
        foreach (var password in passwords)
        {
            try
            {
                return await ExtractEntry(archive, entry, password, folder, ct);
            }
            catch (InvalidOperationException ex)
            {
                last = ex;
            }
        }
        throw last ?? new InvalidOperationException(L("The file could not be extracted.", "تعذّر استخراج الملف."));
    }

    private async Task<AnalysisResult?> RunOneAsync(string path, RunPlan plan, ISandboxProvider provider, Context c, bool quiet, CancellationToken ct, ArchiveOrigin? origin = null)
    {
        var report = await AnalyzeStatic(path, StaticOptions(c), ct);
        if (origin is not null) report = report with { Sample = report.Sample with { Origin = origin } };
        if (!report.Sample.IsExecutableKind)
        {
            await stderr.WriteLineAsync(report.Sample.Kind == FileKind.Archive
                ? L("This is an archive: choose the file to run with --entry (see \"blazma static\").", "هذا ملف مضغوط: اختر الملف المراد تشغيله بالخيار --entry (انظر \"blazma static\").")
                : L($"{report.Sample.FileName}: this kind of file ({report.Sample.Kind}) cannot be run in the sandbox.", $"{report.Sample.FileName}: هذا النوع من الملفات ({report.Sample.Kind}) لا يمكن تشغيله في البيئة المعزولة."));
            return null;
        }

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
            foreach (var e in errors) await stderr.WriteLineAsync(L("Rule pack: ", "حزمة قواعد: ") + e);
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
            stderr.WriteLine($"  {StageText(p.Stage)}{(p.Message is { } m ? ": " + m : "")}");
        });

        AnalysisResult result;
        try
        {
            result = await runner.RunAsync(request, provider, progress, null, ct);
        }
        catch (AnalysisFailedException ex)
        {
            await stderr.WriteLineAsync(L("Analysis failed: ", "فشل التحليل: ") + ex.Reason);
            return null;
        }

        if (plan.ReportPath is { } reportPath)
        {
            var exporter = ReportExporterFor(reportPath)!;
            var r = c.Settings.Reports;
            var options = new ExportOptions(_ar ? "ar" : "en", c.Settings.Privacy.RedactExports, r.IncludeRawEvents, r.IncludeTimeline, r.IncludeStaticDetails, r.IncludeIndicators, r.TimelineSummaryLimit);
            await using var stream = File.Create(reportPath);
            await exporter.ExportAsync(result, stream, options, ct);
            if (!quiet) await stderr.WriteLineAsync(L("Report written to ", "كُتب التقرير في ") + Path.GetFullPath(reportPath));
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
        ".pdf" => new PdfReportExporter(),
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

    private string StageText(AnalysisStage stage) => !_ar ? stage.ToString() : stage switch
    {
        AnalysisStage.Preparing => "تجهيز",
        AnalysisStage.CreatingSandbox => "إنشاء البيئة المعزولة",
        AnalysisStage.Booting => "تشغيل البيئة",
        AnalysisStage.DeployingAgent => "تجهيز وكيل المراقبة",
        AnalysisStage.Ready => "جاهزة",
        AnalysisStage.TransferringSample => "نقل الملف",
        AnalysisStage.Analyzing => "التحليل جارٍ",
        AnalysisStage.CollectingEvents => "جمع الأحداث",
        AnalysisStage.Finalizing => "الإنهاء",
        AnalysisStage.GeneratingReport => "إنشاء التقرير",
        AnalysisStage.Completed => "اكتمل",
        AnalysisStage.Failed => "فشل",
        AnalysisStage.Cancelled => "أُلغي",
        _ => stage.ToString(),
    };

    private static string SeverityText(Severity s, bool ar) => !ar ? s.ToString() : s switch
    {
        Severity.Informational => "معلومة",
        Severity.Low => "منخفض",
        Severity.Medium => "متوسط",
        Severity.High => "مرتفع",
        Severity.Critical => "حرج",
        _ => s.ToString(),
    };

    private static string OneLine(AnalysisResult r, string language)
    {
        var ar = language == "ar";
        return $"{r.Risk.Score,3}/100  {VerdictText(r.Risk.Verdict, language),-18}  {r.Findings.Count} {L(ar, "findings", "نتيجة")}  id {r.AnalysisId.ToString("N")[..8]}{(r.IsDemo ? L(ar, "  (DEMO)", "  (تجريبي)") : "")}";
    }

    internal static string ResultSummary(AnalysisResult r, string language)
    {
        var sb = new StringBuilder();
        var ar = language == "ar";
        if (r.IsDemo) sb.AppendLine(L(ar, "DEMO - simulated events, not a real analysis of this file.", "تجريبي: أحداث اصطناعية، وليس تحليلًا حقيقيًا لهذا الملف.")).AppendLine();
        sb.AppendLine(CultureInfo.InvariantCulture, $"{L(ar, "File     ", "الملف    ")} {r.Sample.FileName}");
        if (r.Sample.Origin is { } origin) sb.AppendLine(CultureInfo.InvariantCulture, $"{L(ar, "From     ", "من       ")} {origin.ArchiveName} -> {origin.EntryPath}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"SHA-256   {r.Sample.Sha256}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"{L(ar, "Score    ", "الدرجة   ")} {r.Risk.Score}/100 - {VerdictText(r.Risk.Verdict, language)}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"{L(ar, "Run      ", "التشغيل  ")} {r.ProviderId}, {r.Options.Network}, {r.Duration?.TotalSeconds ?? 0:0}s, {r.Events.Count:N0} {L(ar, "events", "حدث")}, {r.AllProcesses.Count()} {L(ar, "processes", "عملية")}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"ID        {r.AnalysisId:N}");
        if (r.FinalStage == AnalysisStage.Failed) sb.AppendLine(L(ar, "Failed    ", "فشل      ") + r.FailureReason);
        if (r.MonitoringInterrupted) sb.AppendLine(L(ar, "Warning   monitoring was interrupted; the picture may be incomplete.", "تنبيه    انقطعت المراقبة؛ قد تكون الصورة ناقصة."));
        foreach (var rep in r.Reputation.Where(x => x.Verdict is ReputationVerdict.Malicious or ReputationVerdict.Suspicious))
            sb.AppendLine(CultureInfo.InvariantCulture, $"{L(ar, "Lookup   ", "السمعة   ")} {rep.ProviderName}: {rep.Verdict}{(rep.Detections is { } d ? $" ({d}/{rep.Engines})" : "")}{(rep.Family is { } f ? " " + f : "")}");

        if (r.Findings.Count > 0)
        {
            sb.AppendLine().AppendLine(CultureInfo.InvariantCulture, $"{L(ar, "Findings", "النتائج")} ({r.Findings.Count})");
            foreach (var f in r.Findings.OrderByDescending(f => f.Points).Take(15))
            {
                var attack = f.AttackTechniques.Count > 0 ? "  [" + string.Join(", ", f.AttackTechniques) + "]" : "";
                sb.AppendLine(CultureInfo.InvariantCulture, $"  +{f.Points,-3} {SeverityText(f.Severity, ar),-8} {f.Title.Get(language)}{attack}");
            }
            if (r.Findings.Count > 15) sb.AppendLine(L(ar, $"  ... and {r.Findings.Count - 15} more", $"  ... و{r.Findings.Count - 15} غيرها"));
        }
        var network = r.Indicators.Count;
        if (network > 0) sb.AppendLine().AppendLine(L(ar,
            $"Indicators: {network} (use \"blazma export {r.AnalysisId.ToString("N")[..8]} --format stix\")",
            $"المؤشرات: {network} (للتصدير: \"blazma export {r.AnalysisId.ToString("N")[..8]} --format stix\")"));
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
            return await UsageErrorAsync(L("--limit must be between 1 and 1000.", "قيمة --limit يجب أن تكون بين 1 و1000."));
        await using var c = await OpenAsync(command, ct);
        var items = await c.Repository.ListAsync(limit, 0, ct);
        if (command.Flag("json"))
        {
            await stdout.WriteLineAsync(JsonSerializer.Serialize(items, PrettyJson));
            return ExitCodes.Ok;
        }
        if (items.Count == 0)
        {
            await stdout.WriteLineAsync(L("No analyses yet.", "لا توجد تحليلات بعد."));
            return ExitCodes.Ok;
        }
        foreach (var s in items)
            await stdout.WriteLineAsync(string.Create(CultureInfo.InvariantCulture,
                $"{s.Id.ToString("N")[..8]}  {s.StartedAt.LocalDateTime:yyyy-MM-dd HH:mm}  {s.Score,3}  {VerdictText(s.Verdict, _ar ? "ar" : "en"),-18}  {s.FileName}{(s.IsDemo ? L("  (DEMO)", "  (تجريبي)") : "")}"));
        return ExitCodes.Ok;
    }

    private async Task<int> ExportAsync(CommandLine command, CancellationToken ct)
    {
        if (command.Positionals.Count != 1) return await UsageErrorAsync(L("export needs an analysis id.", "الأمر export يحتاج رقم التحليل."));
        var format = command.Option("format")?.ToLowerInvariant();
        var output = command.Option("out");
        if (format is null || output is null) return await UsageErrorAsync(L("export needs --format and --out.", "الأمر export يحتاج --format و--out."));
        if (format is not ("html" or "pdf" or "json" or "stix" or "misp" or "sigma" or "yara"))
            return await UsageErrorAsync(L("--format must be html, pdf, json, stix, misp, sigma or yara.", "قيمة --format يجب أن تكون html أو pdf أو json أو stix أو misp أو sigma أو yara."));

        await using var c = await OpenAsync(command, ct);
        var id = await ResolveIdAsync(c.Repository, command.Positionals[0], ct);
        if (id is null) return await UsageErrorAsync(L("No single saved analysis matches \"", "لا يوجد تحليل محفوظ واحد يطابق \"") + command.Positionals[0] + "\".");
        var result = await c.Repository.LoadAsync(id.Value, includeEvents: true, ct)
            ?? throw new InvalidDataException(L("The analysis could not be loaded.", "تعذّر تحميل التحليل."));

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
            await stderr.WriteLineAsync(L("Nothing to export: the analysis has no observations this format can describe.", "لا شيء للتصدير: التحليل لا يحتوي ملاحظات تصفها هذه الصيغة."));
            return ExitCodes.Ok;
        }

        await using (var stream = File.Create(output))
        {
            switch (format)
            {
                case "html": await new HtmlReportExporter().ExportAsync(result, stream, options, ct); break;
                case "pdf": await new PdfReportExporter().ExportAsync(result, stream, options, ct); break;
                case "json": await new JsonReportExporter().ExportAsync(result, stream, options, ct); break;
                case "stix": await new StixExporter().ExportAsync(result, stream, options, ct); break;
                case "misp": await new MispExporter().ExportAsync(result, stream, options, ct); break;
                default: await stream.WriteAsync(Encoding.UTF8.GetBytes(text!), ct); break;
            }
        }
        await stdout.WriteLineAsync(L("Written ", "كُتب ") + Path.GetFullPath(output));
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
            await stdout.WriteLineAsync($"{(isDefault ? "*" : " ")} {id,-16} {ReadinessText(a.Readiness),-13} {provider.DisplayName}");
            foreach (var check in a.Checks.Where(x => !x.Passed))
                await stdout.WriteLineAsync($"      - {check.Label.Get(_ar ? "ar" : "en")}: {check.Detail.Get(_ar ? "ar" : "en")}");
        }
        if (command.Flag("json")) await stdout.WriteLineAsync(JsonSerializer.Serialize(rows, PrettyJson));
        return ExitCodes.Ok;
    }

    private string ReadinessText(ProviderReadiness r) => !_ar ? r.ToString() : r switch
    {
        ProviderReadiness.Ready => "جاهزة",
        ProviderReadiness.NotSupported => "غير مدعومة",
        ProviderReadiness.NeedsSetup => "تحتاج إعداد",
        ProviderReadiness.Unavailable => "غير متاحة",
        _ => r.ToString(),
    };
}
