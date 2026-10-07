using System.Text.RegularExpressions;
using Blazma.Analysis.Text;
using Blazma.Core.Events;
using Blazma.Core.Processes;
using Blazma.Core.Text;

namespace Blazma.Analysis.Engine;

/// <summary>
/// Known places Windows reads at sign-in or boot to start programs. A write here is worth
/// explaining, but is not proof of anything on its own: installers legitimately register
/// services and startup entries all the time.
/// </summary>
public static partial class PersistenceCatalog
{
    public sealed record Match(PersistenceTechnique Technique, string Target, string? Value);

    public static bool IsSensitiveLocation(AnalysisEvent e) => Classify(e) is not null
        || (e.Category == EventCategory.Registry && e.Target is not null && ServicesKeyRegex().IsMatch(PathRules.NormalizeRegistryKey(e.Target)));

    public static Match? Classify(AnalysisEvent e)
    {
        switch (e.Action)
        {
            case EventAction.ServiceInstall:
                return new Match(PersistenceTechnique.Service, e.Detail(DetailKeys.ServiceName) ?? e.Target ?? "service", e.Detail(DetailKeys.ImagePath));
            case EventAction.ScheduledTaskCreate:
                return new Match(PersistenceTechnique.ScheduledTask, e.Detail(DetailKeys.TaskName) ?? e.Target ?? "task", e.Detail(DetailKeys.CommandLine));
            case EventAction.FileCreate or EventAction.FileWrite or EventAction.FileRename:
            {
                var path = e.Action == EventAction.FileRename ? e.Detail(DetailKeys.NewPath) ?? e.Target : e.Target;
                if (string.IsNullOrEmpty(path)) return null;
                path = PathRules.NormalizeFilePath(path);
                if (path.Contains(@"\Start Menu\Programs\Startup\", StringComparison.OrdinalIgnoreCase))
                    return new Match(PersistenceTechnique.StartupFolder, path, null);
                if (path.Contains(@"\Windows\System32\Tasks\", StringComparison.OrdinalIgnoreCase))
                    return new Match(PersistenceTechnique.ScheduledTask, PathRules.FileName(path), path);
                return null;
            }
            case EventAction.RegistryValueSet or EventAction.RegistryKeyCreate:
            {
                if (string.IsNullOrEmpty(e.Target)) return null;
                var key = PathRules.NormalizeRegistryKey(e.Target);
                var valueName = e.Detail(DetailKeys.ValueName) ?? string.Empty;
                var data = e.Detail(DetailKeys.ValueData);
                var setValue = e.Action == EventAction.RegistryValueSet;

                if (setValue && RunKeyRegex().IsMatch(key))
                    return new Match(PersistenceTechnique.RunKey, $@"{key}\{valueName}", data);
                if (setValue && ServicesKeyRegex().Match(key) is { Success: true } svc && valueName.Equals("ImagePath", StringComparison.OrdinalIgnoreCase))
                    return new Match(PersistenceTechnique.Service, svc.Groups["name"].Value, data);
                if (TaskCacheRegex().Match(key) is { Success: true } task)
                    return new Match(PersistenceTechnique.ScheduledTask, task.Groups["name"].Value, null);
                if (setValue && WinlogonRegex().IsMatch(key) && valueName is "Shell" or "Userinit" or "Taskman")
                    return new Match(PersistenceTechnique.WinlogonHelper, $@"{key}\{valueName}", data);
                if (setValue && IfeoRegex().IsMatch(key) && valueName is "Debugger" or "GlobalFlag" or "MonitorProcess")
                    return new Match(PersistenceTechnique.ImageFileExecutionOptions, $@"{key}\{valueName}", data);
                if (setValue && AppInitRegex().IsMatch(key) && valueName is "AppInit_DLLs" or "LoadAppInit_DLLs")
                    return new Match(PersistenceTechnique.AppInitDlls, $@"{key}\{valueName}", data);
                if (setValue && ActiveSetupRegex().IsMatch(key) && valueName.Equals("StubPath", StringComparison.OrdinalIgnoreCase))
                    return new Match(PersistenceTechnique.ActiveSetup, $@"{key}\{valueName}", data);
                return null;
            }
            default:
                return null;
        }
    }

    public static LocalizedText Explain(PersistenceTechnique technique) => technique switch
    {
        PersistenceTechnique.RunKey => new(
            "The program added an entry that may make it start automatically every time the user signs in.",
            "أضاف البرنامج إعدادًا قد يجعله يعمل تلقائيًا في كل مرة يسجّل فيها المستخدم الدخول."),
        PersistenceTechnique.StartupFolder => new(
            "The program placed a file in the Startup folder, which Windows opens automatically when the user signs in.",
            "وضع البرنامج ملفًا في مجلد بدء التشغيل، وWindows يفتح محتويات هذا المجلد تلقائيًا عند تسجيل الدخول."),
        PersistenceTechnique.ScheduledTask => new(
            "The program created a scheduled task, which can run a program at set times or events without the user starting it.",
            "أنشأ البرنامج مهمة مجدولة، ويمكنها تشغيل برنامج في أوقات أو أحداث معينة دون أن يشغّله المستخدم."),
        PersistenceTechnique.Service => new(
            "The program registered a Windows service. Services can start with Windows and run in the background with high privileges.",
            "سجّل البرنامج خدمة في Windows. الخدمات يمكن أن تبدأ مع النظام وتعمل في الخلفية بصلاحيات عالية."),
        PersistenceTechnique.WinlogonHelper => new(
            "The program changed what Windows launches at sign-in (Winlogon). Legitimate software rarely does this.",
            "غيّر البرنامج ما يشغّله Windows عند تسجيل الدخول (Winlogon). البرامج السليمة نادرًا ما تفعل ذلك."),
        PersistenceTechnique.ImageFileExecutionOptions => new(
            "The program set a debugger or monitor for another program, which makes Windows run a different program in its place.",
            "عيّن البرنامج Debugger لبرنامج آخر، مما يجعل Windows يشغّل برنامجًا مختلفًا بدلًا منه."),
        PersistenceTechnique.AppInitDlls => new(
            "The program configured a library to be loaded into many other programs as they start.",
            "ضبط البرنامج مكتبة لتُحمَّل داخل برامج أخرى كثيرة عند تشغيلها."),
        PersistenceTechnique.ActiveSetup => new(
            "The program registered an Active Setup command, which runs once for each user when they sign in.",
            "سجّل البرنامج أمر Active Setup، الذي يعمل مرة لكل مستخدم عند تسجيل دخوله."),
        _ => new(
            "The program changed a system setting that can cause it to run again later.",
            "غيّر البرنامج إعدادًا في النظام قد يجعله يعمل مرة أخرى لاحقًا."),
    };

    public static LocalizedText Name(PersistenceTechnique technique) => technique switch
    {
        PersistenceTechnique.RunKey => new("Startup entry (Run key)", "إدخال بدء تشغيل (Run key)"),
        PersistenceTechnique.StartupFolder => new("Startup folder", "مجلد بدء التشغيل"),
        PersistenceTechnique.ScheduledTask => new("Scheduled task", "مهمة مجدولة"),
        PersistenceTechnique.Service => new("Windows service", "خدمة Windows"),
        PersistenceTechnique.WinlogonHelper => new("Winlogon change", "تعديل Winlogon"),
        PersistenceTechnique.ImageFileExecutionOptions => new("Execution redirect (IFEO)", "تحويل التشغيل (IFEO)"),
        PersistenceTechnique.AppInitDlls => new("AppInit DLLs", "مكتبات AppInit"),
        PersistenceTechnique.ActiveSetup => new("Active Setup", "Active Setup"),
        _ => new("Other configuration", "إعداد آخر"),
    };

    [GeneratedRegex(@"^HK(LM|CU)\\Software\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce|Policies\\Explorer\\Run)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RunKeyRegex();

    [GeneratedRegex(@"^HKLM\\System\\(CurrentControlSet|ControlSet\d{3})\\Services\\(?<name>[^\\]+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ServicesKeyRegex();

    [GeneratedRegex(@"^HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\(?<name>.+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TaskCacheRegex();

    [GeneratedRegex(@"^HK(LM|CU)\\Software\\(Wow6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\Winlogon$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex WinlogonRegex();

    [GeneratedRegex(@"^HKLM\\Software\\(Wow6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\(Image File Execution Options|SilentProcessExit)\\[^\\]+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex IfeoRegex();

    [GeneratedRegex(@"^HKLM\\Software\\(Wow6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\Windows$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AppInitRegex();

    [GeneratedRegex(@"^HKLM\\Software\\(Wow6432Node\\)?Microsoft\\Active Setup\\Installed Components\\[^\\]+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ActiveSetupRegex();
}

public static class PersistenceDetector
{
    public static IReadOnlyList<PersistenceDetection> Detect(IReadOnlyList<AnalysisEvent> events, ProcessGraph graph)
    {
        var results = new Dictionary<(PersistenceTechnique, string), PersistenceDetection>();
        foreach (var e in events)
        {
            if (PersistenceCatalog.Classify(e) is not { } match) continue;
            var node = graph.Resolve(e);
            var byTree = node?.InAnalyzedTree == true;
            var key = (match.Technique, match.Target.ToLowerInvariant());
            var pointsToDrop = match.Value is not null && graph.DroppedFiles.Keys.Any(p =>
                match.Value.Contains(p, StringComparison.OrdinalIgnoreCase) ||
                match.Value.Contains(PathRules.FileName(p), StringComparison.OrdinalIgnoreCase));

            if (results.TryGetValue(key, out var existing))
            {
                results[key] = existing with
                {
                    EventSequences = [.. existing.EventSequences, e.Sequence],
                    Value = existing.Value ?? match.Value,
                    PointsToDroppedFile = existing.PointsToDroppedFile || pointsToDrop,
                };
                continue;
            }

            var severity = match.Technique switch
            {
                PersistenceTechnique.WinlogonHelper or PersistenceTechnique.ImageFileExecutionOptions or PersistenceTechnique.AppInitDlls => Severity.Critical,
                _ when pointsToDrop => Severity.High,
                _ => byTree ? Severity.Medium : Severity.Low,
            };

            results[key] = new PersistenceDetection
            {
                Technique = match.Technique,
                ProcessName = node?.Name ?? e.ProcessName,
                Process = node?.Key,
                Target = match.Target,
                Value = match.Value,
                Time = e.RelativeTime,
                Severity = severity,
                Explanation = PersistenceCatalog.Explain(match.Technique),
                EventSequences = [e.Sequence],
                PointsToDroppedFile = pointsToDrop,
                ByAnalyzedTree = byTree,
            };
        }
        return results.Values.OrderBy(p => p.Time).ToList();
    }
}

/// <summary>Public access to technique names for reports and the UI.</summary>
public static class PersistenceNames
{
    public static LocalizedText Of(PersistenceTechnique technique) => PersistenceCatalog.Name(technique);
}
