using System.Text.RegularExpressions;
using Blazma.Analysis.Engine;
using Blazma.Analysis.Text;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Text;

namespace Blazma.Analysis.Rules;

public sealed class DroppedExecutableRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-F001",
        Version = "1.1",
        Name = new("Created a program file in a user folder", "أنشأ ملفًا تنفيذيًا في مجلد المستخدم"),
        Description = new("The program wrote an executable or script into a user-writable folder such as AppData, Temp or ProgramData. Installers and updaters do this, but it is also how unwanted programs place copies of themselves.", "كتب البرنامج ملفًا تنفيذيًا أو سكربتًا في مجلد قابل للكتابة مثل AppData أو Temp أو ProgramData. برامج التثبيت تفعل ذلك، لكنها أيضًا الطريقة التي تضع بها البرامج غير المرغوبة نسخًا منها."),
        Category = FindingCategory.FileSystem,
        Severity = Severity.Medium,
        Weight = 12,
    };

    public override Finding? Evaluate(RuleContext context)
    {
        // Start-menu and desktop shortcuts are what every installer leaves; Startup-folder files are counted
        // as persistence; installer-engine files (setup.tmp, NSIS plug-ins) are not what gets installed.
        var drops = context.Graph.DroppedFiles
            .Where(kv => PathRules.IsExecutablePath(kv.Key) && PathRules.IsUserWritableLocation(kv.Key)
                         && !InstallerPaths.IsShortcut(kv.Key)
                         && !kv.Key.Contains(@"\Start Menu\Programs\Startup\", StringComparison.OrdinalIgnoreCase)
                         && !InstallerPaths.IsEngineArtifact(kv.Key, context.Sample.FileName))
            .Select(kv => kv.Value).OrderBy(e => e.RelativeTime).Take(25).ToList();
        var evidence = drops.Select(e => EventEvidence("file", e,
            new($"{e.ProcessName} created {PathRules.FileName(e.Target)}", $"أنشأ {e.ProcessName} الملف {PathRules.FileName(e.Target)}"))).ToList();
        return Build(evidence, processes: drops.Select(context.NodeOf).Where(n => n is not null).Select(n => n!.Key), firstSeen: drops.FirstOrDefault()?.RelativeTime);
    }
}

public sealed class DroppedFileExecutedRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-F002",
        Version = "1.1",
        Name = new("Ran a program it had just created", "شغّل برنامجًا أنشأه للتو"),
        Description = new("A file written during the analysis was then started as a new process. This two-step pattern hides the real payload from the first look at the original file.", "تم تشغيل ملف كُتب أثناء التحليل كعملية جديدة. هذا النمط على مرحلتين يُخفي الحمولة الحقيقية عن الفحص الأول للملف الأصلي."),
        Category = FindingCategory.Execution,
        Severity = Severity.High,
        Weight = 15,
    };

    public override Finding? Evaluate(RuleContext context)
    {
        // An installer engine starting its own unpacked engine (Inno Setup's setup.tmp, a WiX bundle's
        // clean-room copy, Squirrel's Update.exe) is how the installer works, not a hidden second stage.
        var nodes = context.Graph.Nodes.Values
            .Where(n => n.InAnalyzedTree && n.ImageDroppedDuringAnalysis && !InstallerPaths.IsEngineArtifact(n.ImagePath, context.Sample.FileName))
            .OrderBy(n => n.Start).ToList();
        var evidence = nodes.Select(n =>
        {
            context.Graph.DroppedFiles.TryGetValue(n.ImagePath!, out var drop);
            return new Evidence
            {
                Kind = "dropped-executed",
                Description = new($"{n.Name} was created during the analysis and then started", $"أُنشئ {n.Name} أثناء التحليل ثم تم تشغيله"),
                Technical = n.ImagePath,
                EventSequences = drop is null ? [n.StartEventSequence] : [drop.Sequence, n.StartEventSequence],
            };
        }).ToList();

        if (nodes.Count > 0 && nodes.All(n => InstallerPaths.IsInstalledProgramLocation(n.ImagePath)))
        {
            var installed = Build(evidence, new(
                "A program the installation wrote under Program Files was then started. Installers often run what they just installed, to register it or finish the setup, and only administrators can write to that folder, so this counts for less.",
                "شُغّل برنامج كتبته عملية التثبيت داخل مجلد Program Files. برامج التثبيت كثيرًا ما تشغّل ما ثبّتته للتو لتسجيله أو لإكمال الإعداد، ولا يكتب في هذا المجلد إلا المسؤول، لذا يُحتسب بوزن أقل."),
                nodes.Select(n => n.Key), nodes[0].Start, Severity.Low);
            return installed is null ? null : installed with { Points = 5 };
        }
        return Build(evidence, processes: nodes.Select(n => n.Key), firstSeen: nodes.FirstOrDefault()?.Start);
    }
}

public sealed class SelfDeletionRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-F004",
        Version = "1.0",
        Name = new("Deleted its own file", "حذف ملفه الأصلي"),
        Description = new("The original file was deleted while it or its children were running. This removes traces of where the activity came from.", "تم حذف الملف الأصلي أثناء عمله أو عمل العمليات التابعة له، وهذا يزيل أثر مصدر النشاط."),
        Category = FindingCategory.DefenseEvasion,
        Severity = Severity.Medium,
        Weight = 10,
        AttackTechniques = ["T1070.004"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var image = context.Graph.Sample?.ImagePath;
        if (image is null) return null;
        var deletes = context.TreeEvents.Where(e => e.Action == EventAction.FileDelete && e.Target is not null
            && PathRules.NormalizeFilePath(e.Target).Equals(image, StringComparison.OrdinalIgnoreCase)).ToList();
        var evidence = deletes.Select(e => EventEvidence("file", e, new($"{e.ProcessName} deleted {PathRules.FileName(image)}", $"حذف {e.ProcessName} الملف {PathRules.FileName(image)}"))).ToList();
        return Build(evidence, firstSeen: deletes.FirstOrDefault()?.RelativeTime);
    }
}

public sealed partial class MassFileModificationRule : Rule
{
    private const int Threshold = 30;

    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-F003",
        Version = "1.1",
        Name = new("Changed many personal files quickly", "عدّل عددًا كبيرًا من الملفات الشخصية بسرعة"),
        Description = new("The program modified, renamed or deleted a large number of existing files in personal folders (Desktop, Documents, Pictures and the like), or wrote encrypted-looking copies of them, in a short time. Ransomware behaves like this; so can sync and backup tools.", "عدّل البرنامج أو أعاد تسمية أو حذف عددًا كبيرًا من الملفات الموجودة في المجلدات الشخصية (سطح المكتب والمستندات والصور وما شابهها)، أو كتب منها نسخًا تبدو مشفّرة، خلال وقت قصير. برامج الفدية تتصرف هكذا، وكذلك أدوات المزامنة والنسخ الاحتياطي."),
        Category = FindingCategory.Impact,
        Severity = Severity.Critical,
        Weight = 35,
        AttackTechniques = ["T1486"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        // The first thing the tree did to each personal file decides: creating it means it is the program's own
        // (a portable tool unpacking next to itself on the desktop); writing, renaming or deleting means it existed.
        var first = new Dictionary<string, AnalysisEvent>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in context.TreeEvents)
        {
            if (e.Action is not (EventAction.FileCreate or EventAction.FileWrite or EventAction.FileRename or EventAction.FileDelete) || e.Target is null) continue;
            var path = PathRules.NormalizeFilePath(e.Target);
            if (IsPersonal(path)) first.TryAdd(path, e);
        }
        var touched = first.Where(kv => kv.Value.Action != EventAction.FileCreate || EncryptedCopyRegex().IsMatch(kv.Key))
            .Select(kv => kv.Value).OrderBy(e => e.RelativeTime).ToList();
        if (touched.Count < Threshold) return null;
        var evidence = new List<Evidence>
        {
            new()
            {
                Kind = "file-burst",
                Description = new($"{touched.Count} personal files were modified, renamed, deleted or rewritten as encrypted copies", $"تم تعديل {touched.Count} ملفًا شخصيًا أو إعادة تسميتها أو حذفها أو إعادة كتابتها كنسخ مشفّرة"),
                Technical = string.Join("\n", touched.Take(10).Select(e => e.Target)),
                EventSequences = touched.Take(200).Select(e => e.Sequence).ToList(),
            },
        };
        return Build(evidence, firstSeen: touched[0].RelativeTime);
    }

    /// <summary>A user's own files: anything in a profile or the public profile except AppData.</summary>
    internal static bool IsPersonal(string path) => PersonalRegex().IsMatch(path);

    [GeneratedRegex(@"^[A-Za-z]:\\Users\\[^\\]+\\(?!AppData\\)[^\\]+\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PersonalRegex();

    /// <summary>"report.docx.locked": a document extension followed by an extra, unfamiliar one.</summary>
    [GeneratedRegex(@"\.(docx?|xlsx?|pptx?|pdf|txt|rtf|odt|ods|csv|jpe?g|png|gif|bmp|psd|mp3|mp4|avi|mov|zip|rar|7z|sql|db|mdb|kdbx)\.(?!(tmp|part|partial|crdownload|download|bak|lnk|old)$)[A-Za-z0-9_\-]{2,16}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EncryptedCopyRegex();
}

public sealed partial class SecurityTamperingRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-R001",
        Version = "1.1",
        Name = new("Tried to weaken Windows security", "حاول إضعاف حماية Windows"),
        Description = new("The program changed Microsoft Defender, the firewall or security policy settings, for example disabling real-time protection, adding exclusions, stopping security services, turning the firewall off, clearing event logs or blocking Task Manager.", "غيّر البرنامج إعدادات Microsoft Defender أو جدار الحماية أو سياسات الأمان، مثل تعطيل الحماية الفورية أو إضافة استثناءات أو إيقاف خدمات الحماية أو إيقاف جدار الحماية أو مسح سجلات الأحداث أو منع فتح مدير المهام."),
        Category = FindingCategory.DefenseEvasion,
        Severity = Severity.Critical,
        Weight = 30,
        AttackTechniques = ["T1562.001", "T1686.003", "T1685.005"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var registry = context.Events.Where(e => e.Action == EventAction.RegistryValueSet && e.Target is not null
            && context.Graph.InAnalyzedTree(e) && IsWeakeningSetting(PathRules.NormalizeRegistryKey(e.Target), e.Detail(DetailKeys.ValueName), e.Detail(DetailKeys.ValueData)))
            .ToList();
        var commands = context.Graph.Nodes.Values.Where(n => n.InAnalyzedTree && n.CommandLine is not null && IsWeakeningCommand(n.CommandLine))
            .OrderBy(n => n.Start).ToList();

        var evidence = registry.Select(e => EventEvidence("registry", e, new($"{e.ProcessName} changed a security setting", $"غيّر {e.ProcessName} إعدادًا أمنيًا"),
                $"{e.Target}\\{e.Detail(DetailKeys.ValueName)} = {e.Detail(DetailKeys.ValueData)}"))
            .Concat(commands.Select(n => new Evidence
            {
                Kind = "command-line",
                Description = new($"{n.Name} ran a command that weakens security", $"شغّل {n.Name} أمرًا يُضعف الحماية"),
                Technical = n.CommandLine,
                EventSequences = [n.StartEventSequence],
            })).ToList();
        return Build(evidence, processes: commands.Select(n => n.Key));
    }

    internal static bool IsWeakeningSetting(string key, string? valueName, string? data)
    {
        if (key.Contains(@"\Policies\Microsoft\Windows Defender", StringComparison.OrdinalIgnoreCase)
            || key.Contains(@"\Microsoft\Windows Defender\Exclusions", StringComparison.OrdinalIgnoreCase)
            || key.Contains(@"\Microsoft\Windows Defender\Real-Time Protection", StringComparison.OrdinalIgnoreCase)
            || key.Contains(@"\Microsoft\Windows Defender\Features", StringComparison.OrdinalIgnoreCase))
            return true;
        var off = data?.Trim() is "0" or "0x0" or "0x00000000";
        var on = data?.Trim() is "1" or "2" or "0x1" or "0x00000001";
        if (SecurityServiceRegex().IsMatch(key) && string.Equals(valueName, "Start", StringComparison.OrdinalIgnoreCase) && data?.Trim() is "4" or "0x4" or "0x00000004") return true;
        if (FirewallPolicyRegex().IsMatch(key) && string.Equals(valueName, "EnableFirewall", StringComparison.OrdinalIgnoreCase) && off) return true;
        if (key.EndsWith(@"\Policies\System", StringComparison.OrdinalIgnoreCase) && valueName is "DisableTaskMgr" or "DisableRegistryTools" && on) return true;
        return key.EndsWith(@"\Policies\Microsoft\Windows\System", StringComparison.OrdinalIgnoreCase) && valueName is "DisableCMD" && on;
    }

    internal static bool IsWeakeningCommand(string commandLine) => WeakeningCommandRegex().IsMatch(commandLine);

    [GeneratedRegex(@"\\Services\\(WinDefend|WdNisSvc|WdFilter|WdBoot|WdNisDrv|Sense|SecurityHealthService|wscsvc|mpssvc|BFE|EventLog)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SecurityServiceRegex();

    [GeneratedRegex(@"(\\FirewallPolicy\\(StandardProfile|DomainProfile|PublicProfile)|\\Policies\\Microsoft\\WindowsFirewall\\(StandardProfile|DomainProfile|PublicProfile))$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex FirewallPolicyRegex();

    [GeneratedRegex(@"(set-mppreference\b.*-(disable\w*|exclusion\w*|submitsamplesconsent\s+[23]|mapsreporting\s+0|puaprotection\s+(0|disabled))"
        + @"|add-mppreference\b.*-exclusion"
        + @"|mpcmdrun(\.exe)?""?\s.*-removedefinitions"
        + @"|\b(sc(\.exe)?|net1?(\.exe)?)""?\s+(stop|config|delete)\s+""?(windefend|wdnissvc|sense|securityhealthservice|wscsvc|mpssvc|eventlog)\b"
        + @"|taskkill\b.*\b(msmpeng|nissrv|securityhealthsystray|securityhealthservice|mpcmdrun)(\.exe)?\b"
        + @"|netsh(\.exe)?""?\s+(advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+(mode=)?disable)"
        + @"|set-netfirewallprofile\b.*-enabled\s+(\$?false|0)"
        + @"|wevtutil(\.exe)?""?\s+(cl|clear-log)\s|clear-eventlog\b|remove-eventlog\b)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex WeakeningCommandRegex();
}

public sealed class NetworkRedirectionRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-R002",
        Version = "1.0",
        Name = new("Changed network redirection settings", "غيّر إعدادات توجيه الشبكة"),
        Description = new("The program edited the hosts file or the system proxy settings, which control where network traffic goes.", "عدّل البرنامج ملف hosts أو إعدادات Proxy في النظام، وهي تتحكم في وجهة حركة الشبكة."),
        Category = FindingCategory.Network,
        Severity = Severity.Medium,
        Weight = 12,
        AttackTechniques = ["T1090"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var hits = context.TreeEvents.Where(e =>
                (e.Category == EventCategory.File && e.Action is EventAction.FileWrite or EventAction.FileCreate && e.Target is not null
                 && e.Target.EndsWith(@"\drivers\etc\hosts", StringComparison.OrdinalIgnoreCase))
                || (e.Action == EventAction.RegistryValueSet && e.Target is not null
                    && PathRules.NormalizeRegistryKey(e.Target).EndsWith(@"\CurrentVersion\Internet Settings", StringComparison.OrdinalIgnoreCase)
                    && e.Detail(DetailKeys.ValueName) is "ProxyServer" or "ProxyEnable" or "AutoConfigURL"))
            .ToList();
        var evidence = hits.Select(e => EventEvidence(e.Category == EventCategory.File ? "file" : "registry", e,
            new($"{e.ProcessName} changed {(e.Category == EventCategory.File ? "the hosts file" : "proxy settings")}", $"غيّر {e.ProcessName} {(e.Category == EventCategory.File ? "ملف hosts" : "إعدادات Proxy")}"))).ToList();
        return Build(evidence, firstSeen: hits.FirstOrDefault()?.RelativeTime);
    }
}

/// <summary>
/// The same instruction file left in many folders. In an empty sandbox ransomware may find little
/// to encrypt, but it still drops its note in every folder it walks through.
/// </summary>
public sealed partial class RansomNoteRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-F005",
        Version = "1.0",
        Name = new("Left ransom notes in several folders", "ترك رسائل فدية في عدة مجلدات"),
        Description = new("The same instruction file (for example HOW_TO_DECRYPT.txt) was written into several folders. Ransomware leaves such a note in every folder it encrypts so that the victim finds its payment instructions.",
            "كُتب ملف التعليمات نفسه (مثل HOW_TO_DECRYPT.txt) في عدة مجلدات. تترك برامج الفدية رسالة كهذه في كل مجلد تشفّره ليجد الضحية تعليمات الدفع."),
        Category = FindingCategory.Impact,
        Severity = Severity.Critical,
        Weight = 30,
        AttackTechniques = ["T1486", "T1491.001"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var notes = context.TreeEvents
            .Where(e => e.Action is EventAction.FileCreate or EventAction.FileWrite && e.Target is not null)
            .Select(e => (Event: e, Path: PathRules.NormalizeFilePath(e.Target!)))
            .Where(x => NoteRegex().IsMatch(PathRules.FileName(x.Path)) && !InstallerPaths.IsInstalledProgramLocation(x.Path)
                        && !x.Path.Contains(@"\AppData\Local\Programs\", StringComparison.OrdinalIgnoreCase))
            .GroupBy(x => PathRules.FileName(x.Path), StringComparer.OrdinalIgnoreCase)
            .Select(g => (Name: g.Key, Copies: g.GroupBy(x => x.Path[..Math.Max(0, x.Path.Length - g.Key.Length)], StringComparer.OrdinalIgnoreCase).Select(d => d.First()).ToList()))
            .Where(g => g.Copies.Count >= (StrongNoteRegex().IsMatch(g.Name) ? 2 : 4))
            .OrderByDescending(g => g.Copies.Count).ToList();
        if (notes.Count == 0) return null;

        var evidence = notes.Take(5).Select(g => new Evidence
        {
            Kind = "file",
            Description = new($"{g.Name} was written into {g.Copies.Count} folders", $"كُتب الملف {g.Name} في {g.Copies.Count} مجلدات"),
            Technical = string.Join("\n", g.Copies.Take(10).Select(c => c.Path)),
            EventSequences = g.Copies.Take(50).Select(c => c.Event.Sequence).ToList(),
        }).ToList();
        var first = notes.SelectMany(g => g.Copies).MinBy(c => c.Event.RelativeTime).Event;
        return Build(evidence, processes: notes.SelectMany(g => g.Copies).Select(c => context.NodeOf(c.Event)).OfType<Core.Processes.ProcessNode>().Select(n => n.Key), firstSeen: first.RelativeTime);
    }

    /// <summary>A text or web page whose name reads like instructions.</summary>
    [GeneratedRegex(@"^(?=.*\.(txt|html?|hta|rtf|url)$).*(read[\s_\-.]*me|how[\s_\-]*to|instruction|decrypt|recover|restore|ransom|unlock|encrypt|locked|your[\s_\-]*files|files[\s_\-]*back|attention|warning|!!!)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex NoteRegex();

    /// <summary>Words that leave no doubt; plain "readme" needs more copies.</summary>
    [GeneratedRegex(@"decrypt|recover|restore|ransom|unlock|encrypt|locked|your[\s_\-]*files|files[\s_\-]*back", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex StrongNoteRegex();
}

/// <summary>A copy of a Windows program name living outside Windows: a classic disguise.</summary>
public sealed class MasqueradingRule : Rule
{
    private static readonly HashSet<string> SystemNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe", "explorer.exe", "spoolsv.exe",
        "taskhostw.exe", "taskhost.exe", "dllhost.exe", "conhost.exe", "rundll32.exe", "RuntimeBroker.exe", "sihost.exe", "ctfmon.exe",
        "SearchIndexer.exe", "SearchProtocolHost.exe", "MsMpEng.exe", "WmiPrvSE.exe", "audiodg.exe", "dwm.exe", "lsm.exe", "regsvr32.exe",
        "wuauclt.exe", "userinit.exe", "smartscreen.exe", "SecurityHealthService.exe",
        // Near-misses seen in the wild
        "svch0st.exe", "scvhost.exe", "svhost.exe", "svchosts.exe", "svchost32.exe", "lsasss.exe", "lsas.exe", "isass.exe", "csrsss.exe", "crss.exe",
        "winlogin.exe", "expl0rer.exe", "explorer32.exe", "taskhosts.exe", "dllhst.exe", "spoolsvc.exe",
    };

    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-F006",
        Version = "1.0",
        Name = new("Disguised a program as part of Windows", "تنكّر في صورة أحد برامج Windows"),
        Description = new("A program with the name of a Windows component (such as svchost.exe or explorer.exe), or a near-copy of one, was written or run from a folder outside Windows. Genuine Windows programs live in the Windows folder; the familiar name is meant to avoid notice in Task Manager.",
            "كُتب أو شُغّل خارج مجلد Windows برنامجٌ يحمل اسم أحد مكوّنات Windows (مثل svchost.exe أو explorer.exe) أو اسمًا قريبًا منه. برامج Windows الحقيقية موجودة في مجلد Windows، والاسم المألوف غرضه تجنّب الانتباه في مدير المهام."),
        Category = FindingCategory.DefenseEvasion,
        Severity = Severity.High,
        Weight = 20,
        AttackTechniques = ["T1036.005"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var processes = context.Graph.Nodes.Values
            .Where(n => n.InAnalyzedTree && n.ImagePath is { } image && SystemNames.Contains(PathRules.FileName(image)) && IsOutsideWindows(image))
            .OrderBy(n => n.Start).ToList();
        var files = context.Graph.DroppedFiles
            .Where(kv => SystemNames.Contains(PathRules.FileName(kv.Key)) && IsOutsideWindows(kv.Key) && processes.All(p => !kv.Key.Equals(p.ImagePath, StringComparison.OrdinalIgnoreCase)))
            .Select(kv => kv.Value).OrderBy(e => e.RelativeTime).Take(10).ToList();

        var evidence = processes.Select(n => new Evidence
            {
                Kind = "process",
                Description = new($"{n.Name} ran from {PathRules.FileName(Path.GetDirectoryName(n.ImagePath))}, not from the Windows folder", $"عمل {n.Name} من المجلد {PathRules.FileName(Path.GetDirectoryName(n.ImagePath))} وليس من مجلد Windows"),
                Technical = n.ImagePath,
                EventSequences = [n.StartEventSequence],
            })
            .Concat(files.Select(e => EventEvidence("file", e, new($"{e.ProcessName} created {PathRules.FileName(e.Target)} outside the Windows folder", $"أنشأ {e.ProcessName} الملف {PathRules.FileName(e.Target)} خارج مجلد Windows"))))
            .ToList();
        return Build(evidence, processes: processes.Select(n => n.Key), firstSeen: evidence.Count == 0 ? null : processes.Select(n => n.Start).Concat(files.Select(f => f.RelativeTime)).Min());
    }

    private static bool IsOutsideWindows(string path) =>
        PathRules.NormalizeFilePath(path) is var p && p.Contains('\\', StringComparison.Ordinal) && !p.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Registry hijacks that make an auto-elevating Windows program start something else with administrator rights, and switching UAC off.</summary>
public sealed partial class UacBypassRule : Rule
{
    private static readonly HashSet<string> AutoElevating = new(StringComparer.OrdinalIgnoreCase)
    {
        "fodhelper.exe", "computerdefaults.exe", "sdclt.exe", "eventvwr.exe", "wsreset.exe", "slui.exe", "changepk.exe", "cmstp.exe", "perfmon.exe",
    };

    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-R003",
        Version = "1.0",
        Name = new("Bypassed or turned off User Account Control", "تجاوز التحكم في حساب المستخدم (UAC) أو عطّله"),
        Description = new("The program changed registry entries that make a trusted Windows program (such as fodhelper or eventvwr) start another program with administrator rights without the UAC prompt, or switched UAC prompts off. Legitimate software asks for elevation openly instead.",
            "غيّر البرنامج إدخالات في السجل تجعل برنامجًا موثوقًا من Windows (مثل fodhelper أو eventvwr) يشغّل برنامجًا آخر بصلاحيات المسؤول دون ظهور نافذة UAC، أو أوقف نوافذ UAC. البرامج السليمة تطلب رفع الصلاحيات بشكل صريح بدلًا من ذلك."),
        Category = FindingCategory.DefenseEvasion,
        Severity = Severity.High,
        Weight = 25,
        AttackTechniques = ["T1548.002"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var registry = context.TreeEvents
            .Where(e => e.Action is EventAction.RegistryValueSet or EventAction.RegistryKeyCreate && e.Target is not null
                        && IsBypassSetting(PathRules.NormalizeRegistryKey(e.Target), e.Action == EventAction.RegistryValueSet, e.Detail(DetailKeys.ValueName), e.Detail(DetailKeys.ValueData)))
            .GroupBy(e => (PathRules.NormalizeRegistryKey(e.Target!), e.Detail(DetailKeys.ValueName))).Select(g => g.First())
            .Take(10).ToList();
        // An auto-elevating program started by the tree that then starts something itself.
        var elevated = context.Graph.Nodes.Values
            .Where(n => n.InAnalyzedTree && !n.IsSample && AutoElevating.Contains(n.Name) && n.Children.Any(c => c.InAnalyzedTree && !c.Name.Equals("conhost.exe", StringComparison.OrdinalIgnoreCase)))
            .OrderBy(n => n.Start).ToList();
        if (registry.Count == 0 && elevated.Count == 0) return null;

        var evidence = registry.Select(e => EventEvidence("registry", e, new($"{e.ProcessName} changed {Describe(e)}", $"غيّر {e.ProcessName} {DescribeAr(e)}"),
                $"{e.Target}\\{e.Detail(DetailKeys.ValueName)} = {e.Detail(DetailKeys.ValueData)}"))
            .Concat(elevated.Select(n => new Evidence
            {
                Kind = "process",
                Description = new($"{n.Name}, which Windows runs with administrator rights without asking, started {string.Join(", ", n.Children.Select(c => c.Name).Distinct())}",
                    $"شغّل {n.Name}، الذي يعمل بصلاحيات المسؤول دون سؤال، البرنامج {string.Join("، ", n.Children.Select(c => c.Name).Distinct())}"),
                Technical = n.CommandLine,
                EventSequences = [n.StartEventSequence, .. n.Children.Select(c => c.StartEventSequence)],
            })).ToList();
        var severity = registry.Count > 0 && elevated.Count > 0 ? Severity.Critical : Severity.High;
        return Build(evidence, processes: elevated.Select(n => n.Key), severity: severity);
    }

    private static string Describe(AnalysisEvent e) => IsUacSwitch(e) ? "the UAC settings" : "how a Windows program that runs with administrator rights starts";
    private static string DescribeAr(AnalysisEvent e) => IsUacSwitch(e) ? "إعدادات UAC" : "طريقة تشغيل برنامج من Windows يعمل بصلاحيات المسؤول";
    private static bool IsUacSwitch(AnalysisEvent e) => e.Detail(DetailKeys.ValueName) is "EnableLUA" or "ConsentPromptBehaviorAdmin" or "PromptOnSecureDesktop";

    internal static bool IsBypassSetting(string key, bool valueSet, string? valueName, string? data)
    {
        if (HijackRegex().IsMatch(key)) return true;
        if (!valueSet) return false;
        if (key.Equals(@"HKCU\Environment", StringComparison.OrdinalIgnoreCase) && valueName is not null
            && (valueName.Equals("windir", StringComparison.OrdinalIgnoreCase) || valueName.Equals("SystemRoot", StringComparison.OrdinalIgnoreCase)))
            return true;
        return key.EndsWith(@"\CurrentVersion\Policies\System", StringComparison.OrdinalIgnoreCase)
               && valueName is "EnableLUA" or "ConsentPromptBehaviorAdmin" or "PromptOnSecureDesktop" && data?.Trim() is "0" or "0x0" or "0x00000000";
    }

    [GeneratedRegex(@"^HKCU\\Software\\Classes\\(ms-settings|mscfile|exefile|Folder|Launcher\.SystemSettings|ms-windows-store|AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2)\\shell\\(open|runas)\\command$|^HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control\.exe$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HijackRegex();
}
