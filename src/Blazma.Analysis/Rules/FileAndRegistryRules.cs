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
        Version = "1.0",
        Name = new("Created a program file in a user folder", "أنشأ ملفًا تنفيذيًا في مجلد المستخدم"),
        Description = new("The program wrote an executable or script into a user-writable folder such as AppData, Temp or ProgramData. Installers and updaters do this, but it is also how unwanted programs place copies of themselves.", "كتب البرنامج ملفًا تنفيذيًا أو سكربتًا في مجلد قابل للكتابة مثل AppData أو Temp أو ProgramData. برامج التثبيت تفعل ذلك، لكنها أيضًا الطريقة التي تضع بها البرامج غير المرغوبة نسخًا منها."),
        Category = FindingCategory.FileSystem,
        Severity = Severity.Medium,
        Weight = 12,
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var drops = context.Graph.DroppedFiles
            .Where(kv => PathRules.IsExecutablePath(kv.Key) && PathRules.IsUserWritableLocation(kv.Key))
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
        Version = "1.0",
        Name = new("Ran a program it had just created", "شغّل برنامجًا أنشأه للتو"),
        Description = new("A file written during the analysis was then started as a new process. This two-step pattern hides the real payload from the first look at the original file.", "تم تشغيل ملف كُتب أثناء التحليل كعملية جديدة. هذا النمط على مرحلتين يُخفي الحمولة الحقيقية عن الفحص الأول للملف الأصلي."),
        Category = FindingCategory.Execution,
        Severity = Severity.High,
        Weight = 15,
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var nodes = context.Graph.Nodes.Values.Where(n => n.InAnalyzedTree && n.ImageDroppedDuringAnalysis).OrderBy(n => n.Start).ToList();
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

public sealed class MassFileModificationRule : Rule
{
    private const int Threshold = 30;

    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-F003",
        Version = "1.0",
        Name = new("Changed many personal files quickly", "عدّل عددًا كبيرًا من الملفات الشخصية بسرعة"),
        Description = new("The program modified or renamed a large number of files in personal folders (Documents, Desktop, Pictures) in a short time. Ransomware behaves like this; so can sync and backup tools.", "عدّل البرنامج أو أعاد تسمية عدد كبير من الملفات في المجلدات الشخصية (المستندات وسطح المكتب والصور) خلال وقت قصير. برامج الفدية تتصرف هكذا، وكذلك أدوات المزامنة والنسخ الاحتياطي."),
        Category = FindingCategory.Impact,
        Severity = Severity.Critical,
        Weight = 35,
        AttackTechniques = ["T1486"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var touched = context.TreeEvents
            .Where(e => e.Action is EventAction.FileWrite or EventAction.FileRename && e.Target is not null && IsPersonal(e.Target))
            .GroupBy(e => e.Target!, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();
        if (touched.Count < Threshold) return null;
        var evidence = new List<Evidence>
        {
            new()
            {
                Kind = "file-burst",
                Description = new($"{touched.Count} personal files were modified or renamed", $"تم تعديل أو إعادة تسمية {touched.Count} ملفًا شخصيًا"),
                Technical = string.Join("\n", touched.Take(10).Select(e => e.Target)),
                EventSequences = touched.Take(200).Select(e => e.Sequence).ToList(),
            },
        };
        return Build(evidence, firstSeen: touched[0].RelativeTime);
    }

    private static bool IsPersonal(string path) =>
        path.Contains(@"\Documents\", StringComparison.OrdinalIgnoreCase) ||
        path.Contains(@"\Desktop\", StringComparison.OrdinalIgnoreCase) ||
        path.Contains(@"\Pictures\", StringComparison.OrdinalIgnoreCase);
}

public sealed class SecurityTamperingRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-R001",
        Version = "1.0",
        Name = new("Tried to weaken Windows security", "حاول إضعاف حماية Windows"),
        Description = new("The program changed Microsoft Defender or security policy settings, for example disabling real-time protection or adding exclusions.", "غيّر البرنامج إعدادات Microsoft Defender أو سياسات الأمان، مثل تعطيل الحماية الفورية أو إضافة استثناءات."),
        Category = FindingCategory.DefenseEvasion,
        Severity = Severity.Critical,
        Weight = 30,
        AttackTechniques = ["T1562.001"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var registry = context.Events.Where(e => e.Action == EventAction.RegistryValueSet && e.Target is not null
            && context.Graph.InAnalyzedTree(e)
            && (PathRules.NormalizeRegistryKey(e.Target).Contains(@"\Policies\Microsoft\Windows Defender", StringComparison.OrdinalIgnoreCase)
                || PathRules.NormalizeRegistryKey(e.Target).Contains(@"\Microsoft\Windows Defender\Exclusions", StringComparison.OrdinalIgnoreCase)))
            .ToList();
        var commands = context.Graph.Nodes.Values.Where(n => n.InAnalyzedTree && n.CommandLine is not null &&
            (n.CommandLine.Contains("Set-MpPreference", StringComparison.OrdinalIgnoreCase) && n.CommandLine.Contains("Disable", StringComparison.OrdinalIgnoreCase)
             || n.CommandLine.Contains("Add-MpPreference", StringComparison.OrdinalIgnoreCase) && n.CommandLine.Contains("Exclusion", StringComparison.OrdinalIgnoreCase)))
            .ToList();

        var evidence = registry.Select(e => EventEvidence("registry", e, new($"{e.ProcessName} changed a Defender setting", $"غيّر {e.ProcessName} إعدادًا في Defender"),
                $"{e.Target}\\{e.Detail(DetailKeys.ValueName)} = {e.Detail(DetailKeys.ValueData)}"))
            .Concat(commands.Select(n => new Evidence
            {
                Kind = "command-line",
                Description = new($"{n.Name} ran a Defender configuration command", $"شغّل {n.Name} أمرًا لتعديل إعدادات Defender"),
                Technical = n.CommandLine,
                EventSequences = [n.StartEventSequence],
            })).ToList();
        return Build(evidence);
    }
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
