using System.Text.RegularExpressions;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Text;

namespace Blazma.Analysis.Rules;

internal static class ProcessNames
{
    public static readonly HashSet<string> ScriptEngines = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    };

    public static readonly HashSet<string> ProxyBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe", "wmic.exe", "regasm.exe", "odbcconf.exe",
    };
}

/// <summary>Starting a shell or script host is common (installers do it); on its own it counts very little.</summary>
public sealed class ScriptEngineRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-E001",
        Version = "1.0",
        Name = new("Started a command interpreter", "شغّل مفسّر أوامر"),
        Description = new("A process in the analyzed tree started PowerShell, Command Prompt or a script host. Installers do this too, so on its own this counts for little.", "شغّلت عملية ضمن شجرة التحليل PowerShell أو موجه الأوامر أو مضيف سكربتات. برامج التثبيت تفعل ذلك أيضًا، لذا وزنه منفردًا منخفض."),
        Category = FindingCategory.Execution,
        Severity = Severity.Low,
        Weight = 5,
        AttackTechniques = ["T1059"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var nodes = context.Graph.Nodes.Values
            .Where(n => n.InAnalyzedTree && !n.IsSample && ProcessNames.ScriptEngines.Contains(n.Name))
            .OrderBy(n => n.Start).ToList();
        var evidence = nodes.Select(n => new Evidence
        {
            Kind = "process",
            Description = new($"{n.Name} was started", $"تم تشغيل {n.Name}"),
            Technical = n.CommandLine,
            EventSequences = [n.StartEventSequence],
        }).ToList();
        return Build(evidence, processes: nodes.Select(n => n.Key), firstSeen: nodes.FirstOrDefault()?.Start);
    }
}

public sealed partial class ObfuscatedCommandRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-E002",
        Version = "1.0",
        Name = new("Ran a hidden or encoded command", "شغّل أمرًا مخفيًا أو مشفّرًا"),
        Description = new("A command line used options that hide the window, bypass script policy, decode Base64 or download and run code. These are typical of attempts to avoid notice.", "استخدم سطر أوامر خيارات تخفي النافذة أو تتجاوز سياسة السكربتات أو تفك ترميز Base64 أو تنزّل وتشغّل أكوادًا. هذه أساليب شائعة لتجنّب الملاحظة."),
        Category = FindingCategory.DefenseEvasion,
        Severity = Severity.High,
        Weight = 15,
        AttackTechniques = ["T1059.001", "T1027"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var nodes = context.Graph.Nodes.Values
            .Where(n => n.InAnalyzedTree && n.CommandLine is not null && SuspiciousRegex().IsMatch(n.CommandLine))
            .OrderBy(n => n.Start).ToList();
        var evidence = nodes.Select(n => new Evidence
        {
            Kind = "command-line",
            Description = new($"{n.Name} used: {SuspiciousRegex().Match(n.CommandLine!).Value.Trim()}", $"استخدم {n.Name}: {SuspiciousRegex().Match(n.CommandLine!).Value.Trim()}"),
            Technical = n.CommandLine,
            EventSequences = [n.StartEventSequence],
        }).ToList();
        return Build(evidence, processes: nodes.Select(n => n.Key), firstSeen: nodes.FirstOrDefault()?.Start);
    }

    [GeneratedRegex(@"(\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}|-w(indowstyle)?\s+hidden|-ep\s+bypass|-executionpolicy\s+bypass|iex\b|invoke-expression|downloadstring|downloadfile|frombase64string|invoke-webrequest.+\|\s*iex)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SuspiciousRegex();
}

public sealed partial class ProxyExecutionRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-E003",
        Version = "1.0",
        Name = new("Used a built-in Windows tool to run or fetch code", "استخدم أداة مدمجة في Windows لتشغيل أو جلب أكواد"),
        Description = new("A trusted Windows program (such as rundll32, regsvr32, mshta or certutil) was used in a way that runs or downloads code. This can hide activity behind a legitimate name.", "استُخدم برنامج موثوق من Windows (مثل rundll32 أو regsvr32 أو mshta أو certutil) بطريقة تشغّل أو تنزّل أكوادًا، وهذا قد يخفي النشاط خلف اسم سليم."),
        Category = FindingCategory.DefenseEvasion,
        Severity = Severity.Medium,
        Weight = 12,
        AttackTechniques = ["T1218"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var nodes = context.Graph.Nodes.Values
            .Where(n => n.InAnalyzedTree && !n.IsSample && ProcessNames.ProxyBinaries.Contains(n.Name)
                        && (n.Name.Equals("mshta.exe", StringComparison.OrdinalIgnoreCase) || (n.CommandLine is not null && ArgsRegex().IsMatch(n.CommandLine))))
            .OrderBy(n => n.Start).ToList();
        var evidence = nodes.Select(n => new Evidence
        {
            Kind = "process",
            Description = new($"{n.Name} was used with code-running arguments", $"استُخدم {n.Name} مع وسائط تشغّل أكوادًا"),
            Technical = n.CommandLine,
            EventSequences = [n.StartEventSequence],
        }).ToList();
        return Build(evidence, processes: nodes.Select(n => n.Key), firstSeen: nodes.FirstOrDefault()?.Start);
    }

    [GeneratedRegex(@"(https?://|-urlcache|-decode|/transfer|scrobj|javascript:|vbscript:|process\s+call\s+create|\.dll,|/i:)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ArgsRegex();
}

public sealed partial class ShadowCopyDeletionRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-D001",
        Version = "1.0",
        Name = new("Tried to remove system recovery options", "حاول حذف خيارات استعادة النظام"),
        Description = new("A command tried to delete shadow copies, backups or disable Windows recovery. This makes restoring files after damage much harder.", "حاول أمر حذف النسخ الظلية أو النسخ الاحتياطية أو تعطيل استعادة Windows، وهذا يصعّب استرجاع الملفات بعد أي ضرر."),
        Category = FindingCategory.Impact,
        Severity = Severity.Critical,
        Weight = 35,
        AttackTechniques = ["T1490"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var nodes = context.Graph.Nodes.Values
            .Where(n => n.InAnalyzedTree && n.CommandLine is not null && RecoveryRegex().IsMatch(n.CommandLine))
            .OrderBy(n => n.Start).ToList();
        var evidence = nodes.Select(n => new Evidence
        {
            Kind = "command-line",
            Description = new($"{n.Name} ran a recovery-removal command", $"شغّل {n.Name} أمرًا لحذف خيارات الاستعادة"),
            Technical = n.CommandLine,
            EventSequences = [n.StartEventSequence],
        }).ToList();
        return Build(evidence, processes: nodes.Select(n => n.Key), firstSeen: nodes.FirstOrDefault()?.Start);
    }

    [GeneratedRegex(@"(vssadmin(\.exe)?\s+delete\s+shadows|shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+catalog|recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RecoveryRegex();
}
