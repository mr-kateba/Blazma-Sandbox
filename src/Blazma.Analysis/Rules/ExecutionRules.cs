using System.Text.RegularExpressions;
using Blazma.Analysis.Engine;
using Blazma.Analysis.Text;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Processes;
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
        Version = "1.1",
        Name = new("Ran a hidden or encoded command", "شغّل أمرًا مخفيًا أو مشفّرًا"),
        Description = new("A command line used options that hide the window, bypass script policy, decode Base64 or download and run code. These are typical of attempts to avoid notice.", "استخدم سطر أوامر خيارات تخفي النافذة أو تتجاوز سياسة السكربتات أو تفك ترميز Base64 أو تنزّل وتشغّل أكوادًا. هذه أساليب شائعة لتجنّب الملاحظة."),
        Category = FindingCategory.DefenseEvasion,
        Severity = Severity.High,
        Weight = 15,
        AttackTechniques = ["T1059.001", "T1027"],
    };

    private static readonly LocalizedText PolicyOnly = new(
        "A PowerShell command line switched off the script execution policy for one run, without hiding or encoding anything. Installers and admin scripts often do this, so on its own it counts for little.",
        "عطّل سطر أوامر PowerShell سياسة تشغيل السكربتات لمرة واحدة دون إخفاء أو ترميز أي شيء. برامج التثبيت وسكربتات الإدارة تفعل ذلك كثيرًا، لذا وزنه منفردًا منخفض.");

    public override Finding? Evaluate(RuleContext context)
    {
        var hits = new List<(ProcessNode Node, string Marker, bool Strong)>();
        foreach (var n in context.Graph.Nodes.Values.Where(n => n.InAnalyzedTree && n.CommandLine is not null).OrderBy(n => n.Start))
        {
            var cl = n.CommandLine!;
            // A .ps1 sample is started by the agent with "-NoProfile -ExecutionPolicy Bypass -File": that is the sandbox, not the sample.
            if (n.IsSample) cl = LauncherRegex().Replace(cl, " ");
            var powershell = PowerShellRegex().IsMatch(n.Name) || PowerShellRegex().IsMatch(cl);
            var strong = StrongRegex().Match(cl);
            if (!strong.Success && powershell) strong = PowerShellOnlyRegex().Match(cl);
            if (strong.Success) { hits.Add((n, strong.Value.Trim(), true)); continue; }
            if (powershell && PolicyBypassRegex().Match(cl) is { Success: true } weak) hits.Add((n, weak.Value.Trim(), false));
        }
        if (hits.Count == 0) return null;

        var evidence = hits.Select(h => new Evidence
        {
            Kind = "command-line",
            Description = new($"{h.Node.Name} used: {h.Marker}", $"استخدم {h.Node.Name}: {h.Marker}"),
            Technical = h.Node.CommandLine,
            EventSequences = [h.Node.StartEventSequence],
        }).ToList();
        var processes = hits.Select(h => h.Node.Key);
        if (hits.Any(h => h.Strong)) return Build(evidence, processes: processes, firstSeen: hits[0].Node.Start);
        var weakOnly = Build(evidence, PolicyOnly, processes, hits[0].Node.Start, Severity.Low);
        return weakOnly is null ? null : weakOnly with { Points = 5 };
    }

    /// <summary>Running decoded or downloaded code, in any command line.</summary>
    [GeneratedRegex(@"(\biex\b|invoke-expression|downloadstring|downloadfile|downloaddata|frombase64string|invoke-webrequest.+\|\s*iex)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex StrongRegex();

    /// <summary>Encoded commands and hidden windows, which only mean that for PowerShell (-e and -w are other things elsewhere).</summary>
    [GeneratedRegex(@"(\s[-/](e|ec|en[a-z]*)\s+[A-Za-z0-9+/=]{16,}|\s[-/]w[a-z]*\s+(hidden|h|1)\b)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PowerShellOnlyRegex();

    [GeneratedRegex(@"[-/](ep|ex|exec|executionpolicy)\s+(bypass|unrestricted)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PolicyBypassRegex();

    [GeneratedRegex(@"\b(powershell|pwsh)(\.exe)?\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PowerShellRegex();

    [GeneratedRegex(@"\s-NoProfile\s+-ExecutionPolicy\s+Bypass\s+-File\s+""[^""]*""\s*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LauncherRegex();
}

public sealed partial class ProxyExecutionRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-E003",
        Version = "1.1",
        Name = new("Used a built-in Windows tool to run or fetch code", "استخدم أداة مدمجة في Windows لتشغيل أو جلب أكواد"),
        Description = new("A trusted Windows program (such as rundll32, regsvr32, mshta or certutil) was used in a way that runs or downloads code. This can hide activity behind a legitimate name.", "استُخدم برنامج موثوق من Windows (مثل rundll32 أو regsvr32 أو mshta أو certutil) بطريقة تشغّل أو تنزّل أكوادًا، وهذا قد يخفي النشاط خلف اسم سليم."),
        Category = FindingCategory.DefenseEvasion,
        Severity = Severity.Medium,
        Weight = 12,
        AttackTechniques = ["T1218"],
    };

    /// <summary>Entry points installers and Windows itself call through rundll32 (INF installs, printer and control panel set-up).</summary>
    private static readonly HashSet<string> BenignRundllEntries = new(StringComparer.OrdinalIgnoreCase)
    {
        "InstallHinfSection", "LaunchINFSection", "LaunchINFSectionEx", "PrintUIEntry", "Control_RunDLL", "Control_RunDLLAsUser", "SHCreateLocalServerRunDll", "OpenAs_RunDLL", "ImageView_Fullscreen",
    };

    public override Finding? Evaluate(RuleContext context)
    {
        // Downloads through these tools are reported by BLZ-E004, once.
        var nodes = context.Graph.Nodes.Values
            .Where(n => n.InAnalyzedTree && !n.IsSample && ProcessNames.ProxyBinaries.Contains(n.Name) && !LolbinDownloadRule.IsDownload(n)
                        && (n.Name.Equals("mshta.exe", StringComparison.OrdinalIgnoreCase) || (n.CommandLine is not null && ArgsRegex().IsMatch(n.CommandLine) && !IsBenignRundll(n))))
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

    /// <summary>rundll32 loading a library of a program installed under Program Files, or a Windows set-up entry point, with nothing from a user folder.</summary>
    private static bool IsBenignRundll(ProcessNode n)
    {
        if (!n.Name.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase) || n.CommandLine is not { } cl) return false;
        if (PathRules.IsUserWritableLocation(cl) || cl.Contains("://", StringComparison.Ordinal) || cl.Contains("script:", StringComparison.OrdinalIgnoreCase)) return false;
        if (RundllRegex().Match(cl) is not { Success: true } m) return false;
        return InstallerPaths.IsInstalledProgramLocation(m.Groups["dll"].Value) || BenignRundllEntries.Contains(m.Groups["entry"].Value);
    }

    [GeneratedRegex(@"(https?://|-urlcache|-decode|/transfer|scrobj|javascript:|vbscript:|process\s+call\s+create|\.dll""?\s*,)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ArgsRegex();

    [GeneratedRegex(@"rundll32(\.exe)?""?\s+""?(?<dll>[^"",]+?\.dll)""?\s*,\s*(?<entry>[#\w]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RundllRegex();
}

/// <summary>Windows tools that were never meant to download, pointed at an internet address.</summary>
public sealed partial class LolbinDownloadRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-E004",
        Version = "1.0",
        Name = new("Downloaded a file with a built-in Windows tool", "نزّل ملفًا بأداة مدمجة في Windows"),
        Description = new("A Windows tool that is not meant for downloading (such as certutil, bitsadmin, mshta, regsvr32 or msiexec) was pointed at an internet address. Attackers use these trusted programs to fetch their next stage without bringing a downloader of their own.",
            "وُجّهت أداة من Windows ليست مخصّصة للتنزيل (مثل certutil أو bitsadmin أو mshta أو regsvr32 أو msiexec) إلى عنوان على الإنترنت. يستخدم المهاجمون هذه البرامج الموثوقة لجلب المرحلة التالية دون أن يحضروا أداة تنزيل خاصة بهم."),
        Category = FindingCategory.Execution,
        Severity = Severity.High,
        Weight = 15,
        AttackTechniques = ["T1105", "T1218", "T1197"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var nodes = context.Graph.Nodes.Values.Where(n => n.InAnalyzedTree && !n.IsSample && IsDownload(n)).OrderBy(n => n.Start).ToList();
        var evidence = nodes.Select(n => new Evidence
        {
            Kind = "command-line",
            Description = new($"{n.Name} was used to fetch {Url(n.CommandLine!) ?? "a remote file"}", $"استُخدم {n.Name} لجلب {Url(n.CommandLine!) ?? "ملف بعيد"}"),
            Technical = n.CommandLine,
            EventSequences = [n.StartEventSequence],
        }).ToList();
        return Build(evidence, processes: nodes.Select(n => n.Key), firstSeen: nodes.FirstOrDefault()?.Start);
    }

    internal static bool IsDownload(ProcessNode n)
    {
        if (n.CommandLine is not { } cl) return false;
        var remote = RemoteRegex().IsMatch(cl);
        return n.Name.ToLowerInvariant() switch
        {
            "certutil.exe" => remote || CertutilRegex().IsMatch(cl),
            "bitsadmin.exe" => remote || BitsadminRegex().IsMatch(cl),
            "mshta.exe" or "hh.exe" or "msiexec.exe" or "curl.exe" or "wget.exe" or "certreq.exe" => remote,
            "regsvr32.exe" => Regsvr32Regex().IsMatch(cl),
            "desktopimgdownldr.exe" => cl.Contains("/lockscreenurl:", StringComparison.OrdinalIgnoreCase),
            "mpcmdrun.exe" => cl.Contains("-DownloadFile", StringComparison.OrdinalIgnoreCase) && remote,
            "esentutl.exe" or "expand.exe" or "extrac32.exe" => cl.Contains(@"\\", StringComparison.Ordinal) && cl.Contains('@', StringComparison.Ordinal),
            "powershell.exe" or "pwsh.exe" => remote && cl.Contains("Start-BitsTransfer", StringComparison.OrdinalIgnoreCase),
            _ => false,
        };
    }

    private static string? Url(string commandLine) => UrlRegex().Match(commandLine) is { Success: true } m ? m.Value : null;

    [GeneratedRegex(@"(https?|ftp)://", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RemoteRegex();

    [GeneratedRegex(@"(https?|ftp)://[^\s""']+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"[-/](urlcache|verifyctl)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CertutilRegex();

    [GeneratedRegex(@"/(transfer|addfile|download)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BitsadminRegex();

    [GeneratedRegex(@"/i:\s*""?((https?|ftp)://|\\\\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Regsvr32Regex();
}

public sealed partial class ShadowCopyDeletionRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-D001",
        Version = "1.1",
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
        // System Restore switched off through its policy or settings key.
        var registry = context.TreeEvents.Where(e => e.Action == EventAction.RegistryValueSet && e.Target is not null
                && SystemRestoreRegex().IsMatch(PathRules.NormalizeRegistryKey(e.Target))
                && e.Detail(DetailKeys.ValueName) is "DisableSR" or "DisableConfig" && e.Detail(DetailKeys.ValueData)?.Trim() is "1" or "0x1" or "0x00000001")
            .ToList();
        var evidence = nodes.Select(n => new Evidence
        {
            Kind = "command-line",
            Description = new($"{n.Name} ran a recovery-removal command", $"شغّل {n.Name} أمرًا لحذف خيارات الاستعادة"),
            Technical = n.CommandLine,
            EventSequences = [n.StartEventSequence],
        }).Concat(registry.Select(e => EventEvidence("registry", e, new($"{e.ProcessName} turned System Restore off", $"أوقف {e.ProcessName} استعادة النظام"),
            $"{e.Target}\\{e.Detail(DetailKeys.ValueName)} = {e.Detail(DetailKeys.ValueData)}"))).ToList();
        return Build(evidence, processes: nodes.Select(n => n.Key), firstSeen: nodes.Select(n => n.Start).Concat(registry.Select(e => e.RelativeTime)).DefaultIfEmpty().Min());
    }

    [GeneratedRegex(@"(vssadmin(\.exe)?""?\s+(delete\s+shadows|resize\s+shadowstorage)|shadowcopy\s+delete|win32_shadowcopy\b.*(\.delete\(|remove-(wmiobject|ciminstance))|wbadmin(\.exe)?""?\s+delete\s+(catalog|systemstatebackup|backup)|recoveryenabled\s+""?(no|off|false|0)\b|bootstatuspolicy\s+""?ignoreallfailures|reagentc(\.exe)?""?\s+/disable|delete\s+shadows\s+all)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RecoveryRegex();

    [GeneratedRegex(@"\\(Policies\\Microsoft\\Windows NT|Microsoft\\Windows NT\\CurrentVersion)\\SystemRestore$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SystemRestoreRegex();
}

/// <summary>
/// Reaching for stored passwords: dumping LSASS memory, saving the SAM or SECURITY hives, or
/// copying a browser's saved logins and cookies. The agent does not record file reads, so this
/// looks at commands and at copies of those files appearing elsewhere.
/// </summary>
public sealed partial class CredentialAccessRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-A001",
        Version = "1.0",
        Name = new("Tried to collect saved passwords", "حاول جمع كلمات المرور المحفوظة"),
        Description = new("The program tried to read where Windows or a web browser keeps passwords: it dumped the memory of LSASS (the Windows sign-in process), saved the SAM or SECURITY part of the registry, or copied a browser's saved logins or cookies. Legitimate software does not do this.",
            "حاول البرنامج قراءة المكان الذي يحفظ فيه Windows أو المتصفح كلمات المرور: نسخ ذاكرة LSASS (عملية تسجيل الدخول في Windows)، أو حفظ جزء SAM أو SECURITY من السجل، أو نسخ كلمات المرور أو ملفات تعريف الارتباط المحفوظة في المتصفح. البرامج السليمة لا تفعل ذلك."),
        Category = FindingCategory.CredentialAccess,
        Severity = Severity.Critical,
        Weight = 35,
        AttackTechniques = ["T1003.001", "T1003.002", "T1555.003", "T1539"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var commands = context.Graph.Nodes.Values
            .Where(n => n.InAnalyzedTree && n.CommandLine is { } cl && (DumpRegex().IsMatch(cl) || HiveRegex().IsMatch(cl) || (BrowserStoreRegex().IsMatch(cl) && CopyRegex().IsMatch(cl))))
            .OrderBy(n => n.Start).ToList();
        // A browser's own profile folder is where these files belong; a copy anywhere else was taken.
        var copies = context.TreeEvents
            .Where(e => e.Action is EventAction.FileCreate or EventAction.FileWrite && e.Target is not null
                        && BrowserStoreRegex().IsMatch(PathRules.FileName(e.Target)) && !IsBrowserProfile(PathRules.NormalizeFilePath(e.Target)))
            .GroupBy(e => PathRules.NormalizeFilePath(e.Target!), StringComparer.OrdinalIgnoreCase).Select(g => g.First())
            .Take(10).ToList();

        var evidence = commands.Select(n => new Evidence
            {
                Kind = "command-line",
                Description = new($"{n.Name} ran a command that reads stored credentials", $"شغّل {n.Name} أمرًا يقرأ بيانات الدخول المحفوظة"),
                Technical = n.CommandLine,
                EventSequences = [n.StartEventSequence],
            })
            .Concat(copies.Select(e => EventEvidence("file", e, new($"{e.ProcessName} made a copy of the browser file {PathRules.FileName(e.Target)}", $"نسخ {e.ProcessName} ملف المتصفح {PathRules.FileName(e.Target)}"))))
            .ToList();
        return Build(evidence, processes: commands.Select(n => n.Key),
            firstSeen: evidence.Count == 0 ? null : commands.Select(n => n.Start).Concat(copies.Select(e => e.RelativeTime)).Min());
    }

    private static bool IsBrowserProfile(string path) => BrowserProfileRegex().IsMatch(path);

    [GeneratedRegex(@"(\blsass(\.exe|\.dmp)?\b.*(?<![\w-])(-ma|minidump|full)\b|(?<![\w-])(-ma|minidump)\b.*\blsass\b|comsvcs(\.dll)?""?\s*,?\s*#?(minidump|24)\b|sekurlsa::|lsadump::|\bmimikatz\b|\bntdsutil\b.*\bifm\b)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DumpRegex();

    [GeneratedRegex(@"\breg(\.exe)?""?\s+(save|export)\s+""?hklm\\(sam|security|system)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HiveRegex();

    [GeneratedRegex(@"(Login Data|Web Data|Cookies|logins\.json|key4\.db|cookies\.sqlite|Local State)(\b|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BrowserStoreRegex();

    [GeneratedRegex(@"\b(copy|xcopy|robocopy|copy-item|cp|esentutl|move|move-item)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CopyRegex();

    [GeneratedRegex(@"\\AppData\\(Local|Roaming)\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Opera Software|Vivaldi|Yandex\\YandexBrowser|Mozilla\\Firefox)\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BrowserProfileRegex();
}
