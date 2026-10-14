using System.Text.RegularExpressions;
using Blazma.Analysis.Rules;
using Blazma.Analysis.Text;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Samples;
using Blazma.Core.Settings;
using Blazma.Core.Text;

namespace Blazma.Analysis.Engine;

public enum InstallerTechnology { None, InnoSetup, Nsis, WindowsInstaller, WixBurn, Squirrel, InstallShield }

/// <summary>Where installers put things, and which files are the installer engine itself rather than what it installs.</summary>
public static partial class InstallerPaths
{
    /// <summary>The plug-ins shipped with NSIS and the common third-party ones, unpacked to %TEMP%\nsXXXX.tmp by every NSIS installer.</summary>
    private static readonly HashSet<string> NsisPlugins = new(StringComparer.OrdinalIgnoreCase)
    {
        "System.dll", "nsDialogs.dll", "nsExec.dll", "StartMenu.dll", "UserInfo.dll", "LangDLL.dll", "InstallOptions.dll", "Banner.dll",
        "NSISdl.dll", "inetc.dll", "INetC.dll", "nsisunz.dll", "ExecDos.dll", "ExecCmd.dll", "nsProcess.dll", "AccessControl.dll", "SimpleSC.dll",
        "ShellLink.dll", "registry.dll", "nsArray.dll", "nsJSON.dll", "ApplicationID.dll", "UAC.dll", "LogEx.dll", "FindProcDLL.dll",
        "KillProcDLL.dll", "Math.dll", "Dialer.dll", "AdvSplash.dll", "Splash.dll", "BgImage.dll", "VPatch.dll", "nsis7z.dll", "md5dll.dll",
        "ZipDLL.dll", "Locate.dll", "WinShell.dll", "ButtonEvent.dll", "nsWindows.dll", "NsisCrypt.dll", "StdUtils.dll", "nsResize.dll",
    };

    /// <summary>Program Files, the folder that only administrators (that is, installers) can write to.</summary>
    public static bool IsInstalledProgramLocation(string? path) =>
        !string.IsNullOrEmpty(path) && ProgramFilesRegex().IsMatch(PathRules.NormalizeFilePath(CommandLines.ExpandMachineVariables(path)));

    /// <summary>A command that starts a program under Program Files and does not hand it anything from a user-writable folder.</summary>
    public static bool IsInstalledProgramCommand(string? command) =>
        !string.IsNullOrWhiteSpace(command) && IsInstalledProgramLocation(CommandLines.ExecutablePath(command)) && !PathRules.IsUserWritableLocation(command);

    /// <summary>A shortcut in the Start menu or on a desktop, which every installer creates (Startup folder shortcuts are persistence, not this).</summary>
    public static bool IsShortcut(string path) =>
        path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)
        && !path.Contains(@"\Start Menu\Programs\Startup\", StringComparison.OrdinalIgnoreCase)
        && (path.Contains(@"\Start Menu\Programs\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\Desktop\", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// A file that belongs to the installer engine rather than to what is installed: Inno Setup's
    /// setup.tmp and helpers, NSIS plug-ins and its uninstaller copy, a WiX bundle's copy of itself,
    /// Squirrel's Update.exe while unpacking, Windows Installer's own working files. Malware hidden
    /// in an installer still has to put its payload somewhere else to run it.
    /// </summary>
    public static bool IsEngineArtifact(string? path, string? sampleFileName)
    {
        if (string.IsNullOrEmpty(path)) return false;
        path = PathRules.NormalizeFilePath(path);
        if (InnoEngineRegex().Match(path) is { Success: true } inno)
            return sampleFileName is null || inno.Groups["name"].Value.Equals(Path.GetFileNameWithoutExtension(sampleFileName), StringComparison.OrdinalIgnoreCase);
        if (InnoHelperRegex().IsMatch(path) || InnoUninstallerRegex().IsMatch(path)) return true;
        if (NsisPluginRegex().Match(path) is { Success: true } nsis) return NsisPlugins.Contains(nsis.Groups["plugin"].Value);
        if (NsisUninstallerRegex().IsMatch(path)) return true;
        if (BurnRegex().Match(path) is { Success: true } burn)
            return sampleFileName is null || burn.Groups["name"].Value.Equals(sampleFileName, StringComparison.OrdinalIgnoreCase);
        return path.Contains(@"\ProgramData\Package Cache\", StringComparison.OrdinalIgnoreCase)
            || SquirrelRegex().IsMatch(path)
            || WindowsInstallerRegex().IsMatch(path);
    }

    internal static bool IsInnoEngine(string? path) => path is not null && InnoEngineRegex().IsMatch(PathRules.NormalizeFilePath(path));
    internal static bool IsNsisPlugin(string? path) => path is not null && NsisPluginRegex().Match(PathRules.NormalizeFilePath(path)) is { Success: true } m && NsisPlugins.Contains(m.Groups["plugin"].Value);
    internal static bool IsSquirrelEngine(string? path) => path is not null && SquirrelRegex().IsMatch(PathRules.NormalizeFilePath(path));

    [GeneratedRegex(@"^[A-Za-z]:\\Program Files( \(x86\))?\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ProgramFilesRegex();

    [GeneratedRegex(@"\\Temp\\is-[A-Z0-9]{5}\.tmp\\(?<name>[^\\]+)\.tmp$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex InnoEngineRegex();

    [GeneratedRegex(@"\\Temp\\is-[A-Z0-9]{5}\.tmp\\_isetup\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex InnoHelperRegex();

    [GeneratedRegex(@"\\Temp\\_iu[A-Z0-9]{5}\.tmp$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex InnoUninstallerRegex();

    [GeneratedRegex(@"\\Temp\\ns[a-z0-9]{3,5}\.tmp\\(?<plugin>[^\\]+\.dll)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex NsisPluginRegex();

    [GeneratedRegex(@"\\Temp\\~nsu[a-z]?\.tmp\\(au_|un_[a-z])\.exe$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex NsisUninstallerRegex();

    [GeneratedRegex(@"\\Temp\\\{[0-9A-F-]{36}\}\\\.(cr|be)\\(?<name>[^\\]+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BurnRegex();

    [GeneratedRegex(@"\\AppData\\Local\\SquirrelTemp\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SquirrelRegex();

    [GeneratedRegex(@"^[A-Za-z]:\\(Windows\\Installer|Config\.Msi)\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex WindowsInstallerRegex();
}

/// <summary>
/// What is known about the sample as an installer: its signature and publisher, whether the
/// user trusts that publisher, and which installer technology built it. Used to weigh the
/// behaviours every installer has (writing programs, running them, adding startup entries and
/// services, going online) for less when nothing stealthy happened alongside them.
/// </summary>
public sealed record InstallerContext(bool SignedValid, string? Publisher, bool TrustedPublisher, InstallerTechnology Technology)
{
    /// <summary>Behaviours installers and updaters normally show. Only these are ever weighed down.</summary>
    private static readonly HashSet<string> InstallerTypical = new(StringComparer.OrdinalIgnoreCase)
    {
        "BLZ-F001", "BLZ-F002", "BLZ-P001", "BLZ-P002", "BLZ-P003", "BLZ-E001", "BLZ-E003",
        "BLZ-N001", "BLZ-N002", "BLZ-N004", "BLZ-N005", "BLZ-C001", "BLZ-S002", "BLZ-S101",
    };

    /// <summary>Stealth, tampering and theft: when any of these is present, nothing is weighed down.</summary>
    private static readonly HashSet<string> Aggravating = new(StringComparer.OrdinalIgnoreCase)
    {
        "BLZ-E004", "BLZ-D001", "BLZ-R001", "BLZ-R003", "BLZ-A001", "BLZ-A002", "BLZ-P004", "BLZ-F003", "BLZ-F004",
        "BLZ-F005", "BLZ-F006", "BLZ-Y001", "BLZ-R101", "BLZ-W001", "BLZ-S102", "BLZ-N007",
    };

    public static InstallerContext None { get; } = new(false, null, false, InstallerTechnology.None);

    /// <summary>How much installer-typical findings count: 1 is unchanged.</summary>
    public double Factor => TrustedPublisher ? 0.2
        : SignedValid ? (Technology == InstallerTechnology.None ? 0.4 : 0.3)
        : Technology == InstallerTechnology.None ? 1.0 : 0.6;

    public static InstallerContext From(RuleContext context)
    {
        var stat = context.Static;
        var signed = stat?.Signature.Status == SignatureStatus.Valid;
        var publisher = signed && !string.IsNullOrWhiteSpace(stat!.Signature.Publisher) ? stat.Signature.Publisher.Trim() : null;
        var trusted = publisher is not null && context.TrustedPublishers.Any(p => string.Equals(p?.Trim(), publisher, StringComparison.OrdinalIgnoreCase));
        return new InstallerContext(signed, publisher, trusted, Detect(context));
    }

    /// <summary>The installer technology, from the file (version information, sections, recognised strings) or from what its engine did at run time.</summary>
    public static InstallerTechnology Detect(RuleContext context)
    {
        var sample = context.Static?.Sample ?? context.Sample;
        if (sample.Kind == FileKind.Msi || sample.Extension == ".msi") return InstallerTechnology.WindowsInstaller;

        var pe = context.Static?.Pe;
        if (pe is not null)
        {
            if (pe.Sections.Any(s => s.Name.Equals(".wixburn", StringComparison.OrdinalIgnoreCase))) return InstallerTechnology.WixBurn;
            if (pe.VersionInfo.Values.Any(v => v.Contains("Inno Setup", StringComparison.OrdinalIgnoreCase))) return InstallerTechnology.InnoSetup;
        }
        var marker = context.Static?.Capabilities.FirstOrDefault(c => c.Id == "CAP-INS-001");
        if (marker is not null)
        {
            var text = string.Join("\n", marker.Evidence);
            if (text.Contains("Nullsoft", StringComparison.OrdinalIgnoreCase)) return InstallerTechnology.Nsis;
            if (text.Contains("Inno Setup", StringComparison.OrdinalIgnoreCase)) return InstallerTechnology.InnoSetup;
            if (text.Contains("WixBundle", StringComparison.OrdinalIgnoreCase) || text.Contains(".wixburn", StringComparison.OrdinalIgnoreCase)) return InstallerTechnology.WixBurn;
            if (text.Contains("Squirrel", StringComparison.OrdinalIgnoreCase)) return InstallerTechnology.Squirrel;
            if (text.Contains("InstallShield", StringComparison.OrdinalIgnoreCase)) return InstallerTechnology.InstallShield;
        }

        // At run time each engine leaves its own trace.
        foreach (var n in context.Graph.Nodes.Values.Where(n => n.InAnalyzedTree))
        {
            if (InstallerPaths.IsInnoEngine(n.ImagePath) && n.CommandLine?.Contains("/SL5=", StringComparison.OrdinalIgnoreCase) == true) return InstallerTechnology.InnoSetup;
            if (InstallerPaths.IsSquirrelEngine(n.ImagePath) && n.CommandLine?.Contains("--install", StringComparison.OrdinalIgnoreCase) == true) return InstallerTechnology.Squirrel;
            if (n.Name.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase)) return InstallerTechnology.WindowsInstaller;
        }
        if (context.Graph.DroppedFiles.Keys.Any(InstallerPaths.IsNsisPlugin)) return InstallerTechnology.Nsis;
        return InstallerTechnology.None;
    }

    /// <summary>
    /// Weighs installer-typical findings down for a signed or recognised installer, and says so in
    /// each finding's explanation. Anything stealthy (hidden commands, tampering, credential or
    /// ransomware behaviour, disguise, self-deletion, signatures, reputation) cancels it, as does a
    /// weight the user set for that rule.
    /// </summary>
    public IReadOnlyList<Finding> Apply(IReadOnlyList<Finding> findings, IReadOnlyDictionary<string, RuleOverride> overrides)
    {
        var factor = Factor;
        if (factor >= 1 || findings.Count == 0 || findings.Any(IsAggravating)) return findings;

        var adjusted = new List<Finding>(findings.Count);
        foreach (var f in findings)
        {
            if (!IsDiscountable(f) || f.Points <= 0 || overrides.TryGetValue(f.RuleId, out var ov) && ov.Weight is not null)
            {
                adjusted.Add(f);
                continue;
            }
            var points = Math.Max(1, (int)Math.Round(f.Points * factor, MidpointRounding.AwayFromZero));
            var cap = factor <= 0.4 ? Severity.Low : Severity.Medium;
            adjusted.Add(f with
            {
                Points = points,
                Severity = f.Severity > cap ? cap : f.Severity,
                Explanation = Explain(f.Explanation, f.Points, points),
            });
        }
        return adjusted.OrderByDescending(f => f.Severity).ThenByDescending(f => f.Points).ToList();
    }

    private bool IsDiscountable(Finding f)
    {
        if (!InstallerTypical.Contains(f.RuleId) && !(f.RuleId is "BLZ-E002" or "BLZ-V001" && f.Severity < Severity.High)) return false;
        // Without a signature, startup entries and services pointing into user folders keep their full weight:
        // that is exactly what an installer-wrapped dropper does.
        if (!SignedValid && f.Category == FindingCategory.Persistence && f.Evidence.Any(e => PathRules.IsUserWritableLocation(e.Technical))) return false;
        return true;
    }

    private static bool IsAggravating(Finding f) =>
        f.Points > 0 && (Aggravating.Contains(f.RuleId) || f.RuleId is "BLZ-E002" or "BLZ-V001" && f.Severity >= Severity.High);

    private LocalizedText Explain(LocalizedText original, int from, int to)
    {
        var tech = TechnologyName(Technology);
        var (en, ar) = TrustedPublisher
            ? ($"the file is signed by {Publisher}, a publisher on your trusted list", $"الملف موقّع من {Publisher}، وهو ناشر في قائمة الناشرين الموثوقين لديك")
            : SignedValid && tech is not null
                ? ($"the file is a {tech} installer with a valid signature from {Publisher}", $"الملف برنامج تثبيت مبني بأداة {tech} ويحمل توقيعًا رقميًا صالحًا من {Publisher}")
                : SignedValid
                    ? ($"the file has a valid digital signature from {Publisher}", $"الملف يحمل توقيعًا رقميًا صالحًا من {Publisher}")
                    : ($"the file is a {tech} installer, but it is not signed, so the reduction is small", $"الملف برنامج تثبيت مبني بأداة {tech}، لكنه غير موقّع، لذا التخفيض محدود");
        return new(
            $"{original.En} Context: {en}, and nothing stealthy was seen. Installers commonly do this, so it counts for less here ({from} → {to} points).",
            $"{original.Ar} السياق: {ar}، ولم يُلاحظ أي سلوك للتخفي. برامج التثبيت تفعل ذلك عادةً، لذا يُحتسب هنا بوزن أقل (من {from} إلى {to} نقاط).");
    }

    public static string? TechnologyName(InstallerTechnology technology) => technology switch
    {
        InstallerTechnology.InnoSetup => "Inno Setup",
        InstallerTechnology.Nsis => "NSIS",
        InstallerTechnology.WindowsInstaller => "Windows Installer (MSI)",
        InstallerTechnology.WixBurn => "WiX",
        InstallerTechnology.Squirrel => "Squirrel",
        InstallerTechnology.InstallShield => "InstallShield",
        _ => null,
    };
}
