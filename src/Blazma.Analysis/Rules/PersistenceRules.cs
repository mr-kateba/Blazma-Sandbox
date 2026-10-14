using Blazma.Analysis.Engine;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Processes;
using Blazma.Core.Text;

namespace Blazma.Analysis.Rules;

/// <summary>Shared logic: one finding per persistence technique group, attributed to the analyzed tree.</summary>
public abstract class PersistenceRule : Rule
{
    protected abstract IReadOnlySet<PersistenceTechnique> Techniques { get; }

    /// <summary>
    /// Whether an entry that starts a program installed under Program Files counts for less. Only
    /// installers (running as administrator) can put a program there, and installed applications
    /// routinely start with Windows, keep a service or schedule their updater.
    /// </summary>
    protected virtual bool ReducedForInstalledPrograms => true;

    public override Finding? Evaluate(RuleContext context)
    {
        // System processes acting outside the tree only count when they point at something the tree dropped.
        var hits = context.Persistence
            .Where(p => Techniques.Contains(p.Technique) && (p.ByAnalyzedTree || p.PointsToDroppedFile))
            .ToList();
        if (hits.Count == 0) return null;

        var evidence = hits.Select(p => new Evidence
        {
            Kind = "persistence",
            Description = new LocalizedText(
                $"{PersistenceCatalog.Name(p.Technique).En} created by {p.ProcessName}" + (p.PointsToDroppedFile ? ", pointing to a file created during the analysis" : string.Empty),
                $"{PersistenceCatalog.Name(p.Technique).Ar} أنشأه {p.ProcessName}" + (p.PointsToDroppedFile ? "، ويشير إلى ملف أُنشئ أثناء التحليل" : string.Empty)),
            Technical = p.Value is null ? p.Target : $"{p.Target} = {p.Value}",
            EventSequences = p.EventSequences,
        }).ToList();

        var processes = hits.Where(h => h.Process is not null).Select(h => h.Process!.Value);
        var explanation = PersistenceCatalog.Explain(hits[0].Technique);
        if (ReducedForInstalledPrograms && hits.All(h => InstallerPaths.IsInstalledProgramCommand(h.Value)))
        {
            var reduced = Build(evidence, new LocalizedText(
                explanation.En + " It starts a program installed under Program Files, a folder only administrators can change. Installed applications commonly start this way, so it counts for less.",
                explanation.Ar + " ويشغّل برنامجًا مثبّتًا داخل مجلد Program Files، وهو مجلد لا يعدّله إلا المسؤول. التطبيقات المثبّتة تبدأ بهذه الطريقة عادةً، لذا يُحتسب بوزن أقل."),
                processes, hits.Min(h => h.Time), Severity.Low);
            return reduced is null ? null : reduced with { Points = Math.Max(1, (int)Math.Round(Metadata.Weight / 3.0, MidpointRounding.AwayFromZero)) };
        }

        var severity = hits.Any(h => h.PointsToDroppedFile) && Metadata.Severity < Severity.High ? Severity.High : Metadata.Severity;
        return Build(evidence, explanation, processes, hits.Min(h => h.Time), severity);
    }
}

public sealed class StartupPersistenceRule : PersistenceRule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-P001",
        Version = "1.0",
        Name = new("Created startup persistence", "أنشأ آلية تشغيل تلقائي عند الدخول"),
        Description = new("The program configured itself (or another program) to start automatically when the user signs in.", "ضبط البرنامج نفسه أو برنامجًا آخر ليعمل تلقائيًا عند تسجيل دخول المستخدم."),
        Category = FindingCategory.Persistence,
        Severity = Severity.High,
        Weight = 20,
        AttackTechniques = ["T1547.001"],
    };

    protected override IReadOnlySet<PersistenceTechnique> Techniques { get; } =
        new HashSet<PersistenceTechnique> { PersistenceTechnique.RunKey, PersistenceTechnique.StartupFolder, PersistenceTechnique.ActiveSetup };
}

public sealed class ScheduledTaskRule : PersistenceRule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-P002",
        Version = "1.0",
        Name = new("Created a scheduled task", "أنشأ مهمة مجدولة"),
        Description = new("The program created a scheduled task that can run code later without user action.", "أنشأ البرنامج مهمة مجدولة يمكنها تشغيل أوامر لاحقًا دون تدخل المستخدم."),
        Category = FindingCategory.Persistence,
        Severity = Severity.Medium,
        Weight = 10,
        AttackTechniques = ["T1053.005"],
    };

    protected override IReadOnlySet<PersistenceTechnique> Techniques { get; } = new HashSet<PersistenceTechnique> { PersistenceTechnique.ScheduledTask };
}

public sealed class ServiceInstallRule : PersistenceRule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-P003",
        Version = "1.0",
        Name = new("Installed a Windows service", "ثبّت خدمة Windows"),
        Description = new("The program registered a service, which can start with Windows and run with high privileges.", "سجّل البرنامج خدمة يمكن أن تبدأ مع Windows وتعمل بصلاحيات عالية."),
        Category = FindingCategory.Persistence,
        Severity = Severity.Medium,
        Weight = 14,
        AttackTechniques = ["T1543.003"],
    };

    protected override IReadOnlySet<PersistenceTechnique> Techniques { get; } = new HashSet<PersistenceTechnique> { PersistenceTechnique.Service };
}

public sealed class SystemHijackRule : PersistenceRule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-P004",
        Version = "1.0",
        Name = new("Changed how Windows launches programs", "غيّر طريقة تشغيل Windows للبرامج"),
        Description = new("The program changed Winlogon, execution redirects (IFEO) or AppInit libraries. Legitimate software rarely touches these.", "غيّر البرنامج إعدادات Winlogon أو تحويل التشغيل (IFEO) أو مكتبات AppInit. البرامج السليمة نادرًا ما تلمس هذه الإعدادات."),
        Category = FindingCategory.Persistence,
        Severity = Severity.Critical,
        Weight = 30,
        AttackTechniques = ["T1547.004", "T1546.012", "T1546.010"],
    };

    protected override bool ReducedForInstalledPrograms => false;

    protected override IReadOnlySet<PersistenceTechnique> Techniques { get; } = new HashSet<PersistenceTechnique>
    {
        PersistenceTechnique.WinlogonHelper, PersistenceTechnique.ImageFileExecutionOptions, PersistenceTechnique.AppInitDlls,
    };
}
