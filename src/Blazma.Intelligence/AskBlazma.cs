using System.Globalization;
using Blazma.Analysis.Engine;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Processes;

namespace Blazma.Intelligence;

public enum QuestionIntent { Summary, Score, Changes, Persistence, Network, Processes, Files, Specific, Unknown }

/// <summary>One paragraph of an answer, labelled with where it comes from.</summary>
public sealed record AnswerPart(string Text, Provenance Provenance, IReadOnlyList<long> EventSequences, IReadOnlyList<string> FindingIds);

public sealed record AskAnswer(QuestionIntent Intent, IReadOnlyList<AnswerPart> Parts)
{
    public string Text => string.Join("\n\n", Parts.Select(p => p.Text));
}

/// <summary>
/// Answers questions about one analysis using only its recorded data. It never invents:
/// if the data does not contain an answer, it says so. Facts and rule-based conclusions
/// are labelled separately.
/// </summary>
public sealed class AskBlazma
{
    public static IReadOnlyList<string> SuggestedQuestions(string language) => IsArabic(language)
        ? ["ماذا فعل هذا البرنامج؟", "لماذا الدرجة مرتفعة؟", "هل أنشأ آلية بقاء؟", "أي عملية اتصلت بالإنترنت؟", "ما الذي تغيّر في النظام؟"]
        : ["What did this program do?", "Why is the score high?", "Did it create persistence?", "Which process connected to the internet?", "What did this program change?"];

    public AskAnswer Ask(AnalysisResult result, string question, string language)
    {
        var ar = IsArabic(language);
        var intent = Classify(question);
        if (intent == QuestionIntent.Unknown && FindSpecific(result, question) is { } term) intent = QuestionIntent.Specific;

        IReadOnlyList<AnswerPart> parts = intent switch
        {
            QuestionIntent.Score => Score(result, ar),
            QuestionIntent.Changes => Changes(result, ar),
            QuestionIntent.Persistence => Persistence(result, ar),
            QuestionIntent.Network => Network(result, ar),
            QuestionIntent.Processes => Processes(result, ar),
            QuestionIntent.Files => Files(result, ar),
            QuestionIntent.Specific => Specific(result, FindSpecific(result, question)!, ar),
            QuestionIntent.Summary => Summary(result, ar),
            _ => [new AnswerPart(ar
                ? "أستطيع الإجابة فقط من بيانات هذا التحليل. جرّب سؤالًا عن الدرجة، أو التغييرات، أو آليات البقاء، أو الشبكة، أو العمليات، أو الملفات، أو اكتب اسم عملية أو نطاق."
                : "I can only answer from this analysis. Try asking about the score, changes, persistence, network, processes or files, or type a process or domain name.",
                Provenance.ObservedFact, [], [])],
        };
        return new AskAnswer(intent, parts);
    }

    public static QuestionIntent Classify(string question)
    {
        var q = question.ToLowerInvariant();
        bool Has(params string[] words) => words.Any(q.Contains);

        if (Has("why", "score", "rating", "لماذا", "ليش", "ليه", "درجة", "الدرجة", "تقييم", "خطورة")) return QuestionIntent.Score;
        if (Has("persist", "startup", "reboot", "restart", "autorun", "بقاء", "بدء التشغيل", "إعادة التشغيل", "اعادة التشغيل", "تلقائي")) return QuestionIntent.Persistence;
        if (Has("internet", "network", "connect", "domain", "dns", " ip", "online", "شبكة", "انترنت", "إنترنت", "اتصل", "اتصال", "نطاق", "دومين")) return QuestionIntent.Network;
        if (Has("change", "modif", "registry", "تغيير", "غيّر", "غير", "عدّل", "عدل", "تغير", "تغيّر")) return QuestionIntent.Changes;
        if (Has("process", "child", "spawn", "عملية", "عمليات", "العمليات")) return QuestionIntent.Processes;
        if (Has("file", "drop", "wrote", "ملف", "ملفات", "الملفات")) return QuestionIntent.Files;
        if (Has("what", "summar", "happen", "do?", "ماذا", "ملخص", "شو", "ايش", "إيش", "وش", "صار")) return QuestionIntent.Summary;
        return QuestionIntent.Unknown;
    }

    private static string? FindSpecific(AnalysisResult r, string question)
    {
        var words = question.Split([' ', '?', '؟', ',', '"', '\''], StringSplitOptions.RemoveEmptyEntries).Where(w => w.Length >= 3).ToList();
        foreach (var w in words)
        {
            if (r.AllProcesses.Any(p => p.Name.Contains(w, StringComparison.OrdinalIgnoreCase))) return w;
            if (r.Events.Any(e => e.Target?.Contains(w, StringComparison.OrdinalIgnoreCase) == true)) return w;
        }
        return null;
    }

    private static List<AnswerPart> Score(AnalysisResult r, bool ar)
    {
        var parts = new List<AnswerPart>();
        var verdict = Verdict(r.Risk.Verdict, ar);
        if (r.Risk.Contributions.Count == 0)
        {
            parts.Add(new(ar ? $"الدرجة {r.Risk.Score} من 100 ({verdict}). لم تنطبق أي قاعدة كشف على السلوك الذي تمت ملاحظته."
                             : $"The score is {r.Risk.Score}/100 ({verdict}). No detection rule matched the observed behavior.", Provenance.RuleInference, [], []));
            return parts;
        }

        var top = r.Risk.Contributions.Where(c => c.Points > 0).Take(5).ToList();
        var list = string.Join(ar ? "، " : ", ", top.Select(c => $"{c.Title.Get(ar ? "ar" : "en")} (+{c.Points})"));
        var combined = top.Count > 1;
        parts.Add(new(ar
                ? $"الدرجة {r.Risk.Score} من 100 ({verdict}). " + (combined ? "جاءت من مجموعة سلوكيات مترابطة وليس من حدث منفرد: " : "السبب: ") + list + "."
                : $"The score is {r.Risk.Score}/100 ({verdict}). " + (combined ? "It comes from several related behaviors, not a single event: " : "It comes from: ") + list + ".",
            Provenance.RuleInference, [], top.Select(c => c.FindingId).ToList()));

        if (r.Findings.Any(f => f.Category == FindingCategory.Sequence))
            parts.Add(new(ar ? "جزء من الدرجة يأتي من تسلسل كامل: إنشاء ملف ثم تشغيله ثم تثبيته ثم الاتصال بالخارج. كل خطوة وحدها قد تكون طبيعية."
                             : "Part of the score comes from a complete sequence: a file was created, run, made persistent, and contacted the internet. Each step alone can be normal.",
                Provenance.RuleInference, [], r.Findings.Where(f => f.Category == FindingCategory.Sequence).Select(f => f.Id).ToList()));

        parts.Add(new(ar ? Core.Findings.RiskAssessment.DisclaimerAr : Core.Findings.RiskAssessment.Disclaimer, Provenance.RuleInference, [], []));
        return parts;
    }

    private static List<AnswerPart> Persistence(AnalysisResult r, bool ar)
    {
        var relevant = r.Persistence.Where(p => p.ByAnalyzedTree || p.PointsToDroppedFile).ToList();
        if (relevant.Count == 0)
            return [new(ar ? "لم يُلاحظ أي محاولة بقاء (بدء تشغيل، مهمة مجدولة، خدمة) من البرنامج أو العمليات التابعة له أثناء التحليل."
                           : "No persistence attempt (startup entry, scheduled task, service) was observed from the program or its child processes during the analysis.",
                Provenance.ObservedFact, [], [])];

        return relevant.Select(p => new AnswerPart(ar
                ? $"نعم: {PersistenceNames.Of(p.Technique).Ar} بواسطة {p.ProcessName} عند {Time(p.Time)}. الهدف: {p.Target}" + (p.Value is null ? "" : $" = {p.Value}") + (p.PointsToDroppedFile ? ". يشير إلى ملف أُنشئ أثناء التحليل." : ".")
                : $"Yes: {PersistenceNames.Of(p.Technique).En} by {p.ProcessName} at {Time(p.Time)}. Target: {p.Target}" + (p.Value is null ? "" : $" = {p.Value}") + (p.PointsToDroppedFile ? ". It points to a file created during the analysis." : "."),
            Provenance.ObservedFact, p.EventSequences, [])).ToList();
    }

    private static List<AnswerPart> Network(AnalysisResult r, bool ar)
    {
        var map = NetworkMap.Build(r.Events);
        var connects = r.Events.Where(e => e.Action == EventAction.NetworkConnect).ToList();
        var dns = r.Events.Where(e => e.Action == EventAction.DnsQuery).ToList();
        var parts = new List<AnswerPart>();
        if (connects.Count == 0 && dns.Count == 0)
            return [new(ar ? "لم يُلاحظ أي نشاط شبكة من البرنامج أو العمليات التابعة له." : "No network activity was observed from the program or its child processes.", Provenance.ObservedFact, [], [])];

        foreach (var g in connects.GroupBy(e => e.ProcessName).Take(6))
        {
            var endpoints = g.Select(e => map.DomainFor(e.Detail(DetailKeys.RemoteAddress)) is { } d ? $"{d} ({NetworkMap.Endpoint(e)})" : NetworkMap.Endpoint(e)).Distinct().Take(5);
            parts.Add(new(ar ? $"{g.Key} اتصل بـ: {string.Join("، ", endpoints)}." : $"{g.Key} connected to: {string.Join(", ", endpoints)}.",
                Provenance.ObservedFact, g.Select(e => e.Sequence).Take(20).ToList(), []));
        }
        if (dns.Count > 0)
        {
            var names = dns.Select(e => e.Detail(DetailKeys.QueryName) ?? e.Target).Distinct(StringComparer.OrdinalIgnoreCase).Take(8);
            parts.Add(new(ar ? $"استعلامات DNS: {string.Join("، ", names)}." : $"DNS lookups: {string.Join(", ", names)}.", Provenance.ObservedFact, dns.Select(e => e.Sequence).Take(20).ToList(), []));
        }
        if (r.Options.Network == NetworkPolicy.Disabled)
            parts.Add(new(ar ? "كانت الشبكة معطّلة داخل البيئة المعزولة، لذا هذه محاولات ولم يصل أي اتصال فعليًا." : "Networking was disabled in the sandbox, so these were attempts; no connection actually left the environment.", Provenance.ObservedFact, [], []));
        return parts;
    }

    private static List<AnswerPart> Changes(AnalysisResult r, bool ar)
    {
        var parts = new List<AnswerPart>();
        if (r.SystemChanges is { } sc)
        {
            parts.Add(new(ar
                    ? $"بمقارنة النظام قبل وبعد: الملفات +{sc.FilesCreated.Count} أُنشئت، ~{sc.FilesModified.Count} عُدّلت، −{sc.FilesDeleted.Count} حُذفت. Registry: +{sc.RegistryAdded.Count}، ~{sc.RegistryModified.Count}. خدمات +{sc.ServicesAdded.Count}، مهام +{sc.TasksAdded.Count}، بدء تشغيل +{sc.StartupAdded.Count}."
                    : $"Comparing the system before and after: files +{sc.FilesCreated.Count} created, ~{sc.FilesModified.Count} modified, -{sc.FilesDeleted.Count} deleted. Registry: +{sc.RegistryAdded.Count}, ~{sc.RegistryModified.Count}. Services +{sc.ServicesAdded.Count}, tasks +{sc.TasksAdded.Count}, startup +{sc.StartupAdded.Count}.",
                Provenance.ObservedFact, [], []));
        }
        var writes = r.Events.Where(e => e.Action is EventAction.FileCreate or EventAction.RegistryValueSet).ToList();
        if (writes.Count > 0)
        {
            var files = r.Events.Count(e => e.Category == EventCategory.File && e.Action is EventAction.FileCreate or EventAction.FileWrite);
            var reg = r.Events.Count(e => e.Action == EventAction.RegistryValueSet);
            parts.Add(new(ar ? $"خلال التشغيل سُجّلت {files} عملية كتابة ملفات و{reg} تعديل في Registry من العمليات المحلَّلة." : $"During the run, {files} file writes and {reg} registry value changes were recorded from the analyzed processes.",
                Provenance.ObservedFact, writes.Select(e => e.Sequence).Take(20).ToList(), []));
        }
        if (parts.Count == 0)
            parts.Add(new(ar ? "لم تُسجّل أي تغييرات على النظام." : "No system changes were recorded.", Provenance.ObservedFact, [], []));
        parts.AddRange(Persistence(r, ar).Where(p => p.EventSequences.Count > 0));
        return parts;
    }

    private static List<AnswerPart> Processes(AnalysisResult r, bool ar)
    {
        var tree = r.AllProcesses.Where(p => p.InAnalyzedTree).OrderBy(p => p.Start).ToList();
        if (tree.Count == 0)
            return [new(ar ? "لم تُسجّل أي عملية للبرنامج." : "No processes were recorded for the program.", Provenance.ObservedFact, [], [])];
        var lines = tree.Take(12).Select(p => $"{p.Name} (PID {p.Pid}, {Time(p.Start)})" + (p.ImageDroppedDuringAnalysis ? (ar ? " [أُنشئ أثناء التحليل]" : " [created during analysis]") : ""));
        return [new(ar ? $"شغّل البرنامج {tree.Count} عملية: {string.Join("، ", lines)}." : $"The program ran {tree.Count} process(es): {string.Join(", ", lines)}.",
            Provenance.ObservedFact, tree.Select(p => p.StartEventSequence).ToList(), [])];
    }

    private static List<AnswerPart> Files(AnalysisResult r, bool ar)
    {
        var created = r.Events.Where(e => e.Action == EventAction.FileCreate).ToList();
        if (created.Count == 0)
            return [new(ar ? "لم يُنشئ البرنامج أي ملفات أثناء التحليل." : "The program did not create any files during the analysis.", Provenance.ObservedFact, [], [])];
        var exe = created.Where(e => Analysis.Text.PathRules.IsExecutablePath(e.Target)).ToList();
        var parts = new List<AnswerPart>
        {
            new(ar ? $"أنشأ {created.Count} ملفًا، منها {exe.Count} ملفات تنفيذية أو سكربتات." : $"It created {created.Count} file(s), {exe.Count} of them executables or scripts.", Provenance.ObservedFact, created.Select(e => e.Sequence).Take(20).ToList(), []),
        };
        if (exe.Count > 0)
            parts.Add(new(string.Join("\n", exe.Take(8).Select(e => $"• {e.ProcessName} → {e.Target}")), Provenance.ObservedFact, exe.Select(e => e.Sequence).Take(20).ToList(), []));
        return parts;
    }

    private static List<AnswerPart> Specific(AnalysisResult r, string term, bool ar)
    {
        var events = r.Events.Where(e => e.ProcessName.Contains(term, StringComparison.OrdinalIgnoreCase) || e.Target?.Contains(term, StringComparison.OrdinalIgnoreCase) == true).ToList();
        var byAction = events.GroupBy(e => e.Action).Select(g => $"{g.Key} ×{g.Count()}");
        var first = events.FirstOrDefault();
        return [new(ar
                ? $"وُجد \"{term}\" في {events.Count} حدثًا ({string.Join("، ", byAction)}). أول ظهور عند {Time(first?.RelativeTime ?? TimeSpan.Zero)}."
                : $"\"{term}\" appears in {events.Count} event(s) ({string.Join(", ", byAction)}). First seen at {Time(first?.RelativeTime ?? TimeSpan.Zero)}.",
            Provenance.ObservedFact, events.Select(e => e.Sequence).Take(30).ToList(), [])];
    }

    private static List<AnswerPart> Summary(AnalysisResult r, bool ar)
    {
        var parts = new List<AnswerPart>();
        var procs = r.AllProcesses.Count(p => p.InAnalyzedTree);
        var drops = r.Events.Count(e => e.Action == EventAction.FileCreate && Analysis.Text.PathRules.IsExecutablePath(e.Target));
        var conns = r.Events.Count(e => e.Action == EventAction.NetworkConnect);
        var persist = r.Persistence.Count(p => p.ByAnalyzedTree || p.PointsToDroppedFile);
        parts.Add(new(ar
                ? $"شُغّل {r.Sample.FileName} لمدة {r.Options.Duration.TotalSeconds:0} ثانية. شغّل {procs} عملية، وأنشأ {drops} ملفًا تنفيذيًا، وحاول {conns} اتصالًا، وأنشأ {persist} آلية بقاء."
                : $"{r.Sample.FileName} ran for {r.Options.Duration.TotalSeconds:0} seconds. It started {procs} process(es), created {drops} executable file(s), attempted {conns} connection(s) and created {persist} persistence mechanism(s).",
            Provenance.ObservedFact, [], []));
        foreach (var chain in r.Chains.Where(c => c.Severity >= Severity.Medium).Take(3))
            parts.Add(new(string.Join(ar ? " ← " : " → ", chain.Steps.Select(s => Step(s, ar))), Provenance.ObservedFact, chain.Steps.Select(s => s.EventSequence).ToList(), []));
        parts.AddRange(Score(r, ar).Take(1));
        return parts;
    }

    private static string Step(ChainStep s, bool ar) => (s.Kind, ar) switch
    {
        (ChainStepKind.Started, false) => $"{s.Actor} started",
        (ChainStepKind.Started, true) => $"بدأ {s.Actor}",
        (ChainStepKind.Spawned, false) => $"{s.Actor} started {s.Target}",
        (ChainStepKind.Spawned, true) => $"شغّل {s.Actor} العملية {s.Target}",
        (ChainStepKind.Dropped, false) => $"{s.Actor} created {s.Target}",
        (ChainStepKind.Dropped, true) => $"أنشأ {s.Actor} الملف {s.Target}",
        (ChainStepKind.Executed, false) => $"{s.Actor} ran {s.Target}",
        (ChainStepKind.Executed, true) => $"شغّل {s.Actor} الملف {s.Target}",
        (ChainStepKind.Persisted, false) => $"{s.Actor} set up persistence ({s.Target})",
        (ChainStepKind.Persisted, true) => $"أنشأ {s.Actor} آلية بقاء ({s.Target})",
        (ChainStepKind.Connected, false) => $"{s.Actor} contacted {s.Target}",
        (ChainStepKind.Connected, true) => $"اتصل {s.Actor} بـ {s.Target}",
        (_, false) => $"{s.Actor}: {s.Kind} {s.Target}",
        _ => $"{s.Actor}: {s.Target}",
    };

    private static string Verdict(Core.Findings.Verdict v, bool ar) => v switch
    {
        Core.Findings.Verdict.CriticalBehavior => ar ? "سلوك حرج" : "critical behavior",
        Core.Findings.Verdict.HighRiskBehavior => ar ? "سلوك عالي الخطورة" : "high risk behavior",
        Core.Findings.Verdict.Suspicious => ar ? "مشبوه" : "suspicious",
        _ => ar ? "خطورة منخفضة" : "low risk",
    };

    private static string Time(TimeSpan t) => string.Create(CultureInfo.InvariantCulture, $"{(int)t.TotalMinutes:00}:{t.Seconds:00}.{t.Milliseconds:000}");

    private static bool IsArabic(string language) => language.StartsWith("ar", StringComparison.OrdinalIgnoreCase);
}
