namespace Blazma.Reporting;

/// <summary>Labels used inside exported reports, in both languages.</summary>
internal sealed class ReportStrings
{
    public required bool Rtl { get; init; }
    public required string Lang { get; init; }
    public required string Title { get; init; }
    public required string Demo { get; init; }
    public required string Overview { get; init; }
    public required string Score { get; init; }
    public required string WhyScore { get; init; }
    public required string FileInfo { get; init; }
    public required string ImportantFindings { get; init; }
    public required string Evidence { get; init; }
    public required string BehaviorChains { get; init; }
    public required string ProcessTree { get; init; }
    public required string Network { get; init; }
    public required string Persistence { get; init; }
    public required string SystemChanges { get; init; }
    public required string Indicators { get; init; }
    public required string TimelineSummary { get; init; }
    public required string StaticDetails { get; init; }
    public required string NoFindings { get; init; }
    public required string Nothing { get; init; }
    public required string Name { get; init; }
    public required string Size { get; init; }
    public required string Type { get; init; }
    public required string Signature { get; init; }
    public required string Duration { get; init; }
    public required string Provider { get; init; }
    public required string Generated { get; init; }
    public required string Integrity { get; init; }
    public required string Time { get; init; }
    public required string Process { get; init; }
    public required string Action { get; init; }
    public required string Target { get; init; }
    public required string Value { get; init; }
    public required string Status { get; init; }
    public required string Technique { get; init; }
    public required string Explanation { get; init; }
    public required string Created { get; init; }
    public required string Modified { get; init; }
    public required string Deleted { get; init; }
    public required string Added { get; init; }
    public required string Removed { get; init; }
    public required string Files { get; init; }
    public required string Registry { get; init; }
    public required string Services { get; init; }
    public required string Tasks { get; init; }
    public required string Startup { get; init; }
    public required string Dns { get; init; }
    public required string Connections { get; init; }
    public required string Redacted { get; init; }
    public required string LocalFirst { get; init; }
    public required string Interrupted { get; init; }
    public required string Sections { get; init; }
    public required string CompileTime { get; init; }
    public required string CompileTimeNote { get; init; }
    public required string ShownOf { get; init; }

    public static ReportStrings For(string language) => language.StartsWith("ar", StringComparison.OrdinalIgnoreCase) ? Arabic : English;

    public static readonly ReportStrings English = new()
    {
        Rtl = false, Lang = "en", Title = "Analysis report", Demo = "DEMO DATA: synthetic analysis, no real file was run",
        Overview = "Overview", Score = "Risk score", WhyScore = "Why this score?", FileInfo = "File information",
        ImportantFindings = "Important findings", Evidence = "Evidence", BehaviorChains = "Behavior chains", ProcessTree = "Process tree",
        Network = "Network activity", Persistence = "Persistence", SystemChanges = "System changes", Indicators = "Indicators",
        TimelineSummary = "Timeline summary", StaticDetails = "Static analysis", NoFindings = "No findings were raised.", Nothing = "Nothing observed.",
        Name = "Name", Size = "Size", Type = "Type", Signature = "Signature", Duration = "Duration", Provider = "Analysis environment",
        Generated = "Generated", Integrity = "Content SHA-256", Time = "Time", Process = "Process", Action = "Action", Target = "Target",
        Value = "Value", Status = "Status", Technique = "Technique", Explanation = "Explanation", Created = "created", Modified = "modified",
        Deleted = "deleted", Added = "added", Removed = "removed", Files = "Files", Registry = "Registry", Services = "Services",
        Tasks = "Scheduled tasks", Startup = "Startup", Dns = "DNS requests", Connections = "Connections",
        Redacted = "Personal details (user name, machine name, profile path) were redacted from this report.",
        LocalFirst = "Produced locally by Blazma Sandbox. Nothing in this report was uploaded anywhere.",
        Interrupted = "Monitoring was interrupted before the analysis ended. Results may be incomplete.",
        Sections = "Sections", CompileTime = "Compile timestamp", CompileTimeNote = "can be forged", ShownOf = "Showing {0} of {1} events.",
    };

    public static readonly ReportStrings Arabic = new()
    {
        Rtl = true, Lang = "ar", Title = "تقرير التحليل", Demo = "بيانات تجريبية: تحليل اصطناعي، لم يتم تشغيل أي ملف حقيقي",
        Overview = "نظرة عامة", Score = "درجة الخطورة", WhyScore = "لماذا هذه الدرجة؟", FileInfo = "معلومات الملف",
        ImportantFindings = "أهم النتائج", Evidence = "الأدلة", BehaviorChains = "سلاسل السلوك", ProcessTree = "شجرة العمليات",
        Network = "نشاط الشبكة", Persistence = "آليات البقاء", SystemChanges = "تغييرات النظام", Indicators = "المؤشرات",
        TimelineSummary = "ملخص الخط الزمني", StaticDetails = "التحليل الثابت", NoFindings = "لم تظهر أي نتائج.", Nothing = "لم يُلاحظ شيء.",
        Name = "الاسم", Size = "الحجم", Type = "النوع", Signature = "التوقيع", Duration = "المدة", Provider = "بيئة التحليل",
        Generated = "تاريخ الإنشاء", Integrity = "SHA-256 للمحتوى", Time = "الوقت", Process = "العملية", Action = "الإجراء", Target = "الهدف",
        Value = "القيمة", Status = "الحالة", Technique = "الأسلوب", Explanation = "الشرح", Created = "أُنشئ", Modified = "عُدّل",
        Deleted = "حُذف", Added = "أُضيف", Removed = "أُزيل", Files = "الملفات", Registry = "السجل (Registry)", Services = "الخدمات",
        Tasks = "المهام المجدولة", Startup = "بدء التشغيل", Dns = "طلبات DNS", Connections = "الاتصالات",
        Redacted = "تم حجب البيانات الشخصية (اسم المستخدم واسم الجهاز ومسار الملف الشخصي) من هذا التقرير.",
        LocalFirst = "أُنشئ هذا التقرير محليًا بواسطة Blazma Sandbox، ولم يُرفع أي شيء منه إلى أي مكان.",
        Interrupted = "توقفت المراقبة قبل انتهاء التحليل، لذا قد تكون النتائج ناقصة.",
        Sections = "الأقسام", CompileTime = "تاريخ الترجمة", CompileTimeNote = "قابل للتزوير", ShownOf = "يُعرض {0} من أصل {1} حدث.",
    };
}

public static class VerdictText
{
    public static string Of(Core.Findings.Verdict verdict, string language)
    {
        var ar = language.StartsWith("ar", StringComparison.OrdinalIgnoreCase);
        return verdict switch
        {
            Core.Findings.Verdict.CriticalBehavior => ar ? "سلوك حرج" : "Critical behavior",
            Core.Findings.Verdict.HighRiskBehavior => ar ? "سلوك عالي الخطورة" : "High risk behavior",
            Core.Findings.Verdict.Suspicious => ar ? "مشبوه" : "Suspicious",
            _ => ar ? "خطورة منخفضة" : "Low risk",
        };
    }

    public static string Of(Core.Events.Severity severity, string language)
    {
        var ar = language.StartsWith("ar", StringComparison.OrdinalIgnoreCase);
        return severity switch
        {
            Core.Events.Severity.Critical => ar ? "حرج" : "Critical",
            Core.Events.Severity.High => ar ? "مرتفع" : "High",
            Core.Events.Severity.Medium => ar ? "متوسط" : "Medium",
            Core.Events.Severity.Low => ar ? "منخفض" : "Low",
            _ => ar ? "معلوماتي" : "Informational",
        };
    }
}
