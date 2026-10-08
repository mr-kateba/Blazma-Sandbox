using System.Globalization;
using Blazma.App.Localization;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Indicators;

namespace Blazma.App.Services;

/// <summary>Display formatting that follows the current language.</summary>
public static class Fmt
{
    public static string Relative(TimeSpan t, bool ms = true) =>
        t < TimeSpan.Zero ? "-" + Relative(-t, ms) :
        ms ? string.Create(CultureInfo.InvariantCulture, $"{(int)t.TotalMinutes:00}:{t.Seconds:00}.{t.Milliseconds:000}")
           : string.Create(CultureInfo.InvariantCulture, $"{(int)t.TotalMinutes:00}:{t.Seconds:00}");

    public static string Ago(DateTimeOffset when)
    {
        var d = DateTimeOffset.Now - when;
        if (d < TimeSpan.FromMinutes(1)) return Loc.T("JustNow");
        if (d < TimeSpan.FromHours(1)) return Loc.F("MinutesAgo", (int)d.TotalMinutes);
        if (d < TimeSpan.FromDays(1)) return Loc.F("HoursAgo", (int)d.TotalHours);
        return Loc.F("DaysAgo", (int)d.TotalDays);
    }

    public static string Date(DateTimeOffset when) => when.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

    public static string Duration(TimeSpan? d) => d is null ? "—" : d.Value.TotalMinutes >= 1
        ? string.Create(CultureInfo.InvariantCulture, $"{(int)d.Value.TotalMinutes}m {d.Value.Seconds:00}s")
        : string.Create(CultureInfo.InvariantCulture, $"{d.Value.TotalSeconds:0}s");

    public static string Size(long bytes) => bytes switch
    {
        >= 1L << 30 => string.Create(CultureInfo.InvariantCulture, $"{bytes / (double)(1L << 30):0.0} GB"),
        >= 1L << 20 => string.Create(CultureInfo.InvariantCulture, $"{bytes / (double)(1L << 20):0.0} MB"),
        >= 1L << 10 => string.Create(CultureInfo.InvariantCulture, $"{bytes / 1024.0:0.0} KB"),
        _ => string.Create(CultureInfo.InvariantCulture, $"{bytes} B"),
    };

    public static string ShortHash(string hash) => hash.Length > 16 ? hash[..8] + "…" + hash[^8..] : hash;

    public static string Verdict(Verdict v) => Loc.T(v switch
    {
        Core.Findings.Verdict.CriticalBehavior => "VerdictCritical",
        Core.Findings.Verdict.HighRiskBehavior => "VerdictHigh",
        Core.Findings.Verdict.Suspicious => "VerdictSuspicious",
        _ => "VerdictLow",
    });

    public static Severity SeverityOf(Verdict v) => v switch
    {
        Core.Findings.Verdict.CriticalBehavior => Core.Events.Severity.Critical,
        Core.Findings.Verdict.HighRiskBehavior => Core.Events.Severity.High,
        Core.Findings.Verdict.Suspicious => Core.Events.Severity.Medium,
        _ => Core.Events.Severity.Low,
    };

    public static string Severity(Severity s) => Loc.T("Severity" + s);

    public static string Stage(AnalysisStage s) => Loc.T("Stage" + s);

    public static string Category(EventCategory c) => Loc.T("Cat" + c);

    public static string Action(EventAction a) => Loc.T("Act" + a);

    public static string FindingCategory(FindingCategory c) => Loc.T("FCat" + c);

    public static string IndicatorStatus(IndicatorStatus s) => Loc.T("Ind" + s);

    public static string IndicatorType(IndicatorType t) => Loc.T("IndType" + t);

    public static string Provider(string id) => id switch
    {
        "demo" => Loc.T("ProviderDemo"),
        "windows-sandbox" => "Windows Sandbox",
        _ => id,
    };
}
