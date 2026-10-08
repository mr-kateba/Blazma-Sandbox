using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Encodings.Web;
using System.Text.Json;
using Blazma.Analysis.Text;
using Blazma.Core.Analysis;
using Blazma.Core.Attack;
using Blazma.Core.Findings;
using Blazma.Core.Indicators;
using Blazma.Core.Processes;

namespace Blazma.Reporting.Interop;

/// <summary>
/// An ATT&amp;CK technique as an export should cite it. A technique MITRE has revoked is
/// exported as its replacement (with <see cref="Note"/> saying so), because consumers only
/// know the current ID; an ID missing from the catalog keeps the ID as its name rather than
/// a guessed one.
/// </summary>
public sealed record AttackReference(string CitedId, string Id, string Name, IReadOnlyList<string> Tactics, bool InCatalog)
{
    public string? Note => !InCatalog ? $"{CitedId} is not in the bundled ATT&CK catalog ({AttackCatalog.DataModified})."
        : !CitedId.Equals(Id, StringComparison.OrdinalIgnoreCase) ? $"Cited by the rule as {CitedId}, which MITRE revoked; replaced by {Id}."
        : null;

    public string? Url => InCatalog ? "https://attack.mitre.org/techniques/" + Id.Replace('.', '/') : null;

    public static AttackReference Resolve(string id)
    {
        var cited = id.Trim().ToUpperInvariant();
        if (AttackCatalog.TryGet(cited, out var t)) return new(cited, t.Id, t.Name, t.Tactics, true);
        if (AttackCatalog.TryGetReplacement(cited, out var r)) return new(cited, r.Id, r.Name, r.Tactics, true);
        return new(cited, cited, cited, [], false);
    }

    /// <summary>Distinct techniques (by exported ID) in ordinal order.</summary>
    public static IReadOnlyList<AttackReference> ResolveAll(IEnumerable<string> ids) =>
        ids.Where(i => !string.IsNullOrWhiteSpace(i)).Select(Resolve)
            .GroupBy(r => r.Id, StringComparer.Ordinal).Select(g => g.OrderBy(r => r.CitedId, StringComparer.Ordinal).First())
            .OrderBy(r => r.Id, StringComparer.Ordinal).ToList();
}

/// <summary>Small pieces every interop format needs, kept in one place so the formats agree.</summary>
internal static class InteropData
{
    public static string GeneratorVersion { get; } = typeof(InteropData).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    /// <summary>Indented, "\n" line endings on every OS (byte-identical output), Arabic and paths left readable.</summary>
    public static JsonSerializerOptions Json { get; } = new()
    {
        WriteIndented = true,
        NewLine = "\n",
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static Redactor Redactor(Func<bool, Redactor>? factory, bool redact) =>
        factory?.Invoke(redact) ?? (redact ? new Redactor() : Reporting.Redactor.None);

    /// <summary>STIX 2.1 timestamp: UTC with exactly millisecond precision.</summary>
    public static string StixTime(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    public static string Day(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    public static DateTimeOffset Ended(AnalysisResult a) => a.CompletedAt ?? a.StartedAt;

    /// <summary>Status high enough to be used for detection (blocking, alerting), not just context.</summary>
    public static bool IsActionable(IndicatorStatus status) => status >= IndicatorStatus.Suspicious;

    public static bool IsHex(string? value, int length) =>
        value is not null && value.Length == length && value.All(Uri.IsHexDigit);

    /// <summary>The address family of an indicator value, or null if it is not an IP address.</summary>
    public static AddressFamily? IpFamily(string value) =>
        IPAddress.TryParse(value, out var ip) && ip.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6 ? ip.AddressFamily : null;

    /// <summary>
    /// Techniques of the findings that cite any of these events, so an indicator is linked
    /// only to behavior that actually involved it.
    /// </summary>
    public static IReadOnlyList<AttackReference> TechniquesFor(AnalysisResult a, IEnumerable<long> eventSequences)
    {
        var seqs = eventSequences.ToHashSet();
        if (seqs.Count == 0) return [];
        return AttackReference.ResolveAll(a.Findings.Where(f => f.AllEventSequences.Any(seqs.Contains)).SelectMany(f => f.AttackTechniques));
    }

    public static IReadOnlyList<AttackReference> AllTechniques(AnalysisResult a) =>
        AttackReference.ResolveAll(a.Findings.SelectMany(f => f.AttackTechniques));

    /// <summary>Worst severity among findings that cite any of these events.</summary>
    public static Core.Events.Severity? WorstFindingSeverity(AnalysisResult a, IEnumerable<long> eventSequences)
    {
        var seqs = eventSequences.ToHashSet();
        var hits = a.Findings.Where(f => f.AllEventSequences.Any(seqs.Contains)).Select(f => f.Severity).ToList();
        return hits.Count == 0 ? null : hits.Max();
    }

    /// <summary>
    /// Persistence locations whose target is "key\valueName" rather than a key: the catalog
    /// appends the value name for these (see PersistenceCatalog).
    /// </summary>
    public static bool TargetEndsWithValueName(PersistenceTechnique technique) => technique is PersistenceTechnique.RunKey
        or PersistenceTechnique.WinlogonHelper or PersistenceTechnique.ImageFileExecutionOptions
        or PersistenceTechnique.AppInitDlls or PersistenceTechnique.ActiveSetup;

    /// <summary>Splits a registry indicator into key and value name when the detection says the last part is a value.</summary>
    public static (string Key, string? ValueName) SplitRegistryTarget(AnalysisResult a, string target)
    {
        var detection = a.Persistence.FirstOrDefault(p => p.Target.Equals(target, StringComparison.OrdinalIgnoreCase));
        var normalized = PathRules.NormalizeRegistryKey(target);
        if (detection is null || !TargetEndsWithValueName(detection.Technique)) return (normalized, null);
        var cut = normalized.LastIndexOf('\\');
        return cut <= 0 ? (normalized, null) : (normalized[..cut], normalized[(cut + 1)..]);
    }

    /// <summary>Expands the hive abbreviation, as STIX requires for windows-registry-key.</summary>
    public static string FullHive(string key)
    {
        var k = PathRules.NormalizeRegistryKey(key);
        foreach (var (shortName, full) in Hives)
            if (k.Equals(shortName, StringComparison.OrdinalIgnoreCase) || k.StartsWith(shortName + "\\", StringComparison.OrdinalIgnoreCase))
                return full + k[shortName.Length..];
        return k;
    }

    private static readonly (string Short, string Full)[] Hives =
    [
        ("HKLM", "HKEY_LOCAL_MACHINE"),
        ("HKCU", "HKEY_CURRENT_USER"),
        ("HKU", "HKEY_USERS"),
        ("HKCR", "HKEY_CLASSES_ROOT"),
        ("HKCC", "HKEY_CURRENT_CONFIG"),
    ];

    /// <summary>One sentence about the verdict that never claims more than the analysis did.</summary>
    public static string VerdictSentence(AnalysisResult a, string language)
    {
        var ar = language.StartsWith("ar", StringComparison.OrdinalIgnoreCase);
        var verdict = VerdictText.Of(a.Risk.Verdict, language);
        var parts = new List<string>
        {
            ar ? $"حكم Blazma Sandbox: {verdict} (درجة الخطورة {a.Risk.Score}/100) من تحليل ديناميكي واحد."
               : $"Blazma Sandbox verdict: {verdict} (risk score {a.Risk.Score}/100) from one dynamic analysis.",
            ar ? RiskAssessment.DisclaimerAr : RiskAssessment.Disclaimer,
        };
        if (a.Risk.Verdict == Verdict.LowRisk)
            parts.Add(ar ? "النتيجة المنخفضة لا تثبت أن الملف آمن." : "A low score does not prove that a file is safe.");
        if (a.IsDemo) parts.Add(ar ? "بيانات تجريبية: أحداث مصطنعة وليست من عينة حقيقية." : "DEMO DATA: synthetic events, not from a real sample.");
        if (a.MonitoringInterrupted) parts.Add(ar ? "انقطعت المراقبة؛ قد تكون البيانات ناقصة." : "Monitoring was interrupted; data may be incomplete.");
        if (a.FinalStage != AnalysisStage.Completed) parts.Add(ar ? $"لم يكتمل التحليل ({a.FinalStage})." : $"The analysis did not complete ({a.FinalStage}).");
        return string.Join(' ', parts);
    }
}
