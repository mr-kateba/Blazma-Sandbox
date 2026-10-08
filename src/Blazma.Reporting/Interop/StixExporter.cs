using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Blazma.Analysis.Text;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Attack;
using Blazma.Core.Findings;
using Blazma.Core.Indicators;
using Blazma.Core.Samples;

namespace Blazma.Reporting.Interop;

/// <summary>
/// STIX 2.1 bundle for threat-intelligence platforms (OpenCTI, MISP, TAXII). It states what
/// was observed and what Blazma concluded, never more: the analysis result is at most what
/// the verdict says, a single dynamic run never yields "benign", and only indicators that
/// findings graded Suspicious or higher become detection patterns.
/// </summary>
/// <remarks>
/// Objects: <c>identity</c> (Blazma Sandbox), <c>malware-analysis</c>, a <c>note</c> with the
/// verdict and disclaimer, the sample <c>file</c>, observed <c>domain-name</c>/<c>ipv4-addr</c>/
/// <c>ipv6-addr</c>/<c>url</c>, <c>indicator</c>s, <c>attack-pattern</c>s and <c>relationship</c>s.
/// Every ID is derived from content (observables per STIX 2.1 section 2.9), so the same
/// analysis always exports to the same bytes.
/// </remarks>
public sealed class StixExporter : IReportExporter
{
    /// <summary>Fixed creation time of the Blazma identity, so it is one object across all bundles.</summary>
    private const string IdentityCreated = "2026-01-01T00:00:00.000Z";

    private readonly Func<bool, Redactor>? _redactorFactory;

    public StixExporter(Func<bool, Redactor>? redactorFactory = null) => _redactorFactory = redactorFactory;

    public string Format => "STIX 2.1";
    public string FileExtension => ".stix.json";

    public static string IdentityId { get; } = "identity--" + DeterministicId.For("identity", "Blazma Sandbox");

    public async Task ExportAsync(AnalysisResult result, Stream destination, ExportOptions options, CancellationToken cancellationToken)
    {
        var bytes = Encoding.UTF8.GetBytes(Build(result, options));
        await destination.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The analysis' STIX <c>result</c>. "benign" is never used: one sandbox run cannot show
    /// that a file is harmless (it may detect the sandbox or wait).
    /// </summary>
    public static string ResultFor(Verdict verdict) => verdict switch
    {
        Verdict.CriticalBehavior or Verdict.HighRiskBehavior => "malicious",
        Verdict.Suspicious => "suspicious",
        _ => "unknown",
    };

    public string Build(AnalysisResult a, ExportOptions options)
    {
        var r = InteropData.Redactor(_redactorFactory, options.Redact);
        var started = InteropData.StixTime(a.StartedAt);
        var ended = InteropData.StixTime(InteropData.Ended(a));

        // Observables: the sample file, plus every observed network indicator.
        var sample = SampleFile(a, r);
        var observables = new SortedDictionary<string, JsonObject>(StringComparer.Ordinal);
        if (a.Sample.Kind == FileKind.Url && !string.IsNullOrWhiteSpace(a.Sample.Url))
            AddObservable(observables, "url", r.Apply(a.Sample.Url)!);
        foreach (var i in a.Indicators)
        {
            var value = r.Apply(i.Value)!;
            switch (i.Type)
            {
                case IndicatorType.Domain: AddObservable(observables, "domain-name", value.TrimEnd('.')); break;
                case IndicatorType.Url: AddObservable(observables, "url", value); break;
                case IndicatorType.IpAddress when InteropData.IpFamily(value) is { } family:
                    AddObservable(observables, family == AddressFamily.InterNetworkV6 ? "ipv6-addr" : "ipv4-addr", value);
                    break;
            }
        }

        var analysisId = "malware-analysis--" + DeterministicId.For("malware-analysis", a.AnalysisId.ToString());
        var analysis = Sdo("malware-analysis", analysisId, started, ended);
        if (a.IsDemo) analysis["labels"] = new JsonArray("demo-data");
        analysis["product"] = "blazma-sandbox";
        analysis["version"] = InteropData.GeneratorVersion;
        analysis["analysis_started"] = started;
        if (a.CompletedAt is not null) analysis["analysis_ended"] = ended;
        analysis["result"] = ResultFor(a.Risk.Verdict);
        analysis["sample_ref"] = (string)sample["id"]!;
        analysis["analysis_sco_refs"] = Array(new[] { (string)sample["id"]! }.Concat(observables.Keys).Distinct());

        var ar = options.Language.StartsWith("ar", StringComparison.OrdinalIgnoreCase);
        var note = Sdo("note", "note--" + DeterministicId.For("note", a.AnalysisId.ToString(), options.Language), started, ended);
        note["abstract"] = ar ? "حكم Blazma Sandbox" : "Blazma Sandbox verdict";
        note["content"] = InteropData.VerdictSentence(a, options.Language);
        if (ar) note["lang"] = "ar";
        note["object_refs"] = Array([analysisId, (string)sample["id"]!]);

        // Attack patterns for every technique the findings cite.
        var techniques = InteropData.AllTechniques(a);
        var patterns = techniques.Select(AttackPattern).ToList();
        var relationships = new List<JsonObject>();
        foreach (var t in techniques)
        {
            var rules = a.Findings.Where(f => f.AttackTechniques.Any(x => AttackReference.Resolve(x).Id == t.Id)).Select(f => f.RuleId).Distinct().Order(StringComparer.Ordinal);
            relationships.Add(Relationship("related-to", analysisId, PatternId(t), started, ended,
                $"Behavior matching this technique was observed in this analysis (Blazma rules: {string.Join(", ", rules)})."));
        }

        // Indicators: only what findings graded Suspicious or higher, and only with a valid pattern.
        var indicators = new List<JsonObject>();
        foreach (var i in a.Indicators.Where(i => InteropData.IsActionable(i.Status)).OrderBy(i => i.Type).ThenBy(i => i.Value, StringComparer.Ordinal))
        {
            var value = r.Apply(i.Value)!;
            if (Pattern(a, i.Type, value) is not { } pattern) continue;
            var id = "indicator--" + DeterministicId.For("indicator", a.AnalysisId.ToString(), i.Type.ToString(), value);
            var o = Sdo("indicator", id, started, ended);
            o["name"] = $"{TypeLabel(i.Type)}: {value}";
            o["description"] = $"Observed during a Blazma Sandbox analysis of SHA-256 {a.Sample.Sha256}. Status {i.Status} (source: {i.Source}): raised by findings that cite this activity, not by reputation. Review before blocking.";
            o["indicator_types"] = new JsonArray("anomalous-activity");
            o["pattern"] = pattern;
            o["pattern_type"] = "stix";
            o["pattern_version"] = "2.1";
            o["valid_from"] = started;
            indicators.Add(o);
            foreach (var t in InteropData.TechniquesFor(a, i.EventSequences))
                relationships.Add(Relationship("indicates", id, PatternId(t), started, ended, null));
        }

        var objects = new List<JsonObject> { Identity(), analysis, note, sample };
        objects.AddRange(observables.Values.OrderBy(o => (string)o["type"]!, StringComparer.Ordinal).ThenBy(o => (string)o["value"]!, StringComparer.Ordinal));
        objects.AddRange(indicators);
        objects.AddRange(patterns);
        objects.AddRange(relationships.DistinctBy(o => (string)o["id"]!).OrderBy(o => (string)o["source_ref"]!, StringComparer.Ordinal)
            .ThenBy(o => (string)o["relationship_type"]!, StringComparer.Ordinal).ThenBy(o => (string)o["target_ref"]!, StringComparer.Ordinal));

        var bundle = new JsonObject
        {
            ["type"] = "bundle",
            ["id"] = "bundle--" + DeterministicId.For("bundle", a.AnalysisId.ToString(), options.Redact ? "redacted" : "full", options.Language),
            ["objects"] = new JsonArray([.. objects]),
        };
        return bundle.ToJsonString(InteropData.Json) + "\n";
    }

    /// <summary>
    /// A STIX pattern for one indicator, or null when the indicator cannot be expressed
    /// exactly (a redacted path, a scheduled-task name) or would match far beyond this
    /// sample (process names such as powershell.exe).
    /// </summary>
    public static string? Pattern(AnalysisResult a, IndicatorType type, string value)
    {
        switch (type)
        {
            case IndicatorType.Sha256 when InteropData.IsHex(value, 64):
                return $"[file:hashes.'SHA-256' = '{Escape(value.ToLowerInvariant())}']";
            case IndicatorType.Domain:
                return $"[domain-name:value = '{Escape(value.TrimEnd('.'))}']";
            case IndicatorType.Url:
                return $"[url:value = '{Escape(value)}']";
            case IndicatorType.IpAddress when InteropData.IpFamily(value) is { } family:
                return $"[{(family == AddressFamily.InterNetworkV6 ? "ipv6-addr" : "ipv4-addr")}:value = '{Escape(value)}']";
            case IndicatorType.FilePath when !InteropData.IsRedacted(value):
            {
                var path = PathRules.NormalizeFilePath(value);
                var name = PathRules.FileName(path);
                if (name.Length == 0) return null;
                var dir = path.Length > name.Length + 1 ? path[..(path.Length - name.Length - 1)] : null;
                return dir is null
                    ? $"[file:name = '{Escape(name)}']"
                    : $"[file:name = '{Escape(name)}' AND file:parent_directory_ref.path = '{Escape(dir)}']";
            }
            case IndicatorType.FilePath:
            {
                // Only the name survives redaction intact.
                var name = PathRules.FileName(value);
                return name.Length == 0 || InteropData.IsRedacted(name) ? null : $"[file:name = '{Escape(name)}']";
            }
            case IndicatorType.RegistryKey when !InteropData.IsRedacted(value):
            {
                var (key, valueName) = InteropData.SplitRegistryTarget(a, value);
                var full = InteropData.FullHive(key);
                return valueName is null
                    ? $"[windows-registry-key:key = '{Escape(full)}']"
                    : $"[windows-registry-key:key = '{Escape(full)}' AND windows-registry-key:values[*].name = '{Escape(valueName)}']";
            }
            default:
                return null;
        }
    }

    /// <summary>STIX patterning string literal escaping: backslash and single quote.</summary>
    public static string Escape(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("'", "\\'", StringComparison.Ordinal);

    private static string TypeLabel(IndicatorType type) => type switch
    {
        IndicatorType.Sha256 => "SHA-256",
        IndicatorType.IpAddress => "IP address",
        IndicatorType.Url => "URL",
        IndicatorType.FilePath => "File",
        IndicatorType.RegistryKey => "Registry",
        _ => type.ToString(),
    };

    private static JsonObject Identity() => new()
    {
        ["type"] = "identity",
        ["spec_version"] = "2.1",
        ["id"] = IdentityId,
        ["created"] = IdentityCreated,
        ["modified"] = IdentityCreated,
        ["name"] = "Blazma Sandbox",
        ["description"] = "Local, offline malware-analysis sandbox. Objects it creates describe observed behavior and rule conclusions, not attribution.",
        ["identity_class"] = "system",
    };

    private static JsonObject Sdo(string type, string id, string created, string modified) => new()
    {
        ["type"] = type,
        ["spec_version"] = "2.1",
        ["id"] = id,
        ["created_by_ref"] = IdentityId,
        ["created"] = created,
        ["modified"] = modified,
    };

    private static JsonObject SampleFile(AnalysisResult a, Redactor r)
    {
        var name = r.Apply(a.Sample.FileName);
        var hashes = new JsonObject();
        // The ID uses one hash, preferring MD5, SHA-1, SHA-256 (as the STIX reference library does).
        string? idHashName = null, idHash = null;
        if (InteropData.IsHex(a.Sample.Sha1, 40) && a.Sample.Sha1.Any(c => c != '0'))
        {
            hashes["SHA-1"] = a.Sample.Sha1.ToLowerInvariant();
            (idHashName, idHash) = ("SHA-1", a.Sample.Sha1.ToLowerInvariant());
        }
        if (InteropData.IsHex(a.Sample.Sha256, 64))
        {
            hashes["SHA-256"] = a.Sample.Sha256.ToLowerInvariant();
            if (idHashName is null) (idHashName, idHash) = ("SHA-256", a.Sample.Sha256.ToLowerInvariant());
        }

        var canonical = new StringBuilder("{");
        if (idHashName is not null)
            canonical.Append("\"hashes\":{").Append(DeterministicId.CanonicalJsonString(idHashName)).Append(':').Append(DeterministicId.CanonicalJsonString(idHash!)).Append('}');
        if (!string.IsNullOrEmpty(name))
            canonical.Append(idHashName is null ? "" : ",").Append("\"name\":").Append(DeterministicId.CanonicalJsonString(name));
        canonical.Append('}');

        var o = new JsonObject
        {
            ["type"] = "file",
            ["spec_version"] = "2.1",
            ["id"] = "file--" + DeterministicId.Uuid5(DeterministicId.StixObservableNamespace, canonical.ToString()),
        };
        if (hashes.Count > 0) o["hashes"] = hashes;
        if (a.Sample.Size > 0) o["size"] = a.Sample.Size;
        if (!string.IsNullOrEmpty(name)) o["name"] = name;
        return o;
    }

    private static void AddObservable(SortedDictionary<string, JsonObject> into, string type, string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        var id = ObservableId(type, value);
        into.TryAdd(id, new JsonObject { ["type"] = type, ["spec_version"] = "2.1", ["id"] = id, ["value"] = value });
    }

    /// <summary>STIX 2.1 deterministic ID of a value-only observable (domain-name, ipv4-addr, ipv6-addr, url).</summary>
    public static string ObservableId(string type, string value) =>
        type + "--" + DeterministicId.Uuid5(DeterministicId.StixObservableNamespace, "{\"value\":" + DeterministicId.CanonicalJsonString(value) + "}");

    private static string PatternId(AttackReference t) => "attack-pattern--" + DeterministicId.For("attack-pattern", t.Id);

    private static JsonObject AttackPattern(AttackReference t)
    {
        var created = InteropData.StixTime(DateTimeOffset.Parse(AttackCatalog.DataModified, System.Globalization.CultureInfo.InvariantCulture));
        var o = Sdo("attack-pattern", PatternId(t), created, created);
        o["name"] = t.Name;
        if (t.Note is { } note) o["description"] = note;
        var reference = new JsonObject { ["source_name"] = "mitre-attack", ["external_id"] = t.Id };
        if (t.Url is { } url) reference["url"] = url;
        o["external_references"] = new JsonArray(reference);
        if (t.Tactics.Count > 0)
            o["kill_chain_phases"] = new JsonArray([.. t.Tactics.Select(p => (JsonNode)new JsonObject { ["kill_chain_name"] = "mitre-attack", ["phase_name"] = p })]);
        return o;
    }

    private static JsonObject Relationship(string type, string source, string target, string created, string modified, string? description)
    {
        var o = Sdo("relationship", "relationship--" + DeterministicId.For("relationship", type, source, target), created, modified);
        o["relationship_type"] = type;
        if (description is not null) o["description"] = description;
        o["source_ref"] = source;
        o["target_ref"] = target;
        return o;
    }

    private static JsonArray Array(IEnumerable<string> values) => new([.. values.Select(v => (JsonNode)JsonValue.Create(v))]);
}
