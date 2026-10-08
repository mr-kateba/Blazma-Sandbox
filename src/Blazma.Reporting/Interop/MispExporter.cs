using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Findings;
using Blazma.Core.Indicators;
using Blazma.Core.Samples;

namespace Blazma.Reporting.Interop;

/// <summary>
/// A MISP event (the JSON accepted by "Import from… → MISP JSON"). Distribution is
/// "your organisation only" and the event is unpublished, so nothing is shared until an
/// analyst reviews it. <c>to_ids</c> is set only for values graded Suspicious or higher, so
/// MISP does not push merely observed traffic to detection systems.
/// </summary>
public sealed class MispExporter : IReportExporter
{
    public const string DefaultTlpTag = "tlp:amber";

    private readonly string? _tlpTag;
    private readonly Func<bool, Redactor>? _redactorFactory;

    /// <param name="tlpTag">TLP tag for the event (default <c>tlp:amber</c>); null or empty for none.</param>
    public MispExporter(string? tlpTag = DefaultTlpTag, Func<bool, Redactor>? redactorFactory = null)
    {
        if (!string.IsNullOrWhiteSpace(tlpTag) && !tlpTag.StartsWith("tlp:", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("A TLP tag looks like \"tlp:amber\".", nameof(tlpTag));
        _tlpTag = string.IsNullOrWhiteSpace(tlpTag) ? null : tlpTag.Trim().ToLowerInvariant();
        _redactorFactory = redactorFactory;
    }

    public string Format => "MISP";
    public string FileExtension => ".misp.json";

    public async Task ExportAsync(AnalysisResult result, Stream destination, ExportOptions options, CancellationToken cancellationToken)
    {
        var bytes = Encoding.UTF8.GetBytes(Build(result, options));
        await destination.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>MISP threat level: 1 High, 2 Medium, 3 Low, 4 Undefined.</summary>
    public static string ThreatLevelFor(Verdict verdict) => verdict switch
    {
        Verdict.CriticalBehavior => "1",
        Verdict.HighRiskBehavior => "2",
        Verdict.Suspicious => "3",
        _ => "4",
    };

    public string Build(AnalysisResult a, ExportOptions options)
    {
        var r = InteropData.Redactor(_redactorFactory, options.Redact);
        var timestamp = InteropData.Ended(a).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        var sampleIds = a.Risk.Verdict >= Verdict.Suspicious;
        var id = a.AnalysisId.ToString();

        var attributes = new List<JsonObject>();
        void Add(string type, string category, string? value, bool toIds, string comment)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            if (attributes.Any(x => (string)x["type"]! == type && (string)x["value"]! == value)) return;
            attributes.Add(new JsonObject
            {
                ["uuid"] = DeterministicId.For("misp-attribute", id, type, value),
                ["type"] = type,
                ["category"] = category,
                ["value"] = value,
                ["to_ids"] = toIds,
                ["distribution"] = "5",
                ["comment"] = comment,
                ["timestamp"] = timestamp,
                ["disable_correlation"] = false,
            });
        }

        // The sample itself. Its hashes are detection-worthy when the verdict is.
        var sampleNote = $"Submitted sample; analysis verdict {a.Risk.Verdict}.";
        Add("sha256", "Payload delivery", InteropData.IsHex(a.Sample.Sha256, 64) ? a.Sample.Sha256.ToLowerInvariant() : null, sampleIds, sampleNote);
        Add("sha1", "Payload delivery", InteropData.IsHex(a.Sample.Sha1, 40) && a.Sample.Sha1.Any(c => c != '0') ? a.Sample.Sha1.ToLowerInvariant() : null, sampleIds, sampleNote);
        Add("filename", "Payload delivery", r.Apply(a.Sample.FileName), false, "Submitted file name.");
        if (a.Sample.Kind == FileKind.Url) Add("url", "Payload delivery", r.Apply(a.Sample.Url), sampleIds, sampleNote);

        var others = new List<(string Type, string Category, string Value, bool ToIds, string Comment)>();
        foreach (var i in a.Indicators)
        {
            var value = r.Apply(i.Value)!;
            var toIds = InteropData.IsActionable(i.Status) && !InteropData.IsRedacted(value);
            var comment = $"Status {i.Status} (source: {i.Source}).";
            switch (i.Type)
            {
                case IndicatorType.Sha256 when InteropData.IsHex(value, 64) && !value.Equals(a.Sample.Sha256, StringComparison.OrdinalIgnoreCase):
                    others.Add(("sha256", "Artifacts dropped", value.ToLowerInvariant(), toIds, comment));
                    break;
                case IndicatorType.Domain:
                    var host = value.TrimEnd('.');
                    // Without a public-suffix list, two labels is a domain and more is a host name.
                    others.Add((host.Count(c => c == '.') >= 2 ? "hostname" : "domain", "Network activity", host, toIds, comment));
                    break;
                case IndicatorType.IpAddress when InteropData.IpFamily(value) is not null:
                    others.Add(("ip-dst", "Network activity", value, toIds, comment));
                    break;
                case IndicatorType.Url:
                    others.Add(("url", "Network activity", value, toIds, comment));
                    break;
                case IndicatorType.FilePath:
                    others.Add(("filename", "Artifacts dropped", value, toIds, comment));
                    break;
                case IndicatorType.RegistryKey:
                    var data = a.Persistence.FirstOrDefault(p => p.Target.Equals(i.Value, StringComparison.OrdinalIgnoreCase))?.Value;
                    data = r.Apply(data);
                    if (!string.IsNullOrEmpty(data) && !data.Contains('|', StringComparison.Ordinal) && !value.Contains('|', StringComparison.Ordinal))
                        others.Add(("regkey|value", "Persistence mechanism", value + "|" + data, toIds, comment));
                    else
                        others.Add(("regkey", "Persistence mechanism", value, toIds, comment));
                    break;
                case IndicatorType.PersistenceArtifact:
                    // A task or service name: context for the analyst, not something to match on.
                    others.Add(("text", "Persistence mechanism", value, false, comment));
                    break;
            }
        }
        foreach (var o in others.OrderBy(o => o.Category, StringComparer.Ordinal).ThenBy(o => o.Type, StringComparer.Ordinal).ThenBy(o => o.Value, StringComparer.Ordinal))
            Add(o.Type, o.Category, o.Value, o.ToIds, o.Comment);

        Add("comment", "Other", InteropData.VerdictSentence(a, options.Language), false, "Blazma Sandbox verdict and disclaimer.");

        var tags = new JsonArray();
        if (_tlpTag is not null) tags.Add(Tag(_tlpTag));
        if (a.IsDemo) tags.Add(Tag("blazma-sandbox:demo-data"));
        foreach (var t in InteropData.AllTechniques(a).Where(t => t.InCatalog))
            tags.Add(Tag(GalaxyTag(t)));

        var fileName = r.Apply(a.Sample.FileName);
        var ev = new JsonObject
        {
            ["uuid"] = DeterministicId.For("misp-event", id),
            ["info"] = $"{(a.IsDemo ? "[DEMO] " : "")}Blazma Sandbox analysis of {fileName}: {VerdictText.Of(a.Risk.Verdict, "en")} (risk score {a.Risk.Score}/100)",
            ["date"] = InteropData.Day(a.StartedAt),
            ["threat_level_id"] = ThreatLevelFor(a.Risk.Verdict),
            ["analysis"] = a.FinalStage == AnalysisStage.Completed ? "2" : "1",
            ["distribution"] = "0",
            ["published"] = false,
            ["timestamp"] = timestamp,
            ["Tag"] = tags,
            ["Attribute"] = new JsonArray([.. attributes]),
        };
        return new JsonObject { ["Event"] = ev }.ToJsonString(InteropData.Json) + "\n";
    }

    /// <summary>The MISP galaxy tag for a technique, e.g. <c>misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001"</c>.</summary>
    public static string GalaxyTag(AttackReference technique) => $"misp-galaxy:mitre-attack-pattern=\"{technique.Name} - {technique.Id}\"";

    private static JsonObject Tag(string name) => new() { ["name"] = name };
}
