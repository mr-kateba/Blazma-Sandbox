using System.Text.Json;
using System.Text.Json.Serialization;
using Blazma.Analysis.Text;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Text;

namespace Blazma.Analysis.Rules;

/// <summary>
/// User-defined rules written as JSON, no code required. Matching uses globs only (no
/// regular expressions) so a rule pack cannot hang the engine. User rule IDs must start
/// with "USR-" so they can never replace a built-in rule.
/// </summary>
public sealed class JsonRulePack
{
    public string Pack { get; set; } = "Custom rules";
    public string Version { get; set; } = "1";
    public List<JsonRuleDefinition> Rules { get; set; } = [];

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static (IReadOnlyList<IRule> Rules, IReadOnlyList<string> Errors) Load(string json, string origin)
    {
        var errors = new List<string>();
        JsonRulePack? pack;
        try
        {
            pack = JsonSerializer.Deserialize<JsonRulePack>(json, Options);
        }
        catch (JsonException ex)
        {
            return ([], [$"{origin}: invalid JSON ({ex.Message})"]);
        }
        if (pack is null) return ([], [$"{origin}: empty rule pack"]);

        var rules = new List<IRule>();
        foreach (var def in pack.Rules)
        {
            var problem = def.Validate();
            if (problem is not null) { errors.Add($"{origin}/{def.Id}: {problem}"); continue; }
            rules.Add(new JsonRule(def, pack.Pack));
        }
        return (rules, errors);
    }

    public static string Example => """
    {
      "pack": "My rules",
      "version": "1",
      "rules": [
        {
          "id": "USR-0001",
          "version": "1",
          "name": { "en": "Contacted our test domain", "ar": "اتصل بنطاق الاختبار" },
          "description": { "en": "Flags lookups of *.example.test.", "ar": "يرصد الاستعلام عن ‎*.example.test." },
          "category": "Network",
          "severity": "Medium",
          "weight": 8,
          "attack": [ "T1071" ],
          "match": { "action": "DnsQuery", "target": "*.example.test", "analyzedTreeOnly": true },
          "minCount": 1
        }
      ]
    }
    """;
}

public sealed class JsonRuleDefinition
{
    public string Id { get; set; } = string.Empty;
    public string Version { get; set; } = "1";
    public JsonText Name { get; set; } = new();
    public JsonText Description { get; set; } = new();
    public FindingCategory Category { get; set; } = FindingCategory.Execution;
    public Severity Severity { get; set; } = Severity.Low;
    public int Weight { get; set; } = 5;
    public List<string> Attack { get; set; } = [];
    public JsonMatch Match { get; set; } = new();
    public int MinCount { get; set; } = 1;

    public string? Validate()
    {
        if (!Id.StartsWith("USR-", StringComparison.OrdinalIgnoreCase) || Id.Length > 32) return "rule ids must start with USR- and be at most 32 characters";
        if (string.IsNullOrWhiteSpace(Name.En)) return "name.en is required";
        if (Weight is < 0 or > 50) return "weight must be between 0 and 50";
        if (MinCount is < 1 or > 10_000) return "minCount must be between 1 and 10000";
        if (Match.Action is null && Match.Category is null && Match.Target is null && Match.Process is null) return "match needs at least one condition";
        return null;
    }
}

public sealed class JsonText
{
    public string En { get; set; } = string.Empty;
    public string? Ar { get; set; }

    public LocalizedText ToLocalized() => new(En, string.IsNullOrWhiteSpace(Ar) ? En : Ar);
}

public sealed class JsonMatch
{
    public EventAction? Action { get; set; }
    public EventCategory? Category { get; set; }
    public string? Process { get; set; }
    public string? Target { get; set; }
    public string? DetailKey { get; set; }
    public string? DetailValue { get; set; }
    public bool AnalyzedTreeOnly { get; set; } = true;
}

internal sealed class JsonRule(JsonRuleDefinition def, string origin) : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = def.Id.ToUpperInvariant(),
        Version = def.Version,
        Name = def.Name.ToLocalized(),
        Description = def.Description.En.Length == 0 ? def.Name.ToLocalized() : def.Description.ToLocalized(),
        Category = def.Category,
        Severity = def.Severity,
        Weight = def.Weight,
        AttackTechniques = def.Attack,
        Origin = origin,
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var m = def.Match;
        var hits = context.Events.Where(e =>
                (m.Action is null || e.Action == m.Action) &&
                (m.Category is null || e.Category == m.Category) &&
                (m.Process is null || Glob.IsMatch(e.ProcessName, m.Process)) &&
                (m.Target is null || Glob.IsMatch(e.Target, m.Target)) &&
                (m.DetailKey is null || Glob.IsMatch(e.Detail(m.DetailKey), m.DetailValue ?? "*")) &&
                (!m.AnalyzedTreeOnly || context.Graph.InAnalyzedTree(e)))
            .Take(Math.Max(def.MinCount, 25)).ToList();
        if (hits.Count < def.MinCount) return null;
        var evidence = hits.Take(25).Select(e => EventEvidence("custom-rule", e,
            new($"{e.ProcessName}: {e.Action} {e.Target}", $"{e.ProcessName}: {e.Action} {e.Target}"))).ToList();
        return Build(evidence, firstSeen: hits[0].RelativeTime);
    }
}
