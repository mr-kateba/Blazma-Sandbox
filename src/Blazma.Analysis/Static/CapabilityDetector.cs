using System.Buffers;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Static;

/// <summary>
/// capa-style capability detection from imports and strings, without running anything. Every
/// rule in <see cref="CapabilityCatalog"/> requires a combination of features, because legitimate
/// programs use most Windows APIs on their own. Results are potential abilities, never observed
/// behavior.
/// </summary>
public static class CapabilityDetector
{
    private const int MaxEvidencePerCapability = 12;
    private const int MaxEvidenceTextLength = 120;

    /// <summary>The catalog without evidence, for documentation and settings screens.</summary>
    public static IReadOnlyList<Capability> Catalog { get; } = CapabilityCatalog.Rules.Select(r => r.ToCapability([])).ToList();

    /// <summary>Detects capabilities in a PE (imports and strings) or a script (strings only).</summary>
    public static IReadOnlyList<Capability> Detect(PeInfo? pe, ReadOnlySpan<byte> content) =>
        Detect(pe?.Imports ?? [], StringExtractor.Runs(content));

    public static IReadOnlyList<Capability> Detect(IReadOnlyList<PeImport> imports, IReadOnlyList<string> strings) =>
        Detect(CapabilityFeatures.From(imports, strings));

    internal static IReadOnlyList<Capability> Detect(CapabilityFeatures features)
    {
        var matched = new List<(CapabilityRule Rule, List<string> Evidence)>();
        foreach (var rule in CapabilityCatalog.Rules)
        {
            var evidence = new List<string>();
            if (rule.When.Evaluate(features, evidence)) matched.Add((rule, evidence));
        }

        var superseded = matched.SelectMany(m => m.Rule.Supersedes).ToHashSet(StringComparer.Ordinal);
        return matched
            .Where(m => !superseded.Contains(m.Rule.Id))
            .OrderByDescending(m => m.Rule.Severity)
            .ThenBy(m => m.Rule.Id, StringComparer.Ordinal)
            .Select(m => m.Rule.ToCapability(m.Evidence.Distinct(StringComparer.Ordinal).Take(MaxEvidencePerCapability).ToList()))
            .ToList();
    }

    internal static string Clip(string s) => s.Length > MaxEvidenceTextLength ? s[..MaxEvidenceTextLength] + "…" : s;
}

/// <summary>
/// The features rules look at, gathered once per file. Only names and patterns the catalog
/// mentions are kept, so memory stays bounded whatever the file contains.
/// </summary>
internal sealed class CapabilityFeatures
{
    /// <summary>Catalog API name → "import: lib!Name".</summary>
    public Dictionary<string, string> Imports { get; } = new(StringComparer.Ordinal);

    /// <summary>Catalog API name → "string: Name" when the name appears as an identifier in the strings.</summary>
    public Dictionary<string, string> ApiStrings { get; } = new(StringComparer.Ordinal);

    public HashSet<string> Tokens { get; } = new(StringComparer.Ordinal);

    /// <summary>Catalog text pattern → the text as it appears in the file.</summary>
    public Dictionary<string, string> Texts { get; } = new(StringComparer.Ordinal);

    public static CapabilityFeatures From(IReadOnlyList<PeImport> imports, IReadOnlyList<string> strings)
    {
        var f = new CapabilityFeatures();
        var apis = CapabilityCatalog.ApiNames;

        foreach (var import in imports)
        {
            var lower = import.Library.ToLowerInvariant();
            var dot = lower.LastIndexOf('.');
            var stem = dot > 0 ? lower[..dot] : lower;
            ImpHashOrdinals.ByLibrary.TryGetValue(lower, out var ordinals);
            foreach (var function in import.Functions)
            {
                var name = function;
                if (function.StartsWith('#') && int.TryParse(function.AsSpan(1), out var ordinal) && ordinals is not null && ordinals.TryGetValue(ordinal, out var resolved))
                    name = resolved;
                if (Canonical(name, apis) is { } api) f.Imports.TryAdd(api, $"import: {stem}!{name}");
            }
        }

        var apiLookup = apis.GetAlternateLookup<ReadOnlySpan<char>>();
        var tokenLookup = CapabilityCatalog.TokenNames.GetAlternateLookup<ReadOnlySpan<char>>();
        foreach (var s in strings) ScanIdentifiers(s, f, apiLookup, tokenLookup);

        ScanTexts(string.Join('\n', strings), f);
        return f;
    }

    /// <summary>The catalog name for an API, accepting the ANSI/Unicode "A"/"W" variants.</summary>
    private static string? Canonical(string name, HashSet<string> apis)
    {
        if (apis.TryGetValue(name, out var exact)) return exact;
        if (name.Length > 1 && name[^1] is 'A' or 'W' && apis.TryGetValue(name[..^1], out var trimmed)) return trimmed;
        return null;
    }

    private static void ScanIdentifiers(string s, CapabilityFeatures f,
        HashSet<string>.AlternateLookup<ReadOnlySpan<char>> apis,
        HashSet<string>.AlternateLookup<ReadOnlySpan<char>> tokens)
    {
        var span = s.AsSpan();
        var i = 0;
        while (i < span.Length)
        {
            if (!IsIdentifierStart(span[i])) { i++; continue; }
            var start = i;
            while (i < span.Length && IsIdentifierPart(span[i])) i++;
            var word = span[start..i];
            if (tokens.TryGetValue(word, out var token)) f.Tokens.Add(token);
            if (apis.TryGetValue(word, out var api) || (word.Length > 1 && word[^1] is 'A' or 'W' && apis.TryGetValue(word[..^1], out api)))
            {
                if (CapabilityCatalog.StringEligible(api)) f.ApiStrings.TryAdd(api, "string: " + word.ToString());
            }
        }
    }

    private static bool IsIdentifierStart(char c) => char.IsAsciiLetter(c) || c == '_';
    private static bool IsIdentifierPart(char c) => char.IsAsciiLetterOrDigit(c) || c == '_';

    /// <summary>
    /// Finds every catalog pattern in one vectorized pass: each hit removes the patterns found from
    /// the search set, so the loop runs at most once per pattern however often a text repeats.
    /// </summary>
    private static void ScanTexts(string corpus, CapabilityFeatures f)
    {
        var remaining = CapabilityCatalog.TextPatterns.ToList();
        var span = corpus.AsSpan();
        var position = 0;
        while (remaining.Count > 0 && position < span.Length)
        {
            var search = SearchValues.Create(remaining.ToArray(), StringComparison.OrdinalIgnoreCase);
            var hit = span[position..].IndexOfAny(search);
            if (hit < 0) break;
            var at = position + hit;
            var rest = span[at..];
            var removed = 0;
            for (var k = remaining.Count - 1; k >= 0; k--)
            {
                var p = remaining[k];
                if (!rest.StartsWith(p, StringComparison.OrdinalIgnoreCase)) continue;
                f.Texts[p] = CapabilityDetector.Clip(rest[..p.Length].ToString());
                remaining.RemoveAt(k);
                removed++;
            }
            position = removed > 0 ? at : at + 1; // never loop on the same spot
        }
    }
}

/// <summary>One condition of a capability rule. Evidence is only kept when the whole rule matches.</summary>
internal abstract class CapabilityCondition
{
    public abstract bool Evaluate(CapabilityFeatures f, List<string> evidence);

    /// <summary>For the catalog's lookup sets.</summary>
    public virtual IEnumerable<CapabilityCondition> Children => [];
}

/// <summary>An API imported, or (for API-like names) present as a string, i.e. possibly resolved at run time.</summary>
internal sealed class ApiCondition(string name, bool allowImport = true, bool allowString = true, bool requireNotImported = false) : CapabilityCondition
{
    public string Name { get; } = name;

    public override bool Evaluate(CapabilityFeatures f, List<string> evidence)
    {
        if (f.Imports.TryGetValue(Name, out var imported))
        {
            if (requireNotImported) return false;
            if (allowImport) { evidence.Add(imported); return true; }
        }
        if (allowString && f.ApiStrings.TryGetValue(Name, out var text)) { evidence.Add(text); return true; }
        return false;
    }
}

/// <summary>An identifier in the strings (e.g. a .NET member name), matched case-sensitively as a whole word.</summary>
internal sealed class TokenCondition(string token) : CapabilityCondition
{
    public string Token { get; } = token;

    public override bool Evaluate(CapabilityFeatures f, List<string> evidence)
    {
        if (!f.Tokens.Contains(Token)) return false;
        evidence.Add("string: " + Token);
        return true;
    }
}

/// <summary>A case-insensitive substring of any string in the file.</summary>
internal sealed class TextCondition(string pattern) : CapabilityCondition
{
    public string Pattern { get; } = pattern;

    public override bool Evaluate(CapabilityFeatures f, List<string> evidence)
    {
        if (!f.Texts.TryGetValue(Pattern, out var found)) return false;
        evidence.Add("string: " + found);
        return true;
    }
}

/// <summary>At least <c>min</c> of the parts; every matching part contributes evidence.</summary>
internal sealed class CountCondition(int min, CapabilityCondition[] parts) : CapabilityCondition
{
    public override IEnumerable<CapabilityCondition> Children => parts;

    public override bool Evaluate(CapabilityFeatures f, List<string> evidence)
    {
        var local = new List<string>();
        var count = 0;
        foreach (var p in parts)
            if (p.Evaluate(f, local)) count++;
        if (count < min) return false;
        evidence.AddRange(local);
        return true;
    }
}

internal sealed class AllCondition(CapabilityCondition[] parts) : CapabilityCondition
{
    public override IEnumerable<CapabilityCondition> Children => parts;

    public override bool Evaluate(CapabilityFeatures f, List<string> evidence)
    {
        var local = new List<string>();
        foreach (var p in parts)
            if (!p.Evaluate(f, local)) return false;
        evidence.AddRange(local);
        return true;
    }
}
