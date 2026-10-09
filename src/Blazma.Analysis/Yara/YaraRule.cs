namespace Blazma.Analysis.Yara;

/// <summary>A compiled YARA rule. Immutable, so one rule set can scan from several threads.</summary>
public sealed class YaraRule
{
    internal YaraRule(string name, string origin, int line, bool isPrivate, bool isGlobal, IReadOnlyList<string> tags,
        IReadOnlyDictionary<string, string> meta, YaraString[] strings, YExpr condition, int variableSlots)
    {
        Name = name;
        Origin = origin;
        Line = line;
        IsPrivate = isPrivate;
        IsGlobal = isGlobal;
        Tags = tags;
        Meta = meta;
        Strings = strings;
        Condition = condition;
        VariableSlots = variableSlots;
    }

    public string Name { get; }

    /// <summary>The file (or other source) the rule came from.</summary>
    public string Origin { get; }

    public int Line { get; }

    /// <summary>Private rules are evaluated and can be referenced, but are never reported.</summary>
    public bool IsPrivate { get; }

    /// <summary>When a global rule does not match, no rule from the same source matches.</summary>
    public bool IsGlobal { get; }

    public IReadOnlyList<string> Tags { get; }
    public IReadOnlyDictionary<string, string> Meta { get; }

    internal YaraString[] Strings { get; }
    internal YExpr Condition { get; }
    internal int VariableSlots { get; }
}

/// <summary>
/// The rules compiled from one source. Rules that failed (unsupported feature, bad string)
/// are left out and described in <see cref="Errors"/>; a syntax error leaves no rules.
/// </summary>
public sealed class YaraCompilation
{
    internal YaraCompilation(string origin, IReadOnlyList<YaraRule> rules, IReadOnlyList<string> errors)
    {
        Origin = origin;
        Rules = rules;
        Errors = errors;
    }

    public string Origin { get; }
    public IReadOnlyList<YaraRule> Rules { get; }

    /// <summary>"origin:line: message" for each problem.</summary>
    public IReadOnlyList<string> Errors { get; }
}

/// <summary>Compiles YARA rule text with Blazma's managed engine (no native libyara).</summary>
public static class YaraCompiler
{
    /// <summary>Never throws for bad rule text; problems are returned as errors.</summary>
    public static YaraCompilation Compile(string source, string origin)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(origin);
        return new YaraParser(source, origin).Parse();
    }
}
