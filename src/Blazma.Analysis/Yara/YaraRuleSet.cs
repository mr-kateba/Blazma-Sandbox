using System.Text;
using Blazma.Core.Abstractions;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Yara;

/// <summary>The matches of one scan, plus anything that made the scan less than exact (time budgets, loop caps).</summary>
public sealed record YaraScanResult(IReadOnlyList<YaraMatch> Matches, IReadOnlyList<string> Warnings);

/// <summary>
/// A set of compiled rules that scans bytes. Each source (file) is its own namespace: rule
/// references and global rules apply within the file they are written in, so one file's
/// global rule cannot silence another file's rules. Strings are searched lazily, the first
/// time a condition needs them, so cheap checks such as <c>uint16(0) == 0x5A4D</c> written
/// first avoid searching at all.
/// </summary>
public sealed class YaraRuleSet : IYaraScanner
{
    private readonly YaraCompilation[] _groups;
    private readonly YaraRule[] _rules;
    private readonly int[] _ruleBase;
    private readonly int[] _stringBase;
    private readonly YaraString[] _strings;
    private readonly int _maxSlots;

    private YaraRuleSet(IEnumerable<YaraCompilation> compilations, IEnumerable<string> extraErrors)
    {
        _groups = compilations.ToArray();
        _rules = _groups.SelectMany(g => g.Rules).ToArray();
        _ruleBase = new int[_groups.Length];
        for (int g = 0, n = 0; g < _groups.Length; n += _groups[g].Rules.Count, g++) _ruleBase[g] = n;
        _stringBase = new int[_rules.Length];
        var strings = new List<YaraString>();
        for (var r = 0; r < _rules.Length; r++)
        {
            _stringBase[r] = strings.Count;
            strings.AddRange(_rules[r].Strings);
        }
        _strings = [.. strings];
        _maxSlots = _rules.Length == 0 ? 0 : _rules.Max(r => r.VariableSlots);
        LoadErrors = [.. extraErrors, .. _groups.SelectMany(g => g.Errors)];
    }

    public int RuleCount => _rules.Length;
    public IReadOnlyList<string> LoadErrors { get; }
    public IReadOnlyList<YaraRule> Rules => _rules;

    public static YaraRuleSet FromCompilations(IEnumerable<YaraCompilation> compilations) => new(compilations, []);

    public static YaraRuleSet FromSources(IEnumerable<(string Source, string Origin)> sources) =>
        new(sources.Select(s => YaraCompiler.Compile(s.Source, s.Origin)).ToList(), []);

    /// <summary>
    /// Loads every *.yar and *.yara file under a folder (recursively, symbolic links not
    /// followed). Never throws: unreadable, oversized or surplus files become load errors.
    /// </summary>
    public static YaraRuleSet LoadFolder(string folder)
    {
        var errors = new List<string>();
        var compilations = new List<YaraCompilation>();
        try
        {
            if (!Directory.Exists(folder)) return new YaraRuleSet([], [$"{folder}: rules folder not found"]);
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint,
                MaxRecursionDepth = 16,
            };
            var files = Directory.EnumerateFiles(folder, "*", options)
                .Where(f => Path.GetExtension(f).Equals(".yar", StringComparison.OrdinalIgnoreCase) || Path.GetExtension(f).Equals(".yara", StringComparison.OrdinalIgnoreCase))
                .Order(StringComparer.Ordinal)
                .ToList();
            if (files.Count > YaraLimits.MaxRuleFiles)
            {
                errors.Add($"{folder}: more than {YaraLimits.MaxRuleFiles} rule files; only the first {YaraLimits.MaxRuleFiles} were loaded");
                files = files.Take(YaraLimits.MaxRuleFiles).ToList();
            }
            foreach (var file in files)
            {
                try
                {
                    var info = new FileInfo(file);
                    if (info.Length > YaraLimits.MaxRuleFileBytes)
                    {
                        errors.Add($"{file}: skipped, larger than {YaraLimits.MaxRuleFileBytes / (1024 * 1024)} MB");
                        continue;
                    }
                    compilations.Add(YaraCompiler.Compile(File.ReadAllText(file), file));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DecoderFallbackException)
                {
                    errors.Add($"{file}: could not be read ({ex.Message})");
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException)
        {
            errors.Add($"{folder}: could not be listed ({ex.Message})");
        }
        return new YaraRuleSet(compilations, errors);
    }

    public IReadOnlyList<YaraMatch> Scan(ReadOnlySpan<byte> data, string target) => ScanDetailed(data, target).Matches;

    public YaraScanResult ScanDetailed(ReadOnlySpan<byte> data, string target)
    {
        var warnings = new List<string>();
        var state = new YaraScanState
        {
            Data = data,
            View = new ByteViewCache(),
            Strings = _strings,
            Hits = new List<YaraHit>?[_strings.Length],
            RuleResults = new bool[_rules.Length],
            Vars = new long[Math.Max(1, _maxSlots)],
            Warnings = warnings,
            ScanDeadline = YaraClock.After(YaraLimits.ScanBudget),
            CurrentString = -1,
            RuleName = string.Empty,
        };

        var matches = new List<YaraMatch>();
        for (var g = 0; g < _groups.Length; g++)
        {
            var rules = _groups[g].Rules;
            var globalFailed = false;
            for (var i = 0; i < rules.Count; i++)
            {
                var index = _ruleBase[g] + i;
                state.RuleResults[index] = Evaluate(ref state, rules[i], index, _ruleBase[g]);
                if (rules[i].IsGlobal && !state.RuleResults[index]) globalFailed = true;
            }
            if (globalFailed) continue;
            for (var i = 0; i < rules.Count; i++)
            {
                var index = _ruleBase[g] + i;
                if (state.RuleResults[index] && !rules[i].IsPrivate) matches.Add(Report(ref state, rules[i], index, target));
            }
        }
        return new YaraScanResult(matches, warnings);
    }

    private bool Evaluate(ref YaraScanState state, YaraRule rule, int index, int ruleBase)
    {
        state.StringBase = _stringBase[index];
        state.RuleBase = ruleBase;
        state.RuleName = rule.Name;
        state.CurrentString = -1;
        state.Steps = 0;
        try
        {
            return rule.Condition.Eval(ref state).IsTrue;
        }
        catch (YaraBudgetException)
        {
            state.Warnings.Add($"Rule {rule.Name}: evaluation stopped after {YaraLimits.MaxEvaluationSteps} steps; the rule counts as not matching.");
            return false;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            state.Warnings.Add($"Rule {rule.Name}: evaluation failed ({ex.GetType().Name}); the rule counts as not matching.");
            return false;
        }
    }

    private YaraMatch Report(ref YaraScanState state, YaraRule rule, int index, string target)
    {
        state.StringBase = _stringBase[index];
        state.RuleName = rule.Name;
        state.Steps = 0;
        var hits = new List<YaraStringHit>();
        var reported = 0;
        for (var i = 0; i < rule.Strings.Length && reported < YaraLimits.MaxReportedStrings; i++)
        {
            var str = rule.Strings[i];
            if (str.IsPrivate) continue;
            var list = state.HitsOf(i);
            if (list.Count == 0) continue;
            reported++;
            foreach (var h in list.Take(YaraLimits.MaxReportedHitsPerString))
                hits.Add(new YaraStringHit(str.Identifier, h.Offset, Preview(state.Data, h)));
        }
        return new YaraMatch
        {
            Rule = rule.Name,
            Source = rule.Origin,
            Target = target,
            Tags = rule.Tags,
            Meta = rule.Meta,
            Strings = hits,
        };
    }

    /// <summary>
    /// A short, safe rendering of matched bytes: text when the bytes are mostly printable
    /// (wide text has its zero bytes dropped), otherwise hex. Never more than
    /// <see cref="YaraLimits.PreviewBytes"/> bytes, never control characters.
    /// </summary>
    internal static string Preview(ReadOnlySpan<byte> data, YaraHit hit)
    {
        var slice = data.Slice(hit.Offset, Math.Min(hit.Length, YaraLimits.PreviewBytes));
        var suffix = hit.Length > YaraLimits.PreviewBytes ? "…" : string.Empty;
        if (slice.IsEmpty) return string.Empty;

        var wide = slice.Length >= 4 && slice.Length % 2 == 0;
        for (var i = 1; wide && i < slice.Length; i += 2) wide = slice[i] == 0;
        var sb = new StringBuilder();
        var printable = 0;
        for (var i = 0; i < slice.Length; i += wide ? 2 : 1)
        {
            var b = slice[i];
            var ok = b is >= 0x20 and < 0x7F;
            if (ok) printable++;
            sb.Append(ok ? (char)b : '.');
        }
        if (printable * 4 >= sb.Length * 3) return sb + suffix;
        return string.Join(' ', slice.ToArray().Select(b => b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture))) + suffix;
    }
}
