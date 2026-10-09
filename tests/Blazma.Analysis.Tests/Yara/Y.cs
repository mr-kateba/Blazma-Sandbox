using System.Text;
using Blazma.Analysis.Yara;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Tests.Yara;

/// <summary>Small helpers so each test reads as rule text plus data.</summary>
internal static class Y
{
    public static YaraRuleSet Rules(string source)
    {
        var set = YaraRuleSet.FromSources([(source, "test.yar")]);
        Assert.True(set.LoadErrors.Count == 0, string.Join("\n", set.LoadErrors));
        return set;
    }

    public static IReadOnlyList<YaraMatch> Scan(string source, byte[] data) => Rules(source).Scan(data, "sample");

    public static IReadOnlyList<YaraMatch> Scan(string source, string ascii) => Scan(source, Bytes(ascii));

    /// <summary>Wraps strings and a condition into one rule named "t" and says whether it matched.</summary>
    public static bool Matches(string strings, string condition, byte[] data) =>
        Scan($"rule t {{ {(strings.Length > 0 ? "strings: " + strings : string.Empty)} condition: {condition} }}", data).Any(m => m.Rule == "t");

    public static bool Matches(string strings, string condition, string ascii) => Matches(strings, condition, Bytes(ascii));

    public static bool Cond(string condition, string ascii = "") => Matches(string.Empty, condition, ascii);

    public static IReadOnlyList<string> Errors(string source) => YaraCompiler.Compile(source, "bad.yar").Errors;

    public static string SingleError(string source)
    {
        var errors = Errors(source);
        Assert.True(errors.Count == 1, "expected one error, got: " + string.Join(" | ", errors));
        return errors[0];
    }

    public static byte[] Wide(string s) => Encoding.Unicode.GetBytes(s);

    public static byte[] Cat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    public static byte[] Bytes(string ascii) => Encoding.Latin1.GetBytes(ascii);
}
