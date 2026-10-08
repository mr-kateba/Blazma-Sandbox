using System.Globalization;
using System.Text;

namespace Blazma.Reporting.Interop;

/// <summary>
/// Writes one YAML scalar so any parser reads back exactly the same string. Values from a
/// sample can contain quotes, colons, '#', backslashes, line breaks or look like booleans and
/// numbers; a hand-rolled emitter that only quotes "when needed" gets this wrong easily, so
/// plain style is used only for a small, obviously safe alphabet.
/// </summary>
public static class YamlScalar
{
    private static readonly HashSet<string> Reserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "true", "false", "yes", "no", "on", "off", "y", "n", "null", "~",
    };

    public static string Write(string value)
    {
        if (IsPlainSafe(value)) return value;
        return NeedsEscapes(value) ? DoubleQuoted(value) : "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
    }

    /// <summary>Starts with a letter and uses only letters, digits, space and <c>_ . - / ( )</c>: never a number, date, flow or comment.</summary>
    private static bool IsPlainSafe(string value) =>
        value.Length > 0 && char.IsAsciiLetter(value[0]) && value[^1] != ' ' && !Reserved.Contains(value)
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c is ' ' or '_' or '.' or '-' or '/' or '(' or ')');

    /// <summary>Characters single quotes cannot carry literally (line breaks fold, control characters are not printable).</summary>
    private static bool NeedsEscapes(string value) =>
        value.Any(c => char.IsControl(c) || char.IsSurrogate(c) || c is '\u2028' or '\u2029' or '\uFEFF');

    private static string DoubleQuoted(string value)
    {
        var sb = new StringBuilder(value.Length + 8).Append('"');
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\0': sb.Append("\\0"); break;
                default:
                    if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
                    {
                        sb.Append(c).Append(value[++i]);
                    }
                    else if (char.IsSurrogate(c))
                    {
                        sb.Append('\uFFFD'); // a lone surrogate is not a character YAML (or UTF-8) can carry
                    }
                    else if (char.IsControl(c) || c is '\u2028' or '\u2029' or '\uFEFF')
                    {
                        sb.Append(CultureInfo.InvariantCulture, $"\\u{(int)c:X4}");
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
            }
        }
        return sb.Append('"').ToString();
    }
}
