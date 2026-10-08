using System.Text;
using System.Text.Json;

namespace Blazma.Intelligence.Net;

/// <summary>Cleans text that came from outside (a web service, a model, a sample) before Blazma shows or forwards it.</summary>
internal static class SafeText
{
    /// <summary>
    /// Removes control characters (keeping new lines and tabs when <paramref name="multiline"/>)
    /// and the bidirectional overrides that can make text read differently than it is, then clips.
    /// </summary>
    public static string Clean(string? text, int maxLength, bool multiline = false)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        var sb = new StringBuilder(Math.Min(text.Length, maxLength));
        foreach (var c in text.Replace("\r\n", "\n", StringComparison.Ordinal))
        {
            if (sb.Length >= maxLength) break;
            if (c is '\n' or '\t' && multiline) sb.Append(c);
            else if (c is '\n' or '\r' or '\t') sb.Append(' ');
            else if (char.IsControl(c) || IsBidiControl(c)) continue;
            else sb.Append(c);
        }
        if (sb.Length > 0 && char.IsHighSurrogate(sb[^1])) sb.Length--;
        return sb.ToString().Trim();
    }

    public static string? CleanOrNull(string? text, int maxLength)
    {
        var clean = Clean(text, maxLength);
        return clean.Length == 0 ? null : clean;
    }

    private static bool IsBidiControl(char c) => c is >= '‪' and <= '‮' or >= '⁦' and <= '⁩' or '‎' or '‏' or '؜';

    /// <summary>A SHA-256 as hex: exactly 64 characters 0-9, a-f (any case). Nothing is sent for anything else.</summary>
    public static bool IsSha256(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);

    /// <summary>An API key that can travel in an HTTP header: printable ASCII, no spaces, reasonable length.</summary>
    public static bool IsHeaderSafeKey(string key) => key.Length is > 0 and <= 512 && key.All(c => c is > ' ' and <= '~');

    // Defensive JSON readers: wrong types and missing members give nothing instead of throwing.

    public static JsonElement? Object(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Object ? v : null;

    public static JsonElement? Array(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array ? v : null;

    public static string? String(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public static long? Integer(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n) ? n : null;

    /// <summary>Up to <paramref name="max"/> distinct, cleaned strings from a JSON array of strings.</summary>
    public static IReadOnlyList<string> Strings(JsonElement? array, int max, int maxLength)
    {
        if (array is not { ValueKind: JsonValueKind.Array } a) return [];
        var list = new List<string>();
        foreach (var item in a.EnumerateArray())
        {
            if (list.Count >= max) break;
            if (item.ValueKind != JsonValueKind.String) continue;
            var s = Clean(item.GetString(), maxLength);
            if (s.Length > 0 && !list.Contains(s, StringComparer.OrdinalIgnoreCase)) list.Add(s);
        }
        return list;
    }

    public static JsonDocumentOptions JsonOptions { get; } = new() { MaxDepth = 64, CommentHandling = JsonCommentHandling.Disallow };
}
