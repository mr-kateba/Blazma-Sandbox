using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Blazma.Reporting.Interop;

/// <summary>
/// Name-based UUIDs (version 5, RFC 9562). Interop exports derive every identifier from
/// content so exporting the same analysis twice gives byte-identical files, and tools that
/// merge objects by ID (MISP, TAXII servers) see the same object, not a duplicate.
/// </summary>
public static class DeterministicId
{
    /// <summary>Namespace for Blazma's own identifiers (SDOs, rules, attributes).</summary>
    public const string BlazmaNamespace = "6d1eb783-a9ae-4190-a69b-1d504a222500";

    /// <summary>The namespace STIX 2.1 (section 2.9) fixes for cyber-observable object IDs.</summary>
    public const string StixObservableNamespace = "00abedb4-aa42-466c-9c01-fed23315a9b7";

    /// <summary>A UUIDv5 of <paramref name="name"/> (UTF-8) in <paramref name="namespaceId"/>, lowercase with dashes.</summary>
    public static string Uuid5(string namespaceId, string name)
    {
        var ns = Convert.FromHexString(namespaceId.Replace("-", "", StringComparison.Ordinal));
        if (ns.Length != 16) throw new ArgumentException("Namespace must be a UUID.", nameof(namespaceId));
        var input = new byte[16 + Encoding.UTF8.GetByteCount(name)];
        ns.CopyTo(input, 0);
        Encoding.UTF8.GetBytes(name, 0, name.Length, input, 16);
#pragma warning disable CA5350 // SHA-1 is what the UUIDv5 algorithm specifies; it is not used for security here.
        var hash = SHA1.HashData(input);
#pragma warning restore CA5350
        hash[6] = (byte)((hash[6] & 0x0F) | 0x50);
        hash[8] = (byte)((hash[8] & 0x3F) | 0x80);
        var hex = Convert.ToHexStringLower(hash.AsSpan(0, 16));
        return string.Create(CultureInfo.InvariantCulture, $"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..32]}");
    }

    /// <summary>A Blazma-namespace UUIDv5 over the given parts, joined with a separator that cannot occur in them.</summary>
    public static string For(params string?[] parts) => Uuid5(BlazmaNamespace, string.Join('\u001f', parts.Select(p => p ?? string.Empty)));

    /// <summary>
    /// RFC 8785 (JSON Canonicalization Scheme) form of a string, as STIX uses to name
    /// observables: only quote, backslash and control characters are escaped.
    /// </summary>
    public static string CanonicalJsonString(string value)
    {
        var sb = new StringBuilder(value.Length + 2).Append('"');
        foreach (var c in value)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append(CultureInfo.InvariantCulture, $"\\u{(int)c:x4}");
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }
}
