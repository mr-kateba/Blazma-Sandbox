using System.Diagnostics.CodeAnalysis;
using System.Net;
using Blazma.Core.Text;

namespace Blazma.Intelligence.Ai;

/// <summary>
/// Decides whether an AI endpoint may receive a prompt. By default only this computer is
/// accepted: 127.0.0.0/8, ::1 and "localhost". The address must be written plainly: user
/// names, queries, fragments and unusual number forms (2130706433, 0x7f.1, 0177.0.0.1) are
/// refused, so what the user reads is exactly where the prompt goes.
/// </summary>
public static class AiEndpointPolicy
{
    public static bool TryValidate(string? endpoint, bool allowRemote, [NotNullWhen(true)] out Uri? baseUri, [NotNullWhen(false)] out LocalizedText? error)
    {
        baseUri = null;
        error = null;
        var text = endpoint?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            error = new("No AI server address is set.", "لم يُحدَّد عنوان خادم الذكاء الاصطناعي.");
            return false;
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            error = new("The AI server address must start with http:// or https://.", "يجب أن يبدأ عنوان خادم الذكاء الاصطناعي بـ http:// أو https://.");
            return false;
        }

        if (uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0 || text.Contains('@', StringComparison.Ordinal)
            || !text.Contains(uri.Host, StringComparison.OrdinalIgnoreCase))
        {
            error = new("The AI server address is not in a plain form (for example http://127.0.0.1:11434).",
                "عنوان خادم الذكاء الاصطناعي ليس بصيغة بسيطة (مثل http://127.0.0.1:11434).");
            return false;
        }

        if (!allowRemote && !IsLoopback(uri))
        {
            error = new("Only an AI server on this computer is allowed (127.0.0.1, ::1 or localhost). Remote servers must be allowed in Settings first.",
                "يُسمح فقط بخادم ذكاء اصطناعي على هذا الجهاز (127.0.0.1 أو ::1 أو localhost). يجب السماح بالخوادم البعيدة من الإعدادات أولًا.");
            return false;
        }

        baseUri = uri;
        return true;
    }

    /// <summary>True for loopback IP addresses and the literal name "localhost".</summary>
    public static bool IsLoopback(Uri uri) => uri.HostNameType switch
    {
        UriHostNameType.Dns => string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase),
        UriHostNameType.IPv4 or UriHostNameType.IPv6 => IPAddress.TryParse(uri.DnsSafeHost, out var ip) && IPAddress.IsLoopback(ip),
        _ => false,
    };

    /// <summary>Appends an API path to the base address, keeping any path the user gave (e.g. ".../v1").</summary>
    internal static Uri Combine(Uri baseUri, string relative) =>
        new(baseUri.GetLeftPart(UriPartial.Path).TrimEnd('/') + "/" + relative.TrimStart('/'));
}
