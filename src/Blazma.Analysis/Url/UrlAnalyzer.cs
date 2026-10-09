using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Blazma.Analysis.Static;
using Blazma.Core.Samples;
using Blazma.Core.Text;

namespace Blazma.Analysis.Url;

/// <summary>
/// Reads a web address before anyone opens it: who the host really is, and the tricks phishing
/// links use to look like somewhere else (IP hosts written as one big number, punycode, mixed
/// alphabets, a user name before '@', brand look-alikes). Pure string analysis; nothing is
/// resolved or fetched.
/// </summary>
public static class UrlAnalyzer
{
    public const int MaxUrlLength = 2048;

    /// <summary>
    /// Top-level domains that public abuse statistics (Spamhaus, Interisle) consistently rank among
    /// the most abused relative to their size, plus the free Freenom domains and the file-name-like
    /// .zip and .mov. Modest on purpose: it is a hint shown to the user, not a verdict.
    /// </summary>
    private static readonly HashSet<string> RiskyTlds = new(
        ["tk", "ml", "ga", "cf", "gq", "top", "xyz", "icu", "buzz", "cyou", "cfd", "sbs", "bond", "rest", "monster",
         "quest", "click", "zip", "mov", "su"],
        StringComparer.OrdinalIgnoreCase);

    private static readonly HashSet<string> Shorteners = new(
        ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "v.gd", "buff.ly", "rebrand.ly", "cutt.ly", "tiny.cc",
         "shorturl.at", "rb.gy", "bit.do", "t.ly", "s.id", "lnkd.in", "qrco.de", "shorte.st", "adf.ly", "bl.ink", "tiny.one",
         "x.co", "u.to", "clck.ru", "urlz.fr", "surl.li", "trib.al", "dlvr.it", "short.gy"],
        StringComparer.OrdinalIgnoreCase);

    /// <summary>Second-level suffixes under which the registrable domain has three labels ("example.co.uk").</summary>
    private static readonly HashSet<string> TwoLevelSuffixes = new(
        ["co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp", "com.br",
         "com.cn", "com.mx", "co.in", "co.za", "com.tr", "com.sa", "com.eg", "co.nz", "com.ar", "co.kr", "com.tw", "com.hk",
         "com.sg", "com.my", "co.id", "com.ua", "co.il", "com.pl", "com.vn", "com.ph"],
        StringComparer.OrdinalIgnoreCase);

    public static UrlReport Analyze(string url)
    {
        var uri = Parse(url, out var error) ?? throw new ArgumentException(error!.En, nameof(url));
        var normalized = Normalize(uri);
        var host = HostOf(uri);
        var notes = new List<LocalizedText>();

        // The IP check works on the host as typed, because the parser canonicalizes
        // "http://3232235777/" to 192.168.1.1 and the trick would vanish.
        var rawHost = RawHost(url);
        var ip = uri.HostNameType switch
        {
            UriHostNameType.IPv6 => host,
            UriHostNameType.IPv4 => uri.Host,
            _ => TryParseLooseIpv4(rawHost),
        };
        if (ip is not null)
        {
            notes.Add(new("The address uses an IP address instead of a domain name; legitimate sites rarely do this.",
                "يستخدم العنوان عنوان IP بدلًا من اسم نطاق، ونادرًا ما تفعل المواقع الموثوقة ذلك."));
            if (uri.HostNameType != UriHostNameType.IPv6 && !string.Equals(rawHost, ip, StringComparison.OrdinalIgnoreCase))
                notes.Add(new($"The IP address is written in an unusual form ({rawHost}) that hides the real address {ip}.",
                    $"كُتب عنوان IP بصيغة غير مألوفة ({rawHost}) تُخفي العنوان الحقيقي {ip}."));
        }

        string? unicodeHost = null;
        var mixes = false;
        if (ip is null && host.Contains("xn--", StringComparison.OrdinalIgnoreCase))
        {
            try { unicodeHost = new IdnMapping().GetUnicode(host); }
            catch (ArgumentException) { /* invalid punycode: keep the ASCII form */ }
            if (unicodeHost is not null)
            {
                notes.Add(new($"The domain is internationalized (punycode); a browser may display it as {unicodeHost}.",
                    $"اسم النطاق مُدوَّل (punycode)، وقد يعرضه المتصفح على الشكل {unicodeHost}."));
                mixes = unicodeHost.Split('.').Any(MixesScripts);
                if (mixes)
                    notes.Add(new("The domain mixes letters from different alphabets (for example Latin and Cyrillic), a common way to imitate another name.",
                        "يخلط اسم النطاق بين حروف من أبجديات مختلفة (كاللاتينية والسيريلية)، وهي طريقة شائعة لتقليد اسم آخر."));
            }
        }

        var credentials = uri.UserInfo.Length > 0;
        if (credentials)
            notes.Add(new("The address has a user name before '@'. Browsers ignore it, and it is often used to make the address look like another site.",
                "يحتوي العنوان على اسم مستخدم قبل الرمز '@'. تتجاهله المتصفحات، وكثيرًا ما يُستخدم لإيهام القارئ بأن العنوان يخص موقعًا آخر."));

        int? port = uri.IsDefaultPort ? null : uri.Port;
        if (port is { } p)
            notes.Add(new($"The address uses the non-standard port {p}.", $"يستخدم العنوان المنفذ غير القياسي {p}."));

        if (uri.Scheme == Uri.UriSchemeHttp)
            notes.Add(new("The address does not use an encrypted connection (HTTPS).", "لا يستخدم العنوان اتصالًا مشفّرًا (HTTPS)."));

        var registrable = ip is null ? RegistrableDomain(host) : host;
        var shortener = ip is null && Shorteners.Contains(registrable);
        if (shortener)
            notes.Add(new("This is a link shortener: the real destination stays hidden until the link is opened.",
                "هذا رابط مختصر، ولا تظهر وجهته الحقيقية إلا عند فتحه."));

        var tld = ip is null ? TopLevelDomains.Of(host).ToLowerInvariant() : "";
        var riskyTld = RiskyTlds.Contains(tld);
        if (riskyTld)
            notes.Add(new($"The top-level domain .{tld} is often abused for spam and phishing. On its own this proves nothing.",
                $"يُساء استخدام النطاق العلوي ‎.{tld} كثيرًا في الرسائل المزعجة والتصيّد، وهذا وحده لا يثبت شيئًا."));

        var depth = ip is null ? Math.Max(0, host.Split('.').Length - registrable.Split('.').Length) : 0;
        if (depth >= 3)
            notes.Add(new($"The address has {depth} levels of subdomains, which can push the real domain out of view.",
                $"يحتوي العنوان على {depth} مستويات من النطاقات الفرعية، وهذا قد يُبعد النطاق الحقيقي عن الأنظار."));

        var looksLike = ip is null ? BrandLookalikes.Find(unicodeHost ?? host, host, registrable, tld) : null;
        if (looksLike is not null)
            notes.Add(new($"The address resembles {looksLike} but is not one of its official domains.",
                $"يشبه العنوان {looksLike} لكنه ليس من نطاقاته الرسمية."));

        return new UrlReport
        {
            Url = normalized,
            Scheme = uri.Scheme,
            Host = host,
            UnicodeHost = unicodeHost,
            Port = port,
            HostIsIpAddress = ip is not null,
            HasEmbeddedCredentials = credentials,
            IsKnownShortener = shortener,
            UsesRiskyTopLevelDomain = riskyTld,
            MixesScripts = mixes,
            LooksLike = looksLike,
            SubdomainDepth = depth,
            Notes = notes,
        };
    }

    /// <summary>
    /// Turns what the user typed into a URL sample. The hashes are of the UTF-8 of the normalized
    /// address (<see cref="SampleInfo.Url"/>), so the same address always has the same identity
    /// in History however it was typed.
    /// </summary>
    public static bool TryCreateSample(string input, out SampleInfo? sample, out string? error)
    {
        var ok = TryCreateSample(input, out sample, out LocalizedText? text);
        error = text?.En;
        return ok;
    }

    /// <inheritdoc cref="TryCreateSample(string, out SampleInfo?, out string?)"/>
    public static bool TryCreateSample(string input, out SampleInfo? sample, out LocalizedText? error)
    {
        sample = null;
        var uri = Parse(input, out error);
        if (uri is null) return false;

        var normalized = Normalize(uri);
        if (normalized.Length > MaxUrlLength)
        {
            error = TooLong;
            return false;
        }

        var bytes = Encoding.UTF8.GetBytes(normalized);
#pragma warning disable CA5350 // SHA-1 is kept for external tools, like every sample's; identity is SHA-256
        var sha1 = Convert.ToHexStringLower(SHA1.HashData(bytes));
#pragma warning restore CA5350
        sample = new SampleInfo
        {
            FileName = SafeFileName(HostOf(uri)),
            Size = bytes.Length,
            Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)),
            Sha1 = sha1,
            Kind = FileKind.Url,
            Url = normalized,
        };
        return true;
    }

    private static readonly LocalizedText TooLong = new($"The address is longer than {MaxUrlLength} characters.", $"يتجاوز طول العنوان {MaxUrlLength} حرف.");

    /// <summary>Validates and parses; http and https only, no whitespace or invisible characters, "https://" added when no scheme is given.</summary>
    private static Uri? Parse(string? input, out LocalizedText? error)
    {
        error = null;
        var text = input?.Trim() ?? "";
        if (text.Length == 0)
        {
            error = new("Enter a web address.", "أدخل عنوان ويب.");
            return null;
        }
        if (text.Length > MaxUrlLength)
        {
            error = TooLong;
            return null;
        }
        if (text.Any(c => char.IsControl(c) || char.IsWhiteSpace(c) || CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.Format))
        {
            error = new("The address contains spaces, control or invisible characters.", "يحتوي العنوان على مسافات أو محارف تحكم أو محارف غير مرئية.");
            return null;
        }

        var scheme = SchemeOf(text);
        if (scheme is null) text = "https://" + text;
        else if (!scheme.Equals("http", StringComparison.OrdinalIgnoreCase) && !scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            error = new("Only http and https addresses can be analyzed.", "لا يمكن تحليل سوى العناوين التي تبدأ بـ http أو https.");
            return null;
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || string.IsNullOrEmpty(uri.Host))
        {
            error = new("This is not a valid web address.", "هذا ليس عنوان ويب صالحًا.");
            return null;
        }
        return uri;
    }

    /// <summary>
    /// The scheme the text starts with, or null. "example.com:8080" and "localhost:80" have none:
    /// a scheme has no dot and is not followed by a port number.
    /// </summary>
    private static string? SchemeOf(string text)
    {
        var colon = text.IndexOf(':', StringComparison.Ordinal);
        if (colon <= 0) return null;
        var candidate = text[..colon];
        if (!char.IsAsciiLetter(candidate[0]) || candidate.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '+' or '-' or '.'))) return null;
        if (text.AsSpan(colon).StartsWith("://", StringComparison.Ordinal)) return candidate;
        if (candidate.Contains('.', StringComparison.Ordinal)) return null;
        return colon + 1 < text.Length && char.IsAsciiDigit(text[colon + 1]) ? null : candidate;
    }

    /// <summary>
    /// One spelling per address: lower-case scheme and host, the host in punycode, no default
    /// port, path, query and fragment as the parser escapes them.
    /// </summary>
    private static string Normalize(Uri uri)
    {
        var host = uri.HostNameType == UriHostNameType.IPv6 ? uri.Host : uri.IdnHost;
        var userInfo = uri.UserInfo.Length > 0 ? uri.UserInfo + "@" : "";
        var port = uri.IsDefaultPort ? "" : ":" + uri.Port.ToString(CultureInfo.InvariantCulture);
        return $"{uri.Scheme}://{userInfo}{host.ToLowerInvariant()}{port}{uri.PathAndQuery}{uri.Fragment}";
    }

    private static string HostOf(Uri uri) => (uri.HostNameType == UriHostNameType.IPv6 ? uri.Host.Trim('[', ']') : uri.IdnHost).TrimEnd('.').ToLowerInvariant();

    /// <summary>The host exactly as typed (no user name, no port), for spotting numeric IP forms.</summary>
    private static string RawHost(string url)
    {
        var text = url.Trim();
        var start = text.IndexOf("://", StringComparison.Ordinal);
        text = start >= 0 ? text[(start + 3)..] : text;
        var end = text.IndexOfAny(['/', '?', '#', '\\']);
        if (end >= 0) text = text[..end];
        var at = text.LastIndexOf('@');
        if (at >= 0) text = text[(at + 1)..];
        if (text.StartsWith('[')) return text;
        var colon = text.LastIndexOf(':');
        return (colon >= 0 ? text[..colon] : text).TrimEnd('.').ToLowerInvariant();
    }

    /// <summary>
    /// The forms browsers accept for IPv4 (inet_aton): one to four parts, each decimal, hex
    /// ("0x7f") or octal ("0177"), the last part filling the remaining bytes. Returns the
    /// dotted-quad form, or null when the host is a name.
    /// </summary>
    internal static string? TryParseLooseIpv4(string host)
    {
        var parts = host.Split('.');
        if (parts.Length is < 1 or > 4 || parts.Any(p => p.Length == 0)) return null;
        var values = new ulong[parts.Length];
        for (var i = 0; i < parts.Length; i++)
        {
            var p = parts[i];
            ulong v;
            if (p.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                if (p.Length == 2 || p.Length > 10 || !ulong.TryParse(p.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out v)) return null;
            }
            else if (p.Length > 1 && p[0] == '0')
            {
                if (p.Length > 12 || p.Any(c => c is < '0' or > '7')) return null;
                v = p.Aggregate(0UL, (acc, c) => acc * 8 + (ulong)(c - '0'));
            }
            else if (p.Length > 10 || !p.All(char.IsAsciiDigit) || !ulong.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out v))
            {
                return null;
            }
            values[i] = v;
        }

        for (var i = 0; i < values.Length - 1; i++) if (values[i] > 255) return null;
        var lastBytes = 4 - (values.Length - 1);
        if (values[^1] >= 1UL << (8 * lastBytes)) return null;

        ulong address = 0;
        for (var i = 0; i < values.Length - 1; i++) address |= values[i] << (8 * (3 - i));
        address |= values[^1];
        return string.Join('.', Enumerable.Range(0, 4).Select(i => ((address >> (8 * (3 - i))) & 0xFF).ToString(CultureInfo.InvariantCulture)));
    }

    /// <summary>The domain a person registers: the last two labels, or three under suffixes such as "co.uk".</summary>
    internal static string RegistrableDomain(string host)
    {
        var labels = host.TrimEnd('.').Split('.');
        if (labels.Length <= 2) return host;
        var take = TwoLevelSuffixes.Contains($"{labels[^2]}.{labels[^1]}") ? 3 : 2;
        return string.Join('.', labels[^take..]);
    }

    /// <summary>Whether one label uses letters from more than one script (digits and hyphens are neutral).</summary>
    internal static bool MixesScripts(string label)
    {
        string? first = null;
        foreach (var c in label)
        {
            var script = ScriptOf(c);
            if (script is null) continue;
            if (first is null) first = script;
            else if (first != script) return true;
        }
        return false;
    }

    private static string? ScriptOf(char c) => c switch
    {
        >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= 'À' and <= 'ɏ' or >= 'Ḁ' and <= 'ỿ' => "Latin",
        >= 'Ͱ' and <= 'Ͽ' or >= 'ἀ' and <= '῿' => "Greek",
        >= 'Ѐ' and <= 'ԯ' => "Cyrillic",
        >= '԰' and <= '֏' => "Armenian",
        >= '֐' and <= '׿' => "Hebrew",
        >= '؀' and <= 'ۿ' or >= 'ݐ' and <= 'ݿ' or >= 'ࢠ' and <= 'ࣿ' => "Arabic",
        >= '฀' and <= '๿' => "Thai",
        >= '぀' and <= 'ヿ' or >= '㐀' and <= '䶿' or >= '一' and <= '鿿' => "CJK",
        >= '가' and <= '힯' or >= 'ᄀ' and <= 'ᇿ' => "Hangul",
        _ => null,
    };

    /// <summary>A file name made from the host: letters, digits, dots and hyphens only.</summary>
    private static string SafeFileName(string host)
    {
        var safe = new string(host.Select(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' ? c : '-').ToArray()).Trim('.', '-');
        if (safe.Length > 100) safe = safe[..100];
        return safe.Length == 0 ? "url" : safe;
    }
}
