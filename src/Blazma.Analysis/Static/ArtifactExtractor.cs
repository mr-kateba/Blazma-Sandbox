using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Static;

/// <summary>
/// Finds configuration-like values (C2 addresses, wallets, bot tokens, mutex names) in the
/// printable ASCII and UTF-16LE strings of a file or memory dump. Generic patterns, not a family
/// decoder, so every pattern is backed by a second check (a real top-level domain, a checksum, a
/// plausible address range) to keep false positives low. Nothing found here is proof of anything:
/// these are leads for the analyst.
/// </summary>
/// <remarks>
/// Results are de-duplicated and ordered by <see cref="ArtifactKind"/>, then by where they were
/// first seen, so the same input always gives the same list. Every pattern has a match timeout,
/// and the input is bounded by <see cref="StringExtractor.Runs"/> (first 32 MB).
/// </remarks>
public static partial class ArtifactExtractor
{
    /// <summary>Longer values are cut to this length (a URL with a huge query string, a long blob).</summary>
    public const int MaxValueLength = 2048;

    /// <summary>A Base64 run shorter than this is too likely to be an identifier or a hash.</summary>
    public const int MinBase64Length = 64;

    private const int MinRunLength = 6;
    private const int RegexTimeoutMs = 250;

    private static readonly HashSet<string> PasteHosts = new(
        ["pastebin.com", "paste.ee", "hastebin.com", "ghostbin.co", "rentry.co", "rentry.org", "controlc.com", "paste.rs",
         "dpaste.com", "dpaste.org", "justpaste.it", "pastes.io", "privatebin.net", "termbin.com", "ix.io", "0bin.net",
         "textbin.net", "pastetext.net", "paste.c-net.org", "pastefs.com"],
        StringComparer.OrdinalIgnoreCase);

    private static readonly HashSet<string> DiscordHosts = new(
        ["discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com", "ptb.discordapp.com", "canary.discordapp.com"],
        StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<ExtractedArtifact> Extract(ReadOnlySpan<byte> data, string source, int max = 500) =>
        Extract(StringExtractor.Runs(data, MinRunLength), source, max);

    /// <summary>The same extraction over strings already pulled out of the data.</summary>
    public static IReadOnlyList<ExtractedArtifact> Extract(IEnumerable<string> strings, string source, int max = 500)
    {
        if (max <= 0) return [];
        var found = new Found(max);
        foreach (var s in strings) Scan(s, found);
        return found.ToList(source, max);
    }

    private static void Scan(string raw, Found found)
    {
        if (raw.Length < MinRunLength) return;

        // Values that may sit inside a URL are read from the untouched text.
        foreach (var m in Matches(TelegramTokenRegex(), raw)) found.Add(ArtifactKind.TelegramBotToken, m.Value);
        foreach (var m in Matches(OnionRegex(), raw))
            if (IsOnionV3(m.Value)) found.Add(ArtifactKind.OnionAddress, m.Value.ToLowerInvariant());

        // Then each stage blanks what it took, so a URL does not also show up as a domain, an IP
        // and a Base64 blob.
        var text = new MaskedText(raw);

        foreach (var m in text.Matches(UserAgentRegex()))
        {
            found.Add(ArtifactKind.UserAgent, m.Value.Trim());
            text.Blank(m);
        }
        foreach (var m in text.Matches(UserAgentHeaderRegex()))
        {
            var ua = m.Groups["ua"].Value.Trim();
            if (ua.Length >= 4) found.Add(ArtifactKind.UserAgent, ua);
            text.Blank(m);
        }

        foreach (var m in text.Matches(UrlRegex()))
        {
            var url = m.Value.TrimEnd('.', ',', ';', ':', '!', '?', ')', ']', '\'', '"');
            if (ClassifyUrl(url) is { } kind) found.Add(kind, url);
            text.Blank(m);
        }

        foreach (var m in text.Matches(EmailRegex()))
        {
            var at = m.Value.IndexOf('@', StringComparison.Ordinal);
            if (m.Value[at - 1] != '.' && TopLevelDomains.IsKnown(TopLevelDomains.Of(m.Value)))
                found.Add(ArtifactKind.Email, m.Value.ToLowerInvariant());
            text.Blank(m);
        }

        foreach (var m in text.Matches(MutexRegex()))
        {
            found.Add(ArtifactKind.MutexName, m.Value);
            text.Blank(m);
        }

        foreach (var m in text.Matches(MoneroRegex()))
            if (CryptoAddresses.IsMonero(m.Value)) { found.Add(ArtifactKind.MoneroAddress, m.Value); text.Blank(m); }
        foreach (var m in text.Matches(BitcoinBase58Regex()))
            if (CryptoAddresses.IsBitcoinBase58(m.Value)) { found.Add(ArtifactKind.BitcoinAddress, m.Value); text.Blank(m); }
        foreach (var m in text.Matches(BitcoinBech32Regex()))
            if (CryptoAddresses.IsBitcoinBech32(m.Value)) { found.Add(ArtifactKind.BitcoinAddress, m.Value.ToLowerInvariant()); text.Blank(m); }
        foreach (var m in text.Matches(EthereumRegex()))
            if (CryptoAddresses.IsEthereum(m.Value)) { found.Add(ArtifactKind.EthereumAddress, m.Value); text.Blank(m); }

        foreach (var m in text.Matches(BarePasteRegex()))
        {
            found.Add(ArtifactKind.PastebinLink, m.Value);
            text.Blank(m);
        }

        foreach (var m in text.Matches(Ipv6CandidateRegex()))
            if (NormalizeIpv6(m.Value) is { } v6) { found.Add(ArtifactKind.IpAddress, v6); text.Blank(m); }
        foreach (var m in text.Matches(Ipv4Regex()))
        {
            if (IsPlausibleIpv4(m.Value) && !LooksLikeVersion(text.Current, m.Index)) found.Add(ArtifactKind.IpAddress, m.Value);
            text.Blank(m);
        }

        foreach (var m in text.Matches(DomainRegex()))
            if (IsPlausibleBareDomain(m.Value)) { found.Add(ArtifactKind.Domain, m.Value.ToLowerInvariant()); text.Blank(m); }

        foreach (var m in text.Matches(Base64Regex()))
            if (IsPlausibleBase64(m.Value) && !found.ContinuesBase64(m.Value)) found.Add(ArtifactKind.Base64Blob, m.Value);
    }

    /// <summary>What kind of artifact a matched URL is, or null when its host is not a real one.</summary>
    private static ArtifactKind? ClassifyUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host)) return null;
        var host = uri.IdnHost.TrimEnd('.');
        var hostOk = uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6
            || (uri.HostNameType == UriHostNameType.Dns && host.Contains('.', StringComparison.Ordinal)
                && (TopLevelDomains.IsKnown(TopLevelDomains.Of(host)) || host.EndsWith(".onion", StringComparison.OrdinalIgnoreCase)));
        if (!hostOk) return null;

        if (DiscordHosts.Contains(host) && DiscordWebhookPathRegex().IsMatch(uri.AbsolutePath)) return ArtifactKind.DiscordWebhook;
        var bare = host.StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? host[4..] : host;
        if (PasteHosts.Contains(bare) && uri.AbsolutePath.Length > 4) return ArtifactKind.PastebinLink;
        return ArtifactKind.Url;
    }

    /// <summary>A v3 onion address: 56 base32 characters encoding key, checksum and version 3.</summary>
    /// <remarks>The checksum uses SHA3-256, which Windows 10 does not provide, so only the version byte is checked.</remarks>
    private static bool IsOnionV3(string value)
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        var label = value[..56].ToLowerInvariant();
        // 56 characters are 280 bits = 35 bytes; the version is the last byte, i.e. the last 8 bits.
        var last = (alphabet.IndexOf(label[54], StringComparison.Ordinal) << 5) | alphabet.IndexOf(label[55], StringComparison.Ordinal);
        return (last & 0xFF) == 3;
    }

    /// <summary>
    /// A public IPv4 address. Loopback, "this network", link-local, multicast, reserved, network
    /// (.0) and broadcast (.255) addresses are dropped, as are octets with leading zeros, which
    /// are version numbers or padding rather than addresses.
    /// </summary>
    internal static bool IsPlausibleIpv4(string value)
    {
        var parts = value.Split('.');
        Span<int> o = stackalloc int[4];
        for (var i = 0; i < 4; i++)
        {
            if (parts[i].Length > 1 && parts[i][0] == '0') return false;
            if (!int.TryParse(parts[i], out o[i]) || o[i] > 255) return false;
        }
        if (o[0] is 0 or 127 or >= 224) return false;
        if (o[0] == 169 && o[1] == 254) return false;
        return o[3] is not (0 or 255);
    }

    /// <summary>"v1.2.3.4", "version 1.2.3.4", "Version=1.2.3.4": a four-part version, not an address.</summary>
    private static bool LooksLikeVersion(string text, int index)
    {
        var start = Math.Max(0, index - 12);
        var before = text[start..index].ToLowerInvariant().TrimEnd(' ', '=', ':');
        return before.EndsWith('v') || before.EndsWith("ver", StringComparison.Ordinal) || before.EndsWith("version", StringComparison.Ordinal)
            || before.EndsWith("ver.", StringComparison.Ordinal);
    }

    /// <summary>A global unicast IPv6 address (2000::/3, outside the 2001:db8:: documentation range), normalized.</summary>
    private static string? NormalizeIpv6(string value)
    {
        if (value.Count(c => c == ':') < 2) return null;
        if (!IPAddress.TryParse(value, out var ip) || ip.AddressFamily != AddressFamily.InterNetworkV6) return null;
        var b = ip.GetAddressBytes();
        if ((b[0] & 0xE0) != 0x20) return null;
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return null;
        // An address where most groups are written out is an address; "2001::" alone is too thin.
        return value.Split(':').Count(g => g.Length > 0) >= 3 ? ip.ToString() : null;
    }

    /// <summary>
    /// A host name seen on its own. Stricter than a URL host: the top-level domain must not double
    /// as a file extension or a code member, the name must be written in one case (not
    /// "System.Net"), and short names are dropped because random bytes produce them.
    /// </summary>
    internal static bool IsPlausibleBareDomain(string value)
    {
        if (value.Length < 6) return false;
        if (value.Any(char.IsAsciiLetterUpper) && value.Any(char.IsAsciiLetterLower)) return false;
        var labels = value.Split('.');
        if (labels.Any(l => l.Length == 0 || l[0] == '-' || l[^1] == '-')) return false;
        if (labels[^2].Length < 2) return false;
        return TopLevelDomains.IsDistinctive(labels[^1]);
    }

    /// <summary>
    /// Base64 that is worth showing: mixed case and digits, many distinct characters, decodable, and
    /// not the Base64 alphabet itself (which every encoder embeds).
    /// </summary>
    internal static bool IsPlausibleBase64(string value)
    {
        var body = value.TrimEnd('=');
        if (body.Length < MinBase64Length || body.Length % 4 == 1) return false;
        if (!body.Any(char.IsAsciiLetterUpper) || !body.Any(char.IsAsciiLetterLower) || !body.Any(char.IsAsciiDigit)) return false;
        if (body.Distinct().Count() < 20) return false;
        if (body.Contains("ABCDEFGHIJKLMNOP", StringComparison.Ordinal) || body.Contains("abcdefghijklmnop", StringComparison.Ordinal)
            || body.Contains("0123456789", StringComparison.Ordinal)) return false;
        var padded = body + new string('=', (4 - body.Length % 4) % 4);
        var buffer = new byte[padded.Length / 4 * 3];
        return Convert.TryFromBase64String(padded, buffer, out _);
    }

    private static IEnumerable<Match> Matches(Regex regex, string text)
    {
        var list = new List<Match>();
        try
        {
            foreach (Match m in regex.Matches(text)) list.Add(m);
        }
        catch (RegexMatchTimeoutException)
        {
            // A pathological string: keep what was found before the timeout and move on.
        }
        return list;
    }

    /// <summary>A string whose matched parts are blanked out stage by stage.</summary>
    private sealed class MaskedText(string text)
    {
        private readonly char[] _chars = text.ToCharArray();
        private bool _dirty;
        private string _current = text;

        public string Current
        {
            get
            {
                if (_dirty) { _current = new string(_chars); _dirty = false; }
                return _current;
            }
        }

        public IEnumerable<Match> Matches(Regex regex) => ArtifactExtractor.Matches(regex, Current);

        public void Blank(Match m)
        {
            Array.Fill(_chars, ' ', m.Index, m.Length);
            _dirty = true;
        }
    }

    /// <summary>De-duplicated results per kind, in first-seen order, each kind capped at the overall maximum.</summary>
    private sealed class Found(int max)
    {
        private readonly Dictionary<ArtifactKind, List<string>> _byKind = [];
        private readonly HashSet<(ArtifactKind, string)> _seen = [];
        private readonly List<string> _fullBlobs = [];

        public void Add(ArtifactKind kind, string value)
        {
            if (kind == ArtifactKind.Base64Blob && _fullBlobs.Count < max) _fullBlobs.Add(value);
            if (value.Length > MaxValueLength) value = value[..MaxValueLength];
            if (!_byKind.TryGetValue(kind, out var list)) _byKind[kind] = list = [];
            if (list.Count >= max) return;
            var key = kind is ArtifactKind.Url or ArtifactKind.PastebinLink or ArtifactKind.MutexName or ArtifactKind.UserAgent
                ? value.ToUpperInvariant() : value;
            if (_seen.Add((kind, key))) list.Add(value);
        }

        /// <summary>
        /// Long strings arrive in overlapping 4 KB pieces; a blob that starts inside one already
        /// found is its continuation, not a new value.
        /// </summary>
        public bool ContinuesBase64(string value)
        {
            var head = value[..Math.Min(value.Length, MinBase64Length)];
            if (!_fullBlobs.Any(b => b.Contains(head, StringComparison.Ordinal))) return false;
            if (_fullBlobs.Count < max) _fullBlobs.Add(value); // the next piece continues this one
            return true;
        }

        public List<ExtractedArtifact> ToList(string source, int take) =>
            _byKind.OrderBy(kv => kv.Key)
                .SelectMany(kv => kv.Value.Select(v => new ExtractedArtifact(kv.Key, v, source)))
                .Take(take)
                .ToList();
    }

    [GeneratedRegex(@"\b(?:https?|ftp)://[^\s""'<>`{}|\\^]{3,2048}", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, RegexTimeoutMs)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"^/api/(?:v\d{1,2}/)?webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,68}/?$", RegexOptions.CultureInvariant, RegexTimeoutMs)]
    private static partial Regex DiscordWebhookPathRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9][A-Za-z0-9._%+\-]{0,63}@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){1,8}[A-Za-z]{2,24}(?![A-Za-z0-9\-])", RegexOptions.CultureInvariant, RegexTimeoutMs)]
    private static partial Regex EmailRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])[a-z2-7]{56}\.onion(?![A-Za-z0-9\-])", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, RegexTimeoutMs)]
    private static partial Regex OnionRegex();

    [GeneratedRegex(@"(?<!\d)\d{8,10}:AA[A-Za-z0-9_\-]{33}(?![A-Za-z0-9_\-])", RegexOptions.CultureInvariant, RegexTimeoutMs)]
    private static partial Regex TelegramTokenRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.co|rentry\.(?:co|org)|controlc\.com|paste\.rs|dpaste\.(?:com|org)|justpaste\.it|pastes\.io|privatebin\.net|termbin\.com|ix\.io|0bin\.net|textbin\.net|pastetext\.net)/[A-Za-z0-9_\-/]{4,80}", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, RegexTimeoutMs)]
    private static partial Regex BarePasteRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![A-Za-z0-9])", RegexOptions.CultureInvariant, RegexTimeoutMs)]
    private static partial Regex BitcoinBase58Regex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:bc1[ac-hj-np-z02-9]{11,71}|BC1[AC-HJ-NP-Z02-9]{11,71})(?![A-Za-z0-9])", RegexOptions.CultureInvariant, RegexTimeoutMs)]
    private static partial Regex BitcoinBech32Regex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])0x[0-9a-fA-F]{40}(?![A-Za-z0-9])", RegexOptions.CultureInvariant, RegexTimeoutMs)]
    private static partial Regex EthereumRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?![A-Za-z0-9])", RegexOptions.CultureInvariant, RegexTimeoutMs)]
    private static partial Regex MoneroRegex();

    [GeneratedRegex(@"Mozilla/[45]\.0 \([^()\r\n]{4,200}\)(?: [A-Za-z][A-Za-z0-9._\-]{0,40}(?:/[A-Za-z0-9._\-]{1,40})?(?: \([^()\r\n]{0,120}\))?){0,10}", RegexOptions.CultureInvariant, RegexTimeoutMs)]
    private static partial Regex UserAgentRegex();

    [GeneratedRegex(@"User-Agent:[ \t]*(?<ua>[^\r\n]{4,256})", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, RegexTimeoutMs)]
    private static partial Regex UserAgentHeaderRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:Global|Local)\\[A-Za-z0-9_.\-{}#@$]{3,120}", RegexOptions.CultureInvariant, RegexTimeoutMs)]
    private static partial Regex MutexRegex();

    [GeneratedRegex(@"(?<![0-9A-Za-z:.])[0-9A-Fa-f:]{6,39}(?![0-9A-Za-z:.])", RegexOptions.CultureInvariant, RegexTimeoutMs)]
    private static partial Regex Ipv6CandidateRegex();

    [GeneratedRegex(@"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)", RegexOptions.CultureInvariant, RegexTimeoutMs)]
    private static partial Regex Ipv4Regex();

    [GeneratedRegex(@"(?<![A-Za-z0-9\-_.@\\])(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){1,8}[A-Za-z]{2,24}(?![A-Za-z0-9\-_]|\.[A-Za-z0-9])", RegexOptions.CultureInvariant, RegexTimeoutMs)]
    private static partial Regex DomainRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{64,}={0,2}(?![A-Za-z0-9+/=])", RegexOptions.CultureInvariant, RegexTimeoutMs)]
    private static partial Regex Base64Regex();
}
