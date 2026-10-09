using System.Text;

namespace Blazma.Analysis.Url;

/// <summary>
/// Spots host names that imitate commonly phished brands: the brand name planted in an unrelated
/// domain ("paypal.com.secure-login.example"), digit and letter swaps ("paypa1", "rnicrosoft",
/// "g00gle"), Cyrillic or Greek look-alike letters, and one- or two-letter typos. A brand's own
/// domains are never flagged.
/// </summary>
internal static class BrandLookalikes
{
    /// <summary>A brand, the names it is phished under, and the domains it really owns.</summary>
    /// <param name="Fuzzy">Names that are one typo away from an ordinary word ("icloud"/"cloud", "binance"/"finance") only match exactly.</param>
    private sealed record Brand(string Name, string[] Aliases, string[] Domains, bool Fuzzy = true);

    private static readonly Brand[] Brands =
    [
        new("paypal", ["paypal"], ["paypal.com", "paypal.me", "paypalobjects.com"]),
        new("apple", ["apple", "appleid", "icloud", "itunes"], ["apple.com", "icloud.com", "itunes.com", "me.com", "apple.news"], Fuzzy: false),
        new("microsoft", ["microsoft", "outlook", "office365", "onedrive", "sharepoint", "hotmail", "microsoftonline"],
            ["microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com", "office.net", "sharepoint.com",
             "onedrive.com", "hotmail.com", "msn.com", "azure.com", "windows.net", "windows.com", "bing.com", "skype.com", "xbox.com",
             "microsoft365.com", "msft.net", "msauth.net", "aka.ms"]),
        new("google", ["google", "gmail", "youtube", "googledrive"],
            ["google.com", "gmail.com", "youtube.com", "youtu.be", "googleapis.com", "gstatic.com", "googleusercontent.com", "goo.gl", "g.co",
             "google.co.uk", "google.co.jp", "google.com.au", "google.com.br", "google.co.in", "google.com.mx"]),
        new("amazon", ["amazon", "amazonaws"],
            ["amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.co.jp", "amazon.com.au", "amazon.com.br", "amazon.com.mx", "amazon.in",
             "amazon.sa", "amazon.ae", "amazon.eg", "media-amazon.com", "a2z.com", "aws.amazon.com"]),
        new("facebook", ["facebook", "fbcdn"], ["facebook.com", "fb.com", "fb.me", "fbcdn.net", "meta.com", "messenger.com"]),
        new("instagram", ["instagram"], ["instagram.com", "cdninstagram.com"]),
        new("whatsapp", ["whatsapp"], ["whatsapp.com", "whatsapp.net", "wa.me"]),
        new("netflix", ["netflix"], ["netflix.com", "nflxext.com", "nflxvideo.net"]),
        new("linkedin", ["linkedin"], ["linkedin.com", "licdn.com", "lnkd.in"]),
        new("twitter", ["twitter"], ["twitter.com", "x.com", "t.co", "twimg.com"]),
        new("dropbox", ["dropbox"], ["dropbox.com", "dropboxusercontent.com", "db.tt"]),
        new("docusign", ["docusign"], ["docusign.com", "docusign.net"]),
        new("adobe", ["adobe"], ["adobe.com", "adobelogin.com", "adobe.io", "typekit.net"]),
        new("yahoo", ["yahoo"], ["yahoo.com", "yahoo.co.jp", "yimg.com", "ymail.com"]),
        new("chase", ["chase", "jpmorgan"], ["chase.com", "jpmorgan.com", "jpmorganchase.com"], Fuzzy: false),
        new("wellsfargo", ["wellsfargo"], ["wellsfargo.com", "wf.com"]),
        new("bankofamerica", ["bankofamerica"], ["bankofamerica.com", "bofa.com"]),
        new("citibank", ["citibank"], ["citibank.com", "citi.com", "citigroup.com"]),
        new("hsbc", ["hsbc"], ["hsbc.com", "hsbc.co.uk"]),
        new("barclays", ["barclays"], ["barclays.com", "barclays.co.uk"]),
        new("santander", ["santander"], ["santander.com", "santander.co.uk"]),
        new("americanexpress", ["americanexpress", "amex"], ["americanexpress.com", "aexp.com"]),
        new("mastercard", ["mastercard"], ["mastercard.com"]),
        new("coinbase", ["coinbase"], ["coinbase.com"]),
        new("binance", ["binance"], ["binance.com", "binance.us", "bnbstatic.com"], Fuzzy: false),
        new("metamask", ["metamask"], ["metamask.io"]),
        new("steam", ["steampowered", "steamcommunity"], ["steampowered.com", "steamcommunity.com", "steamstatic.com", "steamgames.com"]),
        new("discord", ["discord", "discordapp"], ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"]),
        new("telegram", ["telegram"], ["telegram.org", "t.me", "telegram.me", "telesco.pe"]),
        new("roblox", ["roblox"], ["roblox.com", "rbxcdn.com"]),
        new("ebay", ["ebay"], ["ebay.com", "ebay.co.uk", "ebay.de", "ebayimg.com"]),
        new("aliexpress", ["aliexpress", "alibaba"], ["aliexpress.com", "alibaba.com", "alicdn.com"]),
        new("dhl", ["dhl"], ["dhl.com", "dhl.de"]),
        new("fedex", ["fedex"], ["fedex.com"]),
        new("usps", ["usps"], ["usps.com", "usps.gov"]),
        new("wetransfer", ["wetransfer"], ["wetransfer.com", "we.tl"]),
        new("github", ["github"], ["github.com", "github.io", "githubusercontent.com", "github.dev"]),
        new("spotify", ["spotify"], ["spotify.com", "scdn.co", "spoti.fi"]),
        new("tiktok", ["tiktok"], ["tiktok.com", "tiktokcdn.com", "tiktokv.com"]),
        new("walmart", ["walmart"], ["walmart.com"]),
        new("trezor", ["trezor"], ["trezor.io"]),
    ];

    /// <summary>Cyrillic and Greek letters that render like Latin ones.</summary>
    private static readonly Dictionary<char, char> Homoglyphs = new()
    {
        ['а'] = 'a', ['е'] = 'e', ['ё'] = 'e', ['к'] = 'k', ['м'] = 'm', ['о'] = 'o', ['р'] = 'p', ['с'] = 'c', ['у'] = 'y',
        ['х'] = 'x', ['і'] = 'i', ['ї'] = 'i', ['ј'] = 'j', ['ѕ'] = 's', ['ԁ'] = 'd', ['ӏ'] = 'l', ['һ'] = 'h', ['ԛ'] = 'q', ['ԝ'] = 'w',
        ['α'] = 'a', ['ο'] = 'o', ['ρ'] = 'p', ['ν'] = 'v', ['ι'] = 'i', ['κ'] = 'k', ['χ'] = 'x', ['υ'] = 'u', ['ε'] = 'e',
        ['0'] = 'o', ['1'] = 'l', ['|'] = 'l',
    };

    private static readonly (Brand Brand, string Alias, string Skeleton)[] Index =
        Brands.SelectMany(b => b.Aliases.Select(a => (b, a, Skeleton(a)))).ToArray();

    /// <summary>
    /// The first brand the host imitates, or null. <paramref name="displayHost"/> is the host as a
    /// person reads it (Unicode), <paramref name="asciiHost"/> the punycode form used to recognise
    /// the brand's own domains.
    /// </summary>
    public static string? Find(string displayHost, string asciiHost, string registrable, string tld)
    {
        var labels = displayHost.ToLowerInvariant().TrimEnd('.').Split('.');
        if (labels.Length < 2) return null;
        var registrableLabel = registrable.Split('.')[0];
        var regionalSuffix = IsRegionalSuffix(registrable[(registrableLabel.Length + 1)..], tld);

        var tokens = new List<(string Text, bool IsRegistrableLabel)>();
        for (var i = 0; i < labels.Length - 1; i++)
        {
            var isRegistrable = i == labels.Length - registrable.Split('.').Length;
            tokens.Add((labels[i].Replace("-", "", StringComparison.Ordinal), isRegistrable));
            if (labels[i].Contains('-', StringComparison.Ordinal))
                tokens.AddRange(labels[i].Split('-', StringSplitOptions.RemoveEmptyEntries).Select(t => (t, false)));
        }

        foreach (var (brand, alias, aliasSkeleton) in Index)
        {
            if (brand.Domains.Any(d => asciiHost == d || asciiHost.EndsWith("." + d, StringComparison.Ordinal))) continue;
            foreach (var (text, isRegistrable) in tokens)
            {
                // "google.ro", "amazon.de": the brand itself under a country domain is its regional site.
                if (isRegistrable && text == alias && text == registrableLabel && regionalSuffix) continue;
                if (Matches(text, alias, aliasSkeleton, brand.Fuzzy)) return brand.Name;
            }
        }
        return null;
    }

    private static bool Matches(string token, string alias, string aliasSkeleton, bool fuzzy)
    {
        if (token.Length < 3) return false;
        var skeleton = Skeleton(token);
        if (skeleton == aliasSkeleton) return true;
        if (!fuzzy || alias.Length < 6 || token.Length < 5) return false;
        var allowed = alias.Length >= 10 ? 2 : 1;
        return Math.Abs(skeleton.Length - aliasSkeleton.Length) <= allowed && Distance(skeleton, aliasSkeleton) <= allowed;
    }

    /// <summary>A country domain ("de", "co.uk") that is not on the abused list.</summary>
    private static bool IsRegionalSuffix(string suffix, string tld) =>
        tld.Length == 2 && tld is not ("tk" or "ml" or "ga" or "cf" or "gq" or "su")
        && (suffix.Length == 2 || suffix.StartsWith("co.", StringComparison.Ordinal) || suffix.StartsWith("com.", StringComparison.Ordinal));

    /// <summary>What a name looks like on screen: look-alike letters mapped to Latin, "rn" read as "m", "vv" as "w".</summary>
    internal static string Skeleton(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (var c in text.ToLowerInvariant()) sb.Append(Homoglyphs.TryGetValue(c, out var latin) ? latin : c);
        return sb.Replace("rn", "m").Replace("vv", "w").ToString();
    }

    /// <summary>Levenshtein distance.</summary>
    private static int Distance(string a, string b)
    {
        var prev = new int[b.Length + 1];
        var cur = new int[b.Length + 1];
        for (var j = 0; j <= b.Length; j++) prev[j] = j;
        for (var i = 1; i <= a.Length; i++)
        {
            cur[0] = i;
            for (var j = 1; j <= b.Length; j++)
                cur[j] = Math.Min(Math.Min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1));
            (prev, cur) = (cur, prev);
        }
        return prev[b.Length];
    }
}
