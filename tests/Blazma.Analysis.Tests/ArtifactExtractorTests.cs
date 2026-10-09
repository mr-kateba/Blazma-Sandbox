using System.Text;
using Blazma.Analysis.Static;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Tests;

public class ArtifactExtractorTests
{
    private const string Onion = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
    private const string Monero = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";
    private const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    private static readonly string TelegramToken = "7012345678:AA" + "HdqTcvCH1vGWJxfSeofSAs0K5PALDsaw1x"[..33];
    private static readonly string DiscordWebhook = "https://discord.com/api/webhooks/123456789012345678/" + new string('x', 34) + "Ab3_-" + new string('Z', 29);
    private static readonly string Blob = Convert.ToBase64String(Bytes(new Random(7), 120));

    /// <summary>Random bytes with the given strings planted at intervals, half of them as UTF-16LE.</summary>
    private static byte[] Noisy(params string[] planted)
    {
        var rng = new Random(1234);
        using var ms = new MemoryStream();
        for (var i = 0; i < planted.Length; i++)
        {
            ms.Write(Bytes(rng, 512));
            ms.WriteByte(0);
            ms.Write(i % 2 == 0 ? Encoding.ASCII.GetBytes(planted[i]) : Encoding.Unicode.GetBytes(planted[i]));
            ms.Write([0, 0]);
        }
        ms.Write(Bytes(rng, 512));
        return ms.ToArray();
    }

    private static byte[] Bytes(Random rng, int n)
    {
        var b = new byte[n];
        rng.NextBytes(b);
        return b;
    }

    private static IReadOnlyList<ExtractedArtifact> Extract(params string[] planted) => ArtifactExtractor.Extract(Noisy(planted), "sample");

    private static void AssertFound(IReadOnlyList<ExtractedArtifact> found, ArtifactKind kind, string value) =>
        Assert.Contains(found, a => a.Kind == kind && a.Value == value);

    [Fact]
    public void Planted_configuration_values_are_found_in_noisy_binary_data()
    {
        var found = Extract(
            "https://update.contoso-cdn.xyz/gate.php?id=7",
            "connect to 45.77.12.34 port 443",
            "fallback 2a03:2880:f12f:83:face:b00c:0:25de",
            "mail: operator@evil-domain.ru",
            "beacon cdn-sync-check.top",
            "hidden " + Onion,
            "pay to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa now",
            "or 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "segwit bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            "taproot bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            "eth 0x52908400098527886E0F7030069857D2E4169EE7",
            "xmr " + Monero,
            "https://api.telegram.org/bot" + TelegramToken + "/sendMessage",
            DiscordWebhook,
            "https://pastebin.com/raw/AbCd1234",
            "rentry.co/k3yz9/raw",
            UserAgent,
            @"Global\QwertyMutex_2024",
            "cfg=" + Blob);

        AssertFound(found, ArtifactKind.Url, "https://update.contoso-cdn.xyz/gate.php?id=7");
        AssertFound(found, ArtifactKind.IpAddress, "45.77.12.34");
        AssertFound(found, ArtifactKind.IpAddress, "2a03:2880:f12f:83:face:b00c:0:25de");
        AssertFound(found, ArtifactKind.Email, "operator@evil-domain.ru");
        AssertFound(found, ArtifactKind.Domain, "cdn-sync-check.top");
        AssertFound(found, ArtifactKind.OnionAddress, Onion);
        AssertFound(found, ArtifactKind.BitcoinAddress, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        AssertFound(found, ArtifactKind.BitcoinAddress, "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");
        AssertFound(found, ArtifactKind.BitcoinAddress, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
        AssertFound(found, ArtifactKind.BitcoinAddress, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0");
        AssertFound(found, ArtifactKind.EthereumAddress, "0x52908400098527886E0F7030069857D2E4169EE7");
        AssertFound(found, ArtifactKind.MoneroAddress, Monero);
        AssertFound(found, ArtifactKind.TelegramBotToken, TelegramToken);
        AssertFound(found, ArtifactKind.DiscordWebhook, DiscordWebhook);
        AssertFound(found, ArtifactKind.PastebinLink, "https://pastebin.com/raw/AbCd1234");
        AssertFound(found, ArtifactKind.PastebinLink, "rentry.co/k3yz9/raw");
        AssertFound(found, ArtifactKind.UserAgent, UserAgent);
        AssertFound(found, ArtifactKind.MutexName, @"Global\QwertyMutex_2024");
        AssertFound(found, ArtifactKind.Base64Blob, Blob);
        Assert.All(found, a => Assert.Equal("sample", a.Source));

        // A URL is not repeated as a domain, an IP or a blob.
        Assert.DoesNotContain(found, a => a.Kind == ArtifactKind.Domain && a.Value.Contains("contoso-cdn", StringComparison.Ordinal));
        Assert.DoesNotContain(found, a => a.Kind == ArtifactKind.Domain && a.Value.Contains("evil-domain", StringComparison.Ordinal));
        Assert.DoesNotContain(found, a => a.Kind == ArtifactKind.Url && a.Value.Contains("discord", StringComparison.Ordinal));
    }

    [Fact]
    public void Results_are_deduplicated_and_in_a_stable_order()
    {
        var data = Noisy("evil-c2.xyz", "45.77.12.34", "EVIL-C2.XYZ", "evil-c2.xyz", "45.77.12.34");
        var first = ArtifactExtractor.Extract(data, "s");
        var second = ArtifactExtractor.Extract(data, "s");
        Assert.Equal(first, second);
        Assert.Single(first, a => a.Kind == ArtifactKind.Domain);
        Assert.Single(first, a => a.Kind == ArtifactKind.IpAddress);
        Assert.Equal(first.OrderBy(a => a.Kind).Select(a => a.Kind), first.Select(a => a.Kind));
    }

    [Fact]
    public void The_result_count_is_capped()
    {
        var hosts = Enumerable.Range(0, 50).Select(i => $"node{i:D2}-relay.xyz").ToArray();
        Assert.Equal(10, ArtifactExtractor.Extract(Noisy(hosts), "s", max: 10).Count);
    }

    [Fact]
    public void Random_data_yields_nothing()
    {
        var rng = new Random(99);
        Assert.Empty(ArtifactExtractor.Extract(Bytes(rng, 1 << 20), "s"));
    }

    [Theory]
    [InlineData("AssemblyVersion 1.0.0.0")]
    [InlineData("v1.2.3.4")]
    [InlineData("Version=4.0.30.1")]
    [InlineData("product version 2.5.1.7")]
    [InlineData("listen on 127.0.0.1 and 0.0.0.0")]
    [InlineData("netmask 255.255.255.0")]
    [InlineData("multicast 239.1.2.3 link 169.254.10.20")]
    [InlineData("1.2.3.4.5.6")]
    [InlineData("using System.Net; using System.IO;")]
    [InlineData("kernel32.dll setup.exe config.json")]
    [InlineData("./install.sh && make -f Makefile.am")]
    [InlineData("obj.id = user.name; event.date")]
    [InlineData("time 12:30:45 mac 00:1A:2B:3C:4D:5E")]
    [InlineData("std::vector<int>::iterator")]
    [InlineData("doc 2001:db8::1 local fe80::1 loop ::1")]
    [InlineData("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")]
    [InlineData("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdl")]
    [InlineData("0x0000000000000000000000000000000000000000")]
    [InlineData("http://localhost/x http://intranet/admin")]
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")]
    [InlineData("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")]
    public void Look_alikes_are_not_reported(string text)
    {
        var found = ArtifactExtractor.Extract(Noisy(text), "s");
        Assert.True(found.Count == 0, string.Join(", ", found.Select(a => $"{a.Kind}={a.Value}")));
    }

    [Fact]
    public void An_onion_address_needs_version_3()
    {
        // Same shape, but the last character encodes a version byte other than 3.
        var bad = Onion[..55] + "a.onion";
        Assert.DoesNotContain(ArtifactExtractor.Extract(Noisy(bad), "s"), a => a.Kind == ArtifactKind.OnionAddress);
    }

    [Fact]
    public void A_long_blob_split_into_pieces_is_reported_once()
    {
        var big = Convert.ToBase64String(Bytes(new Random(3), 9000));
        var found = ArtifactExtractor.Extract(Noisy(big), "s");
        var blob = Assert.Single(found, a => a.Kind == ArtifactKind.Base64Blob);
        Assert.StartsWith(blob.Value, big, StringComparison.Ordinal);
        Assert.True(blob.Value.Length <= ArtifactExtractor.MaxValueLength);
    }
}
