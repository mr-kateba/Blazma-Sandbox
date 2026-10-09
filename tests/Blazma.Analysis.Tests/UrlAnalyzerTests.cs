using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Blazma.Analysis.Url;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Tests;

public class UrlAnalyzerTests
{
    [Fact]
    public void A_url_sample_is_hashed_over_its_normalized_text()
    {
        Assert.True(UrlAnalyzer.TryCreateSample("Example.COM/Path?q=1", out var sample, out string? error), error);
        Assert.NotNull(sample);
        Assert.Equal("https://example.com/Path?q=1", sample.Url);
        Assert.Equal(FileKind.Url, sample.Kind);
        Assert.Equal("example.com", sample.FileName);
        var bytes = Encoding.UTF8.GetBytes(sample.Url!);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)), sample.Sha256);
#pragma warning disable CA5350 // checking the compatibility hash, not using it
        Assert.Equal(Convert.ToHexStringLower(SHA1.HashData(bytes)), sample.Sha1);
#pragma warning restore CA5350
        Assert.Equal(bytes.Length, sample.Size);
    }

    [Fact]
    public void The_same_address_typed_differently_has_one_identity()
    {
        UrlAnalyzer.TryCreateSample("HTTPS://WWW.Example.com:443/a", out var a, out string? _);
        UrlAnalyzer.TryCreateSample("  https://www.example.com/a\n", out var b, out string? _);
        Assert.Equal(a!.Sha256, b!.Sha256);
        Assert.Equal(a.Url, UrlAnalyzer.Analyze(a.Url!).Url);
    }

    [Fact]
    public void An_international_host_is_stored_in_punycode_with_a_safe_file_name()
    {
        Assert.True(UrlAnalyzer.TryCreateSample("https://bücher.example.de/x", out var s, out string? _));
        Assert.Equal("https://xn--bcher-kva.example.de/x", s!.Url);
        Assert.Equal("xn--bcher-kva.example.de", s.FileName);

        Assert.True(UrlAnalyzer.TryCreateSample("http://[2a03:2880::25de]:8080/", out var v6, out string? _));
        Assert.DoesNotContain(':', v6!.FileName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("ftp://files.example.com/a")]
    [InlineData("javascript:alert(1)")]
    [InlineData("file:///C:/Windows/notepad.exe")]
    [InlineData("data:text/html,hi")]
    [InlineData("http://exa mple.com/")]
    [InlineData("http://example.com/\u202Eexe.pdf")]
    [InlineData("http://example.com/\u0007")]
    [InlineData("https://")]
    public void Unsafe_or_invalid_input_is_refused(string input)
    {
        Assert.False(UrlAnalyzer.TryCreateSample(input, out var sample, out string? error));
        Assert.Null(sample);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void Overlong_addresses_are_refused_with_a_bilingual_reason()
    {
        Assert.False(UrlAnalyzer.TryCreateSample("https://example.com/" + new string('a', 2100), out _, out Core.Text.LocalizedText? error));
        Assert.NotNull(error);
        Assert.Contains("2048", error.En, StringComparison.Ordinal);
        Assert.Contains("2048", error.Ar, StringComparison.Ordinal);
    }

    [Fact]
    public void Ports_on_a_host_without_a_scheme_are_not_mistaken_for_a_scheme()
    {
        Assert.True(UrlAnalyzer.TryCreateSample("example.com:8080/x", out var s, out string? _));
        Assert.Equal("https://example.com:8080/x", s!.Url);
    }

    [Theory]
    [InlineData("http://3232235777/login", "192.168.1.1")]
    [InlineData("http://0xC0A80101/", "192.168.1.1")]
    [InlineData("http://0300.0250.01.01/", "192.168.1.1")]
    [InlineData("http://192.168.257/", "192.168.1.1")]
    public void Numeric_ip_hosts_in_disguise_are_recognised(string url, string ip)
    {
        var r = UrlAnalyzer.Analyze(url);
        Assert.True(r.HostIsIpAddress);
        Assert.Contains(r.Notes, n => n.En.Contains(ip, StringComparison.Ordinal) && n.En.Contains("unusual", StringComparison.Ordinal));
    }

    [Fact]
    public void A_plain_ip_host_is_flagged_without_the_disguise_note()
    {
        var r = UrlAnalyzer.Analyze("http://45.77.12.34/gate.php");
        Assert.True(r.HostIsIpAddress);
        Assert.DoesNotContain(r.Notes, n => n.En.Contains("unusual", StringComparison.Ordinal));
        Assert.True(UrlAnalyzer.Analyze("http://[2a03:2880::25de]/").HostIsIpAddress);
    }

    [Fact]
    public void A_cyrillic_homograph_is_decoded_and_flagged()
    {
        var ascii = new IdnMapping().GetAscii("p\u0430ypal.com"); // Cyrillic "а"
        var r = UrlAnalyzer.Analyze("https://" + ascii + "/signin");
        Assert.Equal(ascii, r.Host);
        Assert.Equal("p\u0430ypal.com", r.UnicodeHost);
        Assert.True(r.MixesScripts);
        Assert.Equal("paypal", r.LooksLike);
    }

    [Fact]
    public void A_single_script_international_domain_does_not_mix_scripts()
    {
        var r = UrlAnalyzer.Analyze("https://bücher.de/");
        Assert.Equal("bücher.de", r.UnicodeHost);
        Assert.False(r.MixesScripts);
        Assert.Null(r.LooksLike);
    }

    [Fact]
    public void Credentials_ports_shorteners_risky_tlds_and_deep_subdomains_are_reported()
    {
        var cred = UrlAnalyzer.Analyze("https://www.paypal.com@203.0.113.9/");
        Assert.True(cred.HasEmbeddedCredentials);
        Assert.True(cred.HostIsIpAddress);

        Assert.Equal(8081, UrlAnalyzer.Analyze("http://example.com:8081/").Port);
        Assert.Null(UrlAnalyzer.Analyze("https://example.com:443/").Port);
        Assert.True(UrlAnalyzer.Analyze("https://bit.ly/3xYz").IsKnownShortener);
        Assert.True(UrlAnalyzer.Analyze("https://free-gift.tk/").UsesRiskyTopLevelDomain);
        Assert.False(UrlAnalyzer.Analyze("https://example.com/").UsesRiskyTopLevelDomain);

        var deep = UrlAnalyzer.Analyze("https://paypal.com.account.verify.secure.example.co.uk/");
        Assert.Equal(5, deep.SubdomainDepth);
        Assert.Equal("paypal", deep.LooksLike);
        Assert.Equal(1, UrlAnalyzer.Analyze("https://www.example.co.uk/").SubdomainDepth);
    }

    [Theory]
    [InlineData("https://paypa1-login.com/", "paypal")]
    [InlineData("https://rnicrosoft.com/", "microsoft")]
    [InlineData("https://g00gle.com/", "google")]
    [InlineData("https://arnazon-orders.net/", "amazon")]
    [InlineData("https://faceb00k-security.net/", "facebook")]
    [InlineData("https://netfllx.com/", "netflix")]
    [InlineData("https://instagramm.com/", "instagram")]
    [InlineData("https://secure-wellsfarg0.com/", "wellsfargo")]
    [InlineData("https://dhl-parcel-track.info/", "dhl")]
    [InlineData("https://login.microsoftonline.com.verify-account.top/", "microsoft")]
    [InlineData("https://paypal.tk/", "paypal")]
    public void Brand_lookalikes_are_named(string url, string brand) =>
        Assert.Equal(brand, UrlAnalyzer.Analyze(url).LooksLike);

    [Theory]
    [InlineData("https://www.paypal.com/signin")]
    [InlineData("https://login.microsoftonline.com/common/oauth2")]
    [InlineData("https://contoso.sharepoint.com/sites/x")]
    [InlineData("https://accounts.google.com/")]
    [InlineData("https://www.amazon.de/")]
    [InlineData("https://www.google.ro/")]
    [InlineData("https://someone.github.io/")]
    [InlineData("https://finance.yahoo.com/")]
    [InlineData("https://mycloud-storage.com/")]
    [InlineData("https://apply-now.com/")]
    [InlineData("https://www.purchase-orders.com/")]
    [InlineData("https://example.com/")]
    public void Real_brand_domains_and_ordinary_names_are_not_flagged(string url) =>
        Assert.Null(UrlAnalyzer.Analyze(url).LooksLike);

    [Fact]
    public void Every_note_is_written_in_both_languages()
    {
        var r = UrlAnalyzer.Analyze("http://user@paypa1.tk:8080/");
        Assert.True(r.Notes.Count >= 5);
        Assert.All(r.Notes, n =>
        {
            Assert.False(string.IsNullOrWhiteSpace(n.En));
            Assert.Contains(n.Ar, c => c is >= '\u0600' and <= '\u06FF');
        });
    }

    [Fact]
    public void Analyze_refuses_what_it_cannot_parse() =>
        Assert.Throws<ArgumentException>(() => UrlAnalyzer.Analyze("mailto:a@example.com"));
}
