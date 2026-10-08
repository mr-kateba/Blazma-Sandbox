using Blazma.Storage.Secrets;

namespace Blazma.Intelligence.Tests;

public class SecretProtectorTests
{
    [Fact]
    public void Portable_round_trips_and_says_it_is_only_obfuscation()
    {
        var p = new PortableSecretProtector();
        var stored = p.Protect("vt-key-123");
        Assert.StartsWith(SecretProtector.PlainPrefix, stored, StringComparison.Ordinal);
        Assert.DoesNotContain("vt-key-123", stored, StringComparison.Ordinal);
        Assert.Equal("vt-key-123", p.Unprotect(stored));
        Assert.False(p.IsStrong);
    }

    [Theory]
    [InlineData("")]
    [InlineData("plain:%%%not-base64")]
    [InlineData("plain:")]
    [InlineData("plain://79")] // valid base64, invalid UTF-8
    [InlineData("dpapi:AAAA")] // not readable off the Windows account that wrote it
    [InlineData("   ")]
    public void Portable_returns_null_for_unreadable_values(string stored) =>
        Assert.Null(new PortableSecretProtector().Unprotect(stored));

    [Fact]
    public void Legacy_raw_values_are_accepted()
    {
        Assert.Equal("legacy-key", new PortableSecretProtector().Unprotect("legacy-key"));
        if (OperatingSystem.IsWindows()) Assert.Equal("legacy-key", new DpapiSecretProtector().Unprotect("legacy-key"));
    }

    [Fact]
    public void Empty_secret_is_stored_as_empty() => Assert.Equal(string.Empty, new PortableSecretProtector().Protect(string.Empty));

    [Fact]
    public void Default_matches_the_platform()
    {
        var p = SecretProtector.CreateDefault();
        Assert.Equal(OperatingSystem.IsWindows(), p.IsStrong);
        Assert.Equal("round-trip", p.Unprotect(p.Protect("round-trip")));
    }

    [WindowsFact]
    public void Dpapi_round_trips_and_reads_every_form()
    {
        if (!OperatingSystem.IsWindows()) return; // Skipped by [WindowsFact]; keeps the platform analyzer satisfied.
        var p = new DpapiSecretProtector();
        var stored = p.Protect("vt-key-123");
        Assert.StartsWith(SecretProtector.DpapiPrefix, stored, StringComparison.Ordinal);
        Assert.Equal("vt-key-123", p.Unprotect(stored));
        Assert.Equal("vt-key-123", p.Unprotect(new PortableSecretProtector().Protect("vt-key-123")));
        Assert.Null(p.Unprotect("dpapi:AAAA"));
        Assert.Null(p.Unprotect("dpapi:%%%"));
        Assert.True(p.IsStrong);
    }
}
