namespace Blazma.Agent.Tests;

public class NetworkAttemptTests
{
    /// <summary>SOCKADDR_IN: family 2 (little-endian), port (big-endian), 4 address bytes, 8 bytes of zero.</summary>
    private static byte[] V4(byte a, byte b, byte c, byte d, int port) => [2, 0, (byte)(port >> 8), (byte)port, a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0];

    /// <summary>SOCKADDR_IN6: family 23, port, flow info, 16 address bytes, scope id.</summary>
    private static byte[] V6(byte[] address, int port)
    {
        var data = new byte[28];
        data[0] = 23;
        data[2] = (byte)(port >> 8);
        data[3] = (byte)port;
        address.CopyTo(data, 8);
        return data;
    }

    [Fact]
    public void IPv4_socket_address_is_decoded()
    {
        Assert.True(SocketAddressParser.TryParse(V4(203, 0, 113, 5, 443), out var ip, out var port));
        Assert.Equal("203.0.113.5", ip);
        Assert.Equal(443, port);
    }

    [Fact]
    public void IPv6_socket_address_is_decoded()
    {
        var address = System.Net.IPAddress.Parse("2001:db8::25").GetAddressBytes();
        Assert.True(SocketAddressParser.TryParse(V6(address, 8443), out var ip, out var port));
        Assert.Equal("2001:db8::25", ip);
        Assert.Equal(8443, port);
    }

    [Fact]
    public void IPv4_mapped_IPv6_is_reported_as_IPv4()
    {
        // Dual-stack sockets (the .NET default) connect to IPv4 servers through ::ffff:a.b.c.d.
        var address = System.Net.IPAddress.Parse("::ffff:198.51.100.7").GetAddressBytes();
        Assert.True(SocketAddressParser.TryParse(V6(address, 80), out var ip, out var port));
        Assert.Equal("198.51.100.7", ip);
        Assert.Equal(80, port);
    }

    [Fact]
    public void Malformed_socket_addresses_are_rejected()
    {
        Assert.False(SocketAddressParser.TryParse([], out _, out _));
        Assert.False(SocketAddressParser.TryParse([2, 0, 1], out _, out _));                                 // too short
        Assert.False(SocketAddressParser.TryParse(V6(new byte[16], 80).AsSpan(0, 20), out _, out _));       // IPv6 cut short
        Assert.False(SocketAddressParser.TryParse([1, 0, 0, 80, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0], out _, out _)); // AF_UNIX and others
        Assert.False(SocketAddressParser.TryParse((object?)null, out _, out _));
        Assert.False(SocketAddressParser.TryParse((object)42, out _, out _));
        var random = new byte[64];
        new Random(3).NextBytes(random);
        SocketAddressParser.TryParse(random, out _, out _); // must not throw
    }

    [Theory]
    [InlineData("203.0.113.5:443", "203.0.113.5", 443)]
    [InlineData("[2001:db8::1]:8080", "2001:db8::1", 8080)]
    [InlineData("[::ffff:192.0.2.1]:25", "192.0.2.1", 25)]
    [InlineData("0x020001BBCB00710500000000000000000", null, 0)] // odd number of hex digits
    [InlineData("0x020001BBCB007105", "203.0.113.5", 443)]
    public void Payloads_formatted_as_text_are_understood(string text, string? expected, int expectedPort)
    {
        var ok = SocketAddressParser.TryParse((object)text, out var ip, out var port);
        Assert.Equal(expected is not null, ok);
        if (expected is null) return;
        Assert.Equal(expected, ip);
        Assert.Equal(expectedPort, port);
    }

    [Theory]
    [InlineData(0L, false)]
    [InlineData(0x103L, false)]                   // STATUS_PENDING: still connecting
    [InlineData(0x80000005L, false)]              // a warning
    [InlineData(0xC000023CL, true)]               // STATUS_NETWORK_UNREACHABLE
    [InlineData(unchecked((int)0xC0000236), true)] // STATUS_CONNECTION_REFUSED, as a signed 32-bit payload
    public void Only_NTSTATUS_errors_are_failures(long status, bool failure)
    {
        Assert.Equal(failure, EtwValue.IsFailure(status));
    }

    [Fact]
    public void Status_is_printed_like_windows()
    {
        Assert.Equal("0xC000023C", EtwValue.Hex(unchecked((int)0xC000023C)));
        Assert.Equal(0xC000023CL, EtwValue.Number("0xC000023C"));
        Assert.Equal(42L, EtwValue.Number(42u));
        Assert.Null(EtwValue.Number("nope"));
    }

    [Fact]
    public void Retries_are_counted_not_repeated()
    {
        var attempts = new ConnectAttempts();
        Assert.Equal(AttemptReport.Attempted, attempts.Attempt(10, "192.0.2.77", 8443, "TCP"));
        Assert.Equal(AttemptReport.None, attempts.Attempt(10, "192.0.2.77", 8443, "TCP"));
        Assert.Equal(AttemptReport.Failed, attempts.Attempt(10, "192.0.2.77", 8443, "TCP", failed: true, status: 0xC000023C));
        Assert.Equal(AttemptReport.None, attempts.Attempt(10, "192.0.2.77", 8443, "TCP", failed: true, status: 0xC000023C));
        // The stack's failure event for an attempt already seen is its outcome, not one more try.
        Assert.Equal(AttemptReport.None, attempts.Failure(10, "192.0.2.77", 8443, "TCP", 0xC00000B5));
        // Another process, port or protocol is another destination.
        Assert.Equal(AttemptReport.Attempted, attempts.Attempt(11, "192.0.2.77", 8443, "TCP"));
        Assert.Equal(AttemptReport.Attempted, attempts.Attempt(10, "192.0.2.77", 8443, "UDP"));

        var total = Assert.Single(attempts.Totals(), t => t is { Pid: 10, Protocol: "TCP" });
        Assert.Equal(4, total.Count);
        Assert.True(total.Failed);
        Assert.Equal(0xC00000B5, total.LastFailure);
    }

    [Fact]
    public void A_failure_without_an_attempt_counts_once()
    {
        var attempts = new ConnectAttempts();
        Assert.Equal(AttemptReport.Failed, attempts.Failure(10, "203.0.113.9", 443, "TCP", null));
        Assert.Equal(1, Assert.Single(attempts.Totals()).Count);
    }

    [Fact]
    public void Destinations_are_capped()
    {
        var attempts = new ConnectAttempts(maxDestinations: 3);
        for (var i = 1; i <= 5; i++) attempts.Attempt(10, $"192.0.2.{i}", 80, "TCP");
        Assert.Equal(3, attempts.Totals().Count);
        Assert.Equal(2, attempts.Overflow);
        Assert.Equal(AttemptReport.None, attempts.Attempt(10, "192.0.2.1", 80, "TCP")); // tracked ones still count
        Assert.Equal(2, attempts.Totals().Single(t => t.Address == "192.0.2.1").Count);
    }

    [Fact]
    public void Dns_answers_keep_addresses_only()
    {
        Assert.Equal(["203.0.113.7", "2001:db8::7"], DnsAnswers.Addresses("type:  5 cdn.example.net;::ffff:203.0.113.7;2001:db8::7;::ffff:203.0.113.7;", dropLoopback: false));
        Assert.Empty(DnsAnswers.Addresses("::ffff:127.0.0.1;", dropLoopback: true));
        Assert.Equal(["127.0.0.1"], DnsAnswers.Addresses("127.0.0.1", dropLoopback: false));
        Assert.Empty(DnsAnswers.Addresses(null, dropLoopback: false));
    }

    [Fact]
    public void Only_connect_attempt_events_are_enabled()
    {
        Assert.Equal(new Guid("E53C6823-7BB8-44BB-90DC-3F86090D48A6"), AttemptEvents.WinsockAfd);
        Assert.Equal(new Guid("2F07E2EE-15DB-40F1-90EF-9D7BA282188A"), AttemptEvents.TcpIp);
        Assert.DoesNotContain(1003, AttemptEvents.Afd.Enabled); // sends on connected sockets: far too many
        Assert.DoesNotContain(1004, AttemptEvents.Afd.Enabled); // receives
        Assert.Contains(AttemptEvents.Afd.ConnectWithAddress, AttemptEvents.Afd.Enabled);
        Assert.Contains(AttemptEvents.Tcp.FailedRoute, AttemptEvents.Tcp.Enabled);
    }
}
