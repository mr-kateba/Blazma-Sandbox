using Blazma.Analysis.Engine;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Indicators;
using Blazma.Sandbox.Providers.Demo;

namespace Blazma.Analysis.Tests;

public class NetworkDestinationTests
{
    private static Dictionary<string, string> Attempt(string ip, int port, string status, string? error = null, int attempts = 0, string protocol = "TCP")
    {
        var d = new Dictionary<string, string>
        {
            [DetailKeys.RemoteAddress] = ip,
            [DetailKeys.RemotePort] = port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            [DetailKeys.Protocol] = protocol,
            [DetailKeys.Status] = status,
        };
        if (error is not null) d[DetailKeys.ErrorCode] = error;
        if (attempts > 0) d[DetailKeys.Attempts] = attempts.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return d;
    }

    private static Dictionary<string, string> Simulated(int port, params (string Key, string Value)[] extra)
    {
        var d = new Dictionary<string, string>
        {
            [DetailKeys.RemoteAddress] = "127.0.0.1",
            [DetailKeys.RemotePort] = port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            [DetailKeys.Simulated] = "true",
        };
        foreach (var (k, v) in extra) d[k] = v;
        return d;
    }

    [Fact]
    public void Attempts_retries_and_failures_fold_into_one_row()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "setup.exe", @"C:\Users\u\Desktop\setup.exe", sample: true);
        ev.Raw(1000, EventAction.NetworkConnect, 100, s, "setup.exe", "192.0.2.77", Attempt("192.0.2.77", 8443, ConnectStatus.Attempted));
        ev.Raw(1010, EventAction.NetworkConnect, 100, s, "setup.exe", "192.0.2.77", Attempt("192.0.2.77", 8443, ConnectStatus.Failed, "0xC000023C"));
        ev.Raw(9000, EventAction.NetworkConnect, 100, s, "setup.exe", "192.0.2.77", Attempt("192.0.2.77", 8443, ConnectStatus.Failed, "0xC000023C", attempts: 7));

        var result = TestEngine.Run(ev.Events);

        var d = Assert.Single(result.NetworkDestinations);
        Assert.Equal("192.0.2.77", d.Address);
        Assert.Equal(8443, d.Port);
        Assert.Equal("TCP", d.Protocol);
        Assert.Equal(DestinationStatus.Failed, d.Status);
        Assert.Equal("0xC000023C", d.ErrorCode);
        Assert.Equal(7, d.Count);
        Assert.Equal(TimeSpan.FromSeconds(1), d.FirstSeen);
        Assert.Equal(["setup.exe"], d.Processes);
        Assert.True(d.External);
        Assert.True(d.DirectIp);
        Assert.Contains("network", NetworkDestinations.DescribeError(d.ErrorCode).En, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_connection_that_succeeded_wins_and_bytes_are_added()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "setup.exe", sample: true);
        ev.Dns(500, 100, s, "setup.exe", "cdn.example.net", "type: 5 edge.example.net;::ffff:198.51.100.7");
        ev.Raw(900, EventAction.NetworkConnect, 100, s, "setup.exe", "198.51.100.7", Attempt("198.51.100.7", 443, ConnectStatus.Attempted));
        ev.Connect(1000, 100, s, "setup.exe", "198.51.100.7", 443); // an older agent: no status means connected
        ev.Raw(5000, EventAction.NetworkSend, 100, s, "setup.exe", "198.51.100.7", new()
        {
            [DetailKeys.RemoteAddress] = "198.51.100.7", [DetailKeys.RemotePort] = "443", [DetailKeys.BytesSent] = "1200", [DetailKeys.BytesReceived] = "5300",
        });

        var d = Assert.Single(TestEngine.Run(ev.Events).NetworkDestinations);
        Assert.Equal(DestinationStatus.Connected, d.Status);
        Assert.Equal("cdn.example.net", d.Domain);
        Assert.Equal("dns", d.DomainSource);
        Assert.False(d.DirectIp);
        Assert.Equal(1, d.Count);
        Assert.Equal(1200, d.BytesSent);
        Assert.Equal(5300, d.BytesReceived);
    }

    [Fact]
    public void Simulated_connections_show_the_name_never_the_loopback_address()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "setup.exe", sample: true);
        ev.Dns(100, 100, s, "setup.exe", "c2.example.net");
        // The program's own TCP connection to the simulated server (the hosts file sent it to 127.0.0.1).
        ev.Connect(200, 100, s, "setup.exe", "127.0.0.1", 443);
        ev.Raw(210, EventAction.TlsHandshake, 100, s, "setup.exe", "c2.example.net", Simulated(443, (DetailKeys.ServerName, "c2.example.net")));
        ev.Raw(220, EventAction.HttpRequest, 100, s, "setup.exe", "https://c2.example.net/gate", Simulated(443,
            (DetailKeys.HttpHost, "C2.Example.Net:443"), (DetailKeys.Protocol, "https"), (DetailKeys.HttpMethod, "POST"), (DetailKeys.BytesSent, "64")));
        ev.Raw(300, EventAction.HttpRequest, 100, s, "setup.exe", "http://plain.example.org/x", Simulated(80, (DetailKeys.HttpHost, "plain.example.org"), (DetailKeys.Protocol, "http")));
        // Raw bytes on another port: no name in the data, the lookup just before names it.
        ev.Dns(400, 100, s, "setup.exe", "irc.example.org");
        ev.Raw(450, EventAction.NetworkSend, 100, s, "setup.exe", "127.0.0.1", Simulated(6667, (DetailKeys.BytesReceived, "120")));

        var result = TestEngine.Run(ev.Events);
        var rows = result.NetworkDestinations;

        Assert.DoesNotContain(rows, d => d.Address == "127.0.0.1" || d.Domain == "127.0.0.1");
        var tls = Assert.Single(rows, d => d.Domain == "c2.example.net");
        Assert.Equal(DestinationStatus.Simulated, tls.Status);
        Assert.Equal("HTTPS", tls.Protocol);
        Assert.Equal(443, tls.Port);
        Assert.Equal(1, tls.Count); // the TLS connection; the request inside it is not a second connection
        Assert.Equal(64, tls.BytesSent);
        Assert.Null(tls.Address);
        Assert.False(tls.DirectIp);
        Assert.Equal("HTTP", Assert.Single(rows, d => d.Domain == "plain.example.org").Protocol);
        var raw = Assert.Single(rows, d => d.Domain == "irc.example.org");
        Assert.Equal(("lookup", 6667, 120L), (raw.DomainSource, raw.Port!.Value, raw.BytesSent));
        Assert.DoesNotContain(rows, d => d.Status == DestinationStatus.LookupOnly); // every looked-up name was reached

        // Names reached through the simulated internet are indicators even without a DNS event for them.
        Assert.Contains(result.Indicators, i => i.Type == IndicatorType.Domain && i.Value == "plain.example.org");
        Assert.DoesNotContain(result.Indicators, i => i.Type == IndicatorType.IpAddress && i.Value == "127.0.0.1");
    }

    [Fact]
    public void Names_looked_up_but_never_reached_are_listed_with_networking_off()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "setup.exe", sample: true);
        ev.Dns(100, 100, s, "setup.exe", "update.example.net");
        ev.Dns(2100, 100, s, "setup.exe", "update.example.net.");
        ev.Dns(3000, 100, s, "setup.exe", "printer.local");

        var rows = TestEngine.Run(ev.Events).NetworkDestinations;
        var d = Assert.Single(rows, r => r.Domain == "update.example.net");
        Assert.Equal(DestinationStatus.LookupOnly, d.Status);
        Assert.Equal("DNS", d.Protocol);
        Assert.Equal(2, d.Count);
        Assert.True(d.External);
        Assert.False(Assert.Single(rows, r => r.Domain == "printer.local").External);
        Assert.Equal(["update.example.net"], NetworkDestinations.ContactedDomains(rows));
    }

    [Fact]
    public void Background_processes_are_not_listed()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "setup.exe", sample: true);
        var svc = ev.Start(-60_000, 900, 4, "svchost.exe");
        ev.Raw(500, EventAction.NetworkConnect, 900, svc, "svchost.exe", "203.0.113.50", Attempt("203.0.113.50", 443, ConnectStatus.Failed, "0xC000023C"));
        ev.Raw(600, EventAction.NetworkConnect, 100, s, "setup.exe", "203.0.113.60", Attempt("203.0.113.60", 9001, ConnectStatus.Attempted));

        var d = Assert.Single(TestEngine.Run(ev.Events, new EngineSettings { SuppressBackgroundNoise = false }).NetworkDestinations);
        Assert.Equal("203.0.113.60", d.Address);
        Assert.Equal(DestinationStatus.Attempted, d.Status);
    }

    [Fact]
    public void Attempted_addresses_are_indicators_and_raise_the_direct_ip_finding()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "setup.exe", sample: true);
        ev.Raw(1000, EventAction.NetworkConnect, 100, s, "setup.exe", "::ffff:192.0.2.77", Attempt("::ffff:192.0.2.77", 8443, ConnectStatus.Failed, "0xC000023C", attempts: 5));
        ev.Raw(1000, EventAction.NetworkConnect, 100, s, "setup.exe", "2001:db8::25", Attempt("2001:db8::25", 443, ConnectStatus.Attempted));

        var result = TestEngine.Run(ev.Events);

        Assert.Contains(result.Indicators, i => i.Type == IndicatorType.IpAddress && i.Value == "192.0.2.77");
        Assert.Contains(result.Indicators, i => i.Type == IndicatorType.IpAddress && i.Value == "2001:db8::25");
        var direct = Assert.Single(result.Findings, f => f.RuleId == "BLZ-N007");
        Assert.Equal(Severity.Medium, direct.Severity);
        Assert.Equal(2, direct.Evidence.Count);
        Assert.Contains(direct.Evidence, e => e.Technical == "[2001:db8::25]:443");
        Assert.Contains(direct.Evidence, e => e.Description.En.Contains("5 attempts", StringComparison.Ordinal));
        var retries = Assert.Single(result.Findings, f => f.RuleId == "BLZ-N008");
        Assert.Equal("192.0.2.77:8443", Assert.Single(retries.Evidence).Technical);
        Assert.Contains(result.Risk.Contributions, c => c.Title.En == direct.Title.En);
    }

    [Fact]
    public void An_address_from_a_name_lookup_is_not_a_direct_ip_contact()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "setup.exe", sample: true);
        ev.Dns(500, 100, s, "setup.exe", "api.example.net", "203.0.113.24");
        ev.Raw(900, EventAction.NetworkConnect, 100, s, "setup.exe", "203.0.113.24", Attempt("203.0.113.24", 443, ConnectStatus.Failed, "0xC00000B5", attempts: 2));

        var result = TestEngine.Run(ev.Events);
        Assert.DoesNotContain(result.Findings, f => f.RuleId is "BLZ-N007" or "BLZ-N008");
        Assert.Equal("api.example.net", Assert.Single(result.NetworkDestinations).Domain);
    }

    [Fact]
    public void Simulated_loopback_answers_do_not_name_addresses()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "setup.exe", sample: true);
        ev.Dns(100, 100, s, "setup.exe", "one.example.net", "127.0.0.1");
        var map = NetworkMap.Build(ev.Events);
        Assert.Null(map.DomainFor("127.0.0.1"));
    }

    [Fact]
    public void Demo_shows_attempted_external_addresses()
    {
        var scenario = DemoScenario.PersistentUpdater("setup.exe", DateTimeOffset.UnixEpoch);
        var result = TestEngine.Run(scenario.Events);
        var rows = result.NetworkDestinations;

        var hardCoded = Assert.Single(rows, d => d.Address == "192.0.2.77");
        Assert.Equal((DestinationStatus.Failed, 8443, 6, true), (hardCoded.Status, hardCoded.Port!.Value, hardCoded.Count, hardCoded.DirectIp));
        Assert.Contains(rows, d => d.Address == "2001:db8:4b1::25" && d.Status == DestinationStatus.Failed);
        Assert.Contains(rows, d => d.Address == "198.51.100.200" && d.Protocol == "UDP" && d.Status == DestinationStatus.Attempted);
        Assert.Contains(rows, d => d.Address == "198.51.100.7" && d.Status == DestinationStatus.Connected && d.Domain == "cdn.contoso-update.example");
        Assert.Contains(rows, d => d.Domain == "api.contoso-update.example" && d.Status == DestinationStatus.Simulated);
        Assert.Contains(rows, d => d.Domain == "telemetry.contoso-update.example" && d.Status == DestinationStatus.LookupOnly);
        Assert.DoesNotContain(rows, d => d.Processes.Contains("svchost.exe"));
        Assert.Contains(result.Findings, f => f.RuleId == "BLZ-N007");
        Assert.Contains(result.Indicators, i => i.Type == IndicatorType.IpAddress && i.Value == "192.0.2.77");
    }
}
