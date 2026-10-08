using System.Text;
using Blazma.Agent.FakeNet;

namespace Blazma.Agent.Tests;

public class ParserTests
{
    [Fact]
    public void Http_request_line_and_headers_are_parsed()
    {
        var raw = "POST /gate.php?id=7 HTTP/1.1\r\nHost: c2.example.test\r\nUser-Agent: Mozilla/5.0 (evil)\r\nContent-Length: 4\r\n\r\nabcd"u8;
        Assert.True(HttpRequestParser.TryParse(raw, out var r));
        Assert.Equal("POST", r!.Method);
        Assert.Equal("/gate.php?id=7", r.Target);
        Assert.Equal("c2.example.test", r.Host);
        Assert.Equal("Mozilla/5.0 (evil)", r.UserAgent);
        Assert.Equal(4, r.ContentLength);
        Assert.Equal(raw.Length - 4, r.HeaderBytes);
    }

    [Theory]
    [InlineData("GET / HTTP/1.1\r\nHost: x")]                 // headers not finished yet
    [InlineData("HELLO / HTTP/1.1\r\n\r\n")]                  // unknown method
    [InlineData("GET / SPDY/3\r\n\r\n")]                      // not HTTP/1.x
    [InlineData("\u0016\u0003\u0001\u0002\u0000\u0001\r\n\r\n")] // TLS bytes on an HTTP port
    public void Non_http_or_incomplete_data_is_rejected(string text)
    {
        Assert.False(HttpRequestParser.TryParse(Encoding.Latin1.GetBytes(text), out _));
    }

    [Fact]
    public void Oversized_headers_are_rejected()
    {
        var text = "GET / HTTP/1.1\r\nX: " + new string('a', HttpRequestParser.MaxHeaderBytes) + "\r\n\r\n";
        Assert.False(HttpRequestParser.TryParse(Encoding.ASCII.GetBytes(text), out _));
    }

    [Fact]
    public void Garbage_is_not_a_client_hello()
    {
        Assert.False(TlsClientHello.TryGetServerName([], out _));
        Assert.False(TlsClientHello.TryGetServerName("GET / HTTP/1.1\r\n\r\n"u8, out _));
        Assert.False(TlsClientHello.TryGetServerName([22, 3, 1, 0xFF, 0xFF, 1, 0, 0], out _)); // lengths beyond the data
        var random = new byte[4096];
        new Random(7).NextBytes(random);
        random[0] = 22;
        TlsClientHello.TryGetServerName(random, out _); // must not throw
    }

    [Fact]
    public void Hosts_lines_are_added_once_and_only_for_valid_names()
    {
        var existing = "# comment\r\n127.0.0.1 already.example\r\n";
        var lines = HostsFile.NewLines(existing, ["c2.example.test", "C2.EXAMPLE.TEST.", "already.example", "localhost", "bad name", "x..y", "printer.local", ""]);
        Assert.Equal(["127.0.0.1 c2.example.test " + HostsFile.Marker], lines);
    }

    [Fact]
    public void Hosts_entries_are_capped()
    {
        var names = Enumerable.Range(0, HostsFile.MaxEntries + 50).Select(i => $"n{i}.example.test");
        Assert.Equal(HostsFile.MaxEntries, HostsFile.NewLines(string.Empty, names).Count);
    }

    [Fact]
    public void Hosts_file_is_appended_not_replaced()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "127.0.0.1 keep.example");
            Assert.Equal(2, HostsFile.Add(path, ["a.example.test", "b.example.test", "a.example.test"]));
            Assert.Equal(0, HostsFile.Add(path, ["a.example.test"]));
            var text = File.ReadAllText(path);
            Assert.StartsWith("127.0.0.1 keep.example\r\n", text, StringComparison.Ordinal);
            Assert.Contains("127.0.0.1 b.example.test", text, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
