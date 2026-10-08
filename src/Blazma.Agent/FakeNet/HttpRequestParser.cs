using System.Text;

namespace Blazma.Agent.FakeNet;

internal sealed record HttpRequestInfo(string Method, string Target, string Version, string? Host, string? UserAgent, IReadOnlyDictionary<string, string> Headers, int HeaderBytes, long? ContentLength);

/// <summary>Parses the request line and headers of an HTTP/1.x request. Strict limits; anything odd is rejected, not guessed.</summary>
internal static class HttpRequestParser
{
    public const int MaxHeaderBytes = 16 * 1024;
    private const int MaxHeaders = 64;

    private static readonly HashSet<string> Methods = new(StringComparer.Ordinal)
    {
        "GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "CONNECT", "PROPFIND", "TRACE",
    };

    /// <summary>Returns false while the headers are incomplete or when the data is not HTTP.</summary>
    public static bool TryParse(ReadOnlySpan<byte> data, out HttpRequestInfo? request)
    {
        request = null;
        var end = data.IndexOf("\r\n\r\n"u8);
        if (end < 0 || end > MaxHeaderBytes) return false;
        var text = Encoding.Latin1.GetString(data[..end]);
        var lines = text.Split("\r\n");
        var first = lines[0].Split(' ');
        if (first.Length != 3 || !Methods.Contains(first[0]) || !first[2].StartsWith("HTTP/1.", StringComparison.Ordinal)) return false;
        if (first[1].Length is 0 or > 4096) return false;

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1).Take(MaxHeaders))
        {
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0) continue;
            var name = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            if (name.Length > 64) continue;
            if (value.Length > 1024) value = value[..1024];
            headers.TryAdd(name, value);
        }

        long? contentLength = headers.TryGetValue("Content-Length", out var cl) && long.TryParse(cl, out var n) && n >= 0 ? n : null;
        request = new HttpRequestInfo(first[0], first[1], first[2], headers.GetValueOrDefault("Host"), headers.GetValueOrDefault("User-Agent"), headers, end + 4, contentLength);
        return true;
    }
}
