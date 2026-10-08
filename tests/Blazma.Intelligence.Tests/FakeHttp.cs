using System.Net;
using System.Text;

namespace Blazma.Intelligence.Tests;

/// <summary>Answers HTTP requests in memory and records what was sent.</summary>
public sealed class FakeHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
{
    public List<HttpRequestMessage> Requests { get; } = [];
    public List<string?> Bodies { get; } = [];

    public static FakeHandler Json(HttpStatusCode status, string json) =>
        new((_, _) => Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") }));

    public static FakeHandler Status(HttpStatusCode status) =>
        new((_, _) => Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(string.Empty) }));

    /// <summary>Never answers until the token is cancelled.</summary>
    public static FakeHandler Hang() => new(async (_, ct) =>
    {
        await Task.Delay(Timeout.Infinite, ct);
        throw new InvalidOperationException("unreachable");
    });

    /// <summary>An endless body with no Content-Length: only a limit enforced while reading stops it.</summary>
    public static FakeHandler Endless() =>
        new((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new EndlessStream()) }));

    public HttpClient Client() => new(this);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        Bodies.Add(request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken));
        var response = await respond(request, cancellationToken);
        response.RequestMessage ??= request;
        return response;
    }
}

/// <summary>Non-seekable stream of '{' characters that never ends.</summary>
public sealed class EndlessStream : Stream
{
    public long Served { get; private set; }
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count)
    {
        Array.Fill(buffer, (byte)'{', offset, count);
        Served += count;
        return count;
    }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
