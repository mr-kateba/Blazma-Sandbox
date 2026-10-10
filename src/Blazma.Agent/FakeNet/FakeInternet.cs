using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Blazma.Agent.FakeNet;

/// <summary>What the simulated internet saw: an HTTP request, a TLS server name, or raw bytes on another port.</summary>
internal sealed record FakeNetRecord(string Kind, int ServerPort, int ClientPort, string? Host, Dictionary<string, string> Details);

/// <summary>
/// Local servers on 127.0.0.1 that answer whatever the sample tries to reach once its
/// names resolve here (see <see cref="HostsFile"/>). HTTP gets a harmless page, TLS gets a
/// self-signed certificate (the server name is recorded either way), other ports are read
/// and logged. Every connection has a time and size budget; nothing is ever forwarded.
/// </summary>
internal sealed class FakeInternet : IDisposable
{
    public static readonly int[] DefaultHttpPorts = [80, 8080, 8000, 8888, 3000, 5000];
    public static readonly int[] DefaultTlsPorts = [443, 8443];
    public static readonly int[] DefaultRawPorts = [21, 25, 110, 143, 465, 587, 993, 995, 1080, 1337, 4444, 5555, 6667, 7777, 9001, 9050, 9999];

    private const int MaxRequestBytes = 64 * 1024;
    private const int MaxConnections = 2000;
    private static readonly TimeSpan ConnectionTimeout = TimeSpan.FromSeconds(10);

    private readonly Action<FakeNetRecord> _record;
    private readonly List<TcpListener> _listeners = [];
    private readonly CancellationTokenSource _stop = new();
    private readonly Lazy<X509Certificate2> _certificate = new(CreateCertificate);
    private readonly ConcurrentDictionary<int, byte> _ports = new();
    private int _connections;

    public FakeInternet(Action<FakeNetRecord> record) => _record = record;

    public IReadOnlyCollection<int> ListeningPorts => _ports.Keys.ToList();

    /// <summary>Starts listeners. A port already in use is skipped; the rest still work.</summary>
    public void Start(IEnumerable<int> httpPorts, IEnumerable<int> tlsPorts, IEnumerable<int> rawPorts)
    {
        foreach (var p in httpPorts) Listen(p, Protocol.Http);
        foreach (var p in tlsPorts) Listen(p, Protocol.Tls);
        foreach (var p in rawPorts) Listen(p, Protocol.Raw);
    }

    /// <summary>Starts one listener on an ephemeral port (tests). Returns the port.</summary>
    public int ListenEphemeral(bool tls, bool raw = false)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Accept(listener, port, raw ? Protocol.Raw : tls ? Protocol.Tls : Protocol.Http);
        return port;
    }

    private enum Protocol { Http, Tls, Raw }

    private void Listen(int port, Protocol protocol)
    {
        if (!_ports.TryAdd(port, 0)) return;
        try
        {
            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
            Accept(listener, port, protocol);
        }
        catch (SocketException ex)
        {
            AgentLog.Warn($"The simulated internet cannot listen on port {port}: {ex.Message}");
            _ports.TryRemove(port, out _);
        }
    }

    private void Accept(TcpListener listener, int port, Protocol protocol)
    {
        _listeners.Add(listener);
        _ = Task.Run(async () =>
        {
            while (!_stop.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(_stop.Token).ConfigureAwait(false); }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException) { return; }
                catch (Exception ex)
                {
                    AgentLog.Limited("fakenet-accept", $"The simulated server on port {port} stopped accepting connections", ex);
                    return;
                }
                if (Interlocked.Increment(ref _connections) > MaxConnections) { client.Dispose(); continue; }
                _ = Task.Run(() => HandleAsync(client, port, protocol));
            }
        });
    }

    private async Task HandleAsync(TcpClient client, int port, Protocol protocol)
    {
        using var _ = client;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
        timeout.CancelAfter(ConnectionTimeout);
        var clientPort = (client.Client.RemoteEndPoint as IPEndPoint)?.Port ?? 0;
        try
        {
            var stream = client.GetStream();
            switch (protocol)
            {
                case Protocol.Http:
                    await ServeHttpAsync(stream, port, clientPort, "http", timeout.Token).ConfigureAwait(false);
                    break;
                case Protocol.Tls:
                    await ServeTlsAsync(stream, port, clientPort, timeout.Token).ConfigureAwait(false);
                    break;
                default:
                    var data = await ReadSomeAsync(stream, 4096, timeout.Token).ConfigureAwait(false);
                    _record(new FakeNetRecord("raw", port, clientPort, null, new()
                    {
                        ["BytesReceived"] = data.Length.ToString(CultureInfo.InvariantCulture),
                        ["BodyPreview"] = Preview(data),
                    }));
                    break;
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or AuthenticationException or ObjectDisposedException or InvalidOperationException)
        {
            // The client went away, timed out or rejected the certificate: nothing more to record.
        }
        catch (Exception ex)
        {
            AgentLog.Limited("fakenet-connection", $"A simulated connection on port {port} failed", ex);
        }
    }

    private async Task ServeHttpAsync(Stream stream, int port, int clientPort, string scheme, CancellationToken ct)
    {
        var buffer = new byte[MaxRequestBytes];
        var filled = 0;
        HttpRequestInfo? request = null;
        while (filled < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(filled), ct).ConfigureAwait(false);
            if (n == 0) break;
            filled += n;
            if (HttpRequestParser.TryParse(buffer.AsSpan(0, filled), out request)) break;
            if (filled >= HttpRequestParser.MaxHeaderBytes) break;
        }
        if (request is null)
        {
            if (filled > 0)
                _record(new FakeNetRecord("raw", port, clientPort, null, new() { ["BytesReceived"] = filled.ToString(CultureInfo.InvariantCulture), ["BodyPreview"] = Preview(buffer.AsSpan(0, filled)) }));
            return;
        }

        // Read a little of the body (exfiltration attempts are worth seeing), never all of it.
        var bodyStart = request.HeaderBytes;
        var wanted = (int)Math.Min(request.ContentLength ?? 0, 2048);
        while (filled - bodyStart < wanted && filled < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(filled, Math.Min(buffer.Length - filled, wanted)), ct).ConfigureAwait(false);
            if (n == 0) break;
            filled += n;
        }
        var body = buffer.AsSpan(bodyStart, Math.Max(0, Math.Min(filled - bodyStart, 2048)));

        var details = new Dictionary<string, string>
        {
            ["HttpMethod"] = request.Method,
            ["HttpPath"] = Clip(request.Target, 2048),
            ["Protocol"] = scheme,
            ["RemotePort"] = port.ToString(CultureInfo.InvariantCulture),
            ["Simulated"] = "true",
        };
        if (request.Host is { Length: > 0 } host) details["HttpHost"] = Clip(host, 255);
        if (request.UserAgent is { Length: > 0 } ua) details["UserAgent"] = Clip(ua, 512);
        if (body.Length > 0) details["BodyPreview"] = Preview(body);
        if (request.ContentLength is { } len) details["BytesSent"] = len.ToString(CultureInfo.InvariantCulture);
        _record(new FakeNetRecord("http", port, clientPort, request.Host, details));

        var (contentType, payload) = ResponseFor(request.Target);
        var head = $"HTTP/1.1 200 OK\r\nContent-Type: {contentType}\r\nContent-Length: {payload.Length}\r\nConnection: close\r\nServer: blazma-simulated\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(head), ct).ConfigureAwait(false);
        if (request.Method != "HEAD") await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    private async Task ServeTlsAsync(NetworkStream stream, int port, int clientPort, CancellationToken ct)
    {
        // Peek at the ClientHello for the server name before handing the bytes to SslStream.
        var hello = new byte[16 * 1024];
        var filled = 0;
        string? serverName = null;
        while (filled < hello.Length)
        {
            var n = await stream.ReadAsync(hello.AsMemory(filled), ct).ConfigureAwait(false);
            if (n == 0) break;
            filled += n;
            if (TlsClientHello.TryGetServerName(hello.AsSpan(0, filled), out var sni)) { serverName = sni; break; }
            if (filled >= 5 && filled >= 5 + ((hello[3] << 8) | hello[4])) break; // whole first record read, no SNI
        }
        var details = new Dictionary<string, string> { ["RemotePort"] = port.ToString(CultureInfo.InvariantCulture), ["Simulated"] = "true" };
        if (serverName is not null) details["ServerName"] = serverName;
        _record(new FakeNetRecord("tls", port, clientPort, serverName, details));
        if (filled == 0) return;

        await using var replay = new ReplayStream(hello.AsMemory(0, filled), stream);
        await using var ssl = new SslStream(replay, leaveInnerStreamOpen: false);
        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = _certificate.Value }, ct).ConfigureAwait(false);
        await ServeHttpAsync(ssl, port, clientPort, "https", ct).ConfigureAwait(false);
    }

    private static (string ContentType, byte[] Payload) ResponseFor(string target)
    {
        var path = target.Split('?', 2)[0].ToLowerInvariant();
        var ext = Path.GetExtension(path);
        return ext switch
        {
            ".exe" or ".dll" or ".bin" or ".dat" or ".zip" or ".7z" or ".msi" or ".scr" => ("application/octet-stream", Encoding.ASCII.GetBytes("BLAZMA-SIMULATED-INTERNET: placeholder content, not a real download.\n")),
            ".ps1" or ".txt" or ".vbs" or ".js" or ".bat" => ("text/plain", Encoding.ASCII.GetBytes("# Blazma simulated internet: placeholder content.\r\n")),
            ".json" => ("application/json", Encoding.ASCII.GetBytes("{}")),
            _ => ("text/html; charset=utf-8", Encoding.ASCII.GetBytes("<!doctype html><html><head><title>OK</title></head><body>OK</body></html>")),
        };
    }

    private static async Task<byte[]> ReadSomeAsync(Stream stream, int max, CancellationToken ct)
    {
        var buffer = new byte[max];
        var filled = 0;
        try
        {
            while (filled < max)
            {
                var n = await stream.ReadAsync(buffer.AsMemory(filled), ct).ConfigureAwait(false);
                if (n == 0) break;
                filled += n;
            }
        }
        catch (OperationCanceledException) { }
        return buffer[..filled];
    }

    /// <summary>Printable preview of client data: ASCII kept, everything else as dots, bounded.</summary>
    public static string Preview(ReadOnlySpan<byte> data)
    {
        var length = Math.Min(data.Length, 512);
        var sb = new StringBuilder(length);
        foreach (var b in data[..length]) sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
        return sb.ToString();
    }

    private static string Clip(string s, int max) => s.Length > max ? s[..max] : s;

    private static X509Certificate2 CreateCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=simulated.blazma", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null);
    }

    public void Dispose()
    {
        _stop.Cancel();
        foreach (var l in _listeners)
        {
            try { l.Stop(); } catch (SocketException) { }
        }
        if (_certificate.IsValueCreated) _certificate.Value.Dispose();
        _stop.Dispose();
    }

    /// <summary>Replays the bytes already read for SNI, then continues with the socket.</summary>
    private sealed class ReplayStream(ReadOnlyMemory<byte> prefix, Stream inner) : Stream
    {
        private ReadOnlyMemory<byte> _prefix = prefix;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => inner.WriteAsync(buffer, cancellationToken);

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            if (_prefix.IsEmpty) return inner.Read(buffer);
            var n = Math.Min(buffer.Length, _prefix.Length);
            _prefix.Span[..n].CopyTo(buffer);
            _prefix = _prefix[n..];
            return n;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_prefix.IsEmpty) return inner.ReadAsync(buffer, cancellationToken);
            return ValueTask.FromResult(Read(buffer.Span));
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        protected override void Dispose(bool disposing)
        {
            if (disposing) inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
