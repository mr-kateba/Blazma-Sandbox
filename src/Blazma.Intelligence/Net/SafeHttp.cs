using System.Net;

namespace Blazma.Intelligence.Net;

/// <summary>
/// HttpClient factory for online lookups and local AI. Redirects are never followed and
/// cookies are never kept; the size limit applies to the decompressed body.
/// </summary>
public static class IntegrationHttp
{
    /// <param name="useProxy">
    /// True for internet services (the system proxy applies). False for the local AI client,
    /// so a prompt meant for this computer is never handed to a proxy.
    /// </param>
    public static HttpClient CreateClient(bool useProxy = true) => new(CreateHandler(useProxy), disposeHandler: true)
    {
        // Each request has its own, shorter timeout; this is only a backstop.
        Timeout = TimeSpan.FromMinutes(10),
    };

    public static SocketsHttpHandler CreateHandler(bool useProxy = true) => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = useProxy,
        AutomaticDecompression = DecompressionMethods.All,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        ConnectTimeout = TimeSpan.FromSeconds(15),
    };
}

internal sealed record HttpReply(HttpStatusCode Status, byte[] Body, Uri? FinalUri);

/// <summary>The server sent more than the caller is willing to read.</summary>
internal sealed class ResponseTooLargeException : Exception
{
    public ResponseTooLargeException() : base("The response exceeded the size limit.") { }
}

internal static class SafeHttp
{
    public const int DefaultMaxResponseBytes = 2 * 1024 * 1024;

    /// <summary>
    /// Sends the request and reads at most <paramref name="maxBytes"/> of body, enforced while
    /// reading. Throws <see cref="TimeoutException"/> when <paramref name="timeout"/> elapses,
    /// <see cref="OperationCanceledException"/> only when the caller cancels,
    /// <see cref="ResponseTooLargeException"/> and <see cref="HttpRequestException"/>.
    /// </summary>
    public static async Task<HttpReply> SendAsync(HttpClient http, HttpRequestMessage request, TimeSpan timeout, int maxBytes, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        try
        {
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            if (response.Content.Headers.ContentLength > maxBytes) throw new ResponseTooLargeException();

            var stream = await response.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
            await using (stream.ConfigureAwait(false))
            {
                using var body = new MemoryStream();
                var chunk = new byte[16 * 1024];
                int read;
                while ((read = await stream.ReadAsync(chunk, cts.Token).ConfigureAwait(false)) > 0)
                {
                    if (body.Length + read > maxBytes) throw new ResponseTooLargeException();
                    body.Write(chunk, 0, read);
                }
                return new HttpReply(response.StatusCode, body.ToArray(), response.RequestMessage?.RequestUri);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Our own timeout (or HttpClient.Timeout), not the caller.
            throw new TimeoutException();
        }
    }

    /// <summary>True when the response came from somewhere other than where the request went.</summary>
    public static bool WasRedirectedElsewhere(Uri requested, Uri? final) =>
        final is not null && (!string.Equals(requested.Scheme, final.Scheme, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(requested.IdnHost, final.IdnHost, StringComparison.OrdinalIgnoreCase)
            || requested.Port != final.Port);

    public static bool IsRedirect(HttpStatusCode status) => (int)status is >= 300 and < 400;
}
