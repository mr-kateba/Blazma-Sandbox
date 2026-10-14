using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Settings;

namespace Blazma.Intelligence.Net;

/// <summary>Limits for looking up contacted domains after an analysis.</summary>
public sealed record DnsOverHttpsOptions
{
    public static DnsOverHttpsOptions Default { get; } = new();

    /// <summary>Cloudflare's public resolver, JSON API (RFC 8484 GET with <c>accept: application/dns-json</c>).</summary>
    public Uri Endpoint { get; init; } = new("https://cloudflare-dns.com/dns-query");

    /// <summary>Per request.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(8);

    /// <summary>For the whole batch: names not reached in time are reported as not looked up.</summary>
    public TimeSpan TotalTimeout { get; init; } = TimeSpan.FromSeconds(60);

    public int MaxDomains { get; init; } = 25;

    /// <summary>Largest answer read, enforced while reading. A DNS answer is a few hundred bytes.</summary>
    public int MaxResponseBytes { get; init; } = 64 * 1024;

    public int MaxAddressesPerDomain { get; init; } = 16;
}

/// <summary>
/// Opt-in: looks up the current IPv4 and IPv6 addresses of the domains an analysis
/// contacted, from this computer, after the analysis, through a public DNS-over-HTTPS
/// resolver, so the domains' owners do not see this computer's address and the local
/// network's resolver is not involved. Sends the domain name and the record type only:
/// no file, hash, path, address or analysis detail. Every failure becomes a result with
/// an error; only the caller's own cancellation throws.
/// </summary>
public sealed partial class DnsOverHttpsResolver : IHostDomainResolver
{
    private readonly HttpClient _http;
    private readonly Func<IntegrationSettings> _settings;
    private readonly DnsOverHttpsOptions _options;
    private readonly TimeProvider _time;

    /// <param name="httpClient">Use <see cref="IntegrationHttp.CreateClient"/> (no redirects, no cookies).</param>
    /// <param name="settings">Read on every call, so the setting applies without a restart.</param>
    public DnsOverHttpsResolver(HttpClient httpClient, Func<IntegrationSettings> settings, DnsOverHttpsOptions? options = null, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(settings);
        _http = httpClient;
        _settings = settings;
        _options = options ?? DnsOverHttpsOptions.Default;
        _time = time ?? TimeProvider.System;
    }

    public bool IsEnabled => _settings().ResolveContactedDomains;

    public async Task<IReadOnlyList<HostResolution>> ResolveAsync(IEnumerable<string> domains, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domains);
        cancellationToken.ThrowIfCancellationRequested();
        if (!IsEnabled) return [];
        var names = domains.Select(ToQueryName).OfType<string>().Distinct(StringComparer.Ordinal).Take(_options.MaxDomains).ToList();
        var results = new List<HostResolution>(names.Count);
        using var total = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        total.CancelAfter(_options.TotalTimeout);
        foreach (var name in names)
        {
            if (total.IsCancellationRequested)
            {
                cancellationToken.ThrowIfCancellationRequested();
                results.Add(Failed(name, "Not looked up: the time allowed for these lookups ran out."));
                continue;
            }
            results.Add(await ResolveOneAsync(name, total.Token, cancellationToken).ConfigureAwait(false));
        }
        return results;
    }

    /// <summary>
    /// The name as it is sent: lower case, ASCII (IDN), a public-looking host name. IP addresses,
    /// single labels and reserved or local suffixes are never sent; they have no public answer.
    /// </summary>
    public static string? ToQueryName(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return null;
        var name = domain.Trim().TrimEnd('.');
        if (name.Length is 0 or > 253 || IPAddress.TryParse(name, out _)) return null;
        try { name = new IdnMapping().GetAscii(name).ToLowerInvariant(); }
        catch (ArgumentException) { return null; }
        if (!HostName().IsMatch(name) || !name.Contains('.', StringComparison.Ordinal)) return null;
        return ReservedSuffixes.Any(s => name == s[1..] || name.EndsWith(s, StringComparison.Ordinal)) ? null : name;
    }

    private static readonly string[] ReservedSuffixes = [".local", ".localhost", ".invalid", ".test", ".example", ".internal", ".lan", ".home.arpa", ".arpa", ".onion"];

    private async Task<HostResolution> ResolveOneAsync(string name, CancellationToken token, CancellationToken caller)
    {
        var addresses = new List<string>();
        var answered = 0;
        string? error = null;
        foreach (var type in new[] { "A", "AAAA" })
        {
            var (_, found, problem) = await QueryAsync(name, type, token, caller).ConfigureAwait(false);
            if (problem is not null) { error ??= problem; continue; }
            answered++;
            foreach (var a in found)
                if (addresses.Count < _options.MaxAddressesPerDomain && !addresses.Contains(a, StringComparer.OrdinalIgnoreCase)) addresses.Add(a);
        }
        var resolved = new HostResolution
        {
            Domain = name,
            // NXDOMAIN, or no address of either type: the name has no public address (now).
            Status = addresses.Count > 0 ? HostResolutionStatus.Resolved : answered > 0 ? HostResolutionStatus.NotFound : HostResolutionStatus.Failed,
            Addresses = addresses,
            Resolver = _options.Endpoint.IdnHost,
            ResolvedAt = _time.GetUtcNow(),
        };
        return resolved.Status == HostResolutionStatus.Failed ? resolved with { Error = error } : resolved;
    }

    /// <returns>The DNS response code, the addresses of the requested type, or a problem in words.</returns>
    private async Task<(int Status, IReadOnlyList<string> Addresses, string? Problem)> QueryAsync(string name, string type, CancellationToken token, CancellationToken caller)
    {
        var uri = new Uri($"{_options.Endpoint.GetLeftPart(UriPartial.Path)}?name={Uri.EscapeDataString(name)}&type={type}");
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Accept.ParseAdd("application/dns-json");
            var reply = await SafeHttp.SendAsync(_http, request, _options.Timeout, _options.MaxResponseBytes, token).ConfigureAwait(false);
            if (SafeHttp.WasRedirectedElsewhere(uri, reply.FinalUri) || SafeHttp.IsRedirect(reply.Status)) return (-1, [], "The resolver answered with a redirect; it was not followed.");
            if (reply.Status != HttpStatusCode.OK) return (-1, [], $"The resolver returned HTTP {(int)reply.Status}.");

            using var json = JsonDocument.Parse(reply.Body, SafeText.JsonOptions);
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object || SafeText.Integer(root, "Status") is not { } status) return (-1, [], "The resolver sent an answer Blazma could not read.");
            if (status is not (0 or 3)) return ((int)status, [], $"The resolver returned DNS error {status.ToString(CultureInfo.InvariantCulture)}.");

            var wanted = type == "A" ? 1 : 28;
            var family = type == "A" ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
            var list = new List<string>();
            if (SafeText.Array(root, "Answer") is { } answers)
            {
                foreach (var answer in answers.EnumerateArray().Take(64))
                {
                    if (answer.ValueKind != JsonValueKind.Object || SafeText.Integer(answer, "type") != wanted) continue; // CNAME and others
                    if (SafeText.String(answer, "data") is { Length: <= 64 } data && IPAddress.TryParse(data, out var ip) && ip.AddressFamily == family)
                        list.Add(ip.ToString());
                }
            }
            return ((int)status, list, null);
        }
        catch (OperationCanceledException) when (caller.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return (-1, [], "Not looked up: the time allowed for these lookups ran out.");
        }
        catch (TimeoutException)
        {
            return (-1, [], "The resolver did not answer in time.");
        }
        catch (ResponseTooLargeException)
        {
            return (-1, [], "The resolver's answer was larger than allowed.");
        }
        catch (JsonException)
        {
            return (-1, [], "The resolver sent an answer Blazma could not read.");
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            return (-1, [], "The resolver could not be reached.");
        }
    }

    private HostResolution Failed(string name, string error) => new()
    {
        Domain = name,
        Status = HostResolutionStatus.Failed,
        Resolver = _options.Endpoint.IdnHost,
        ResolvedAt = _time.GetUtcNow(),
        Error = error,
    };

    [GeneratedRegex(@"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex HostName();
}
