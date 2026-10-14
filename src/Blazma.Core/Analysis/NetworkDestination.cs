using System.Text.Json.Serialization;

namespace Blazma.Core.Analysis;

/// <summary>What happened when the analyzed programs tried to reach a destination. Always shown with a shape and a label, never colour alone.</summary>
public enum DestinationStatus
{
    /// <summary>A real connection was established (real network enabled).</summary>
    Connected,

    /// <summary>Answered by the simulated internet inside the sandbox; nothing left the sandbox.</summary>
    Simulated,

    /// <summary>Windows reported that the attempt failed: no network, no route, refused, timed out or blocked.</summary>
    Failed,

    /// <summary>The program asked to connect or send; no answer was seen.</summary>
    Attempted,

    /// <summary>The program looked the name up but no connection to it was seen (typically: the lookup failed with networking off).</summary>
    LookupOnly,
}

/// <summary>
/// One place the analyzed programs tried to reach, with every attempt folded into one row:
/// the address, port and protocol, the name it was known by, who tried, when first, how
/// often, how much data went each way and how it ended.
/// </summary>
public sealed record NetworkDestination
{
    /// <summary>The IP address. Null when only a name is known (simulated internet, lookup only).</summary>
    public string? Address { get; init; }

    public int? Port { get; init; }

    /// <summary>"TCP", "UDP", "HTTP", "HTTPS", "TLS" or "DNS".</summary>
    public string Protocol { get; init; } = "TCP";

    /// <summary>The domain name the address was reached by, when known.</summary>
    public string? Domain { get; init; }

    /// <summary>Where the name came from: "dns" (an answer seen in the sandbox), "http-host", "tls-sni" or "lookup".</summary>
    public string? DomainSource { get; init; }

    public IReadOnlyList<string> Processes { get; init; } = [];

    public DestinationStatus Status { get; init; }

    /// <summary>Windows status code of the last failure, as hexadecimal.</summary>
    public string? ErrorCode { get; init; }

    /// <summary>Connection attempts (retries included).</summary>
    public int Count { get; init; }

    public TimeSpan FirstSeen { get; init; }

    public long BytesSent { get; init; }
    public long BytesReceived { get; init; }

    /// <summary>The address is on the internet (not private, loopback or link-local).</summary>
    public bool External { get; init; }

    /// <summary>An external IP address the program used without any name lookup leading to it: typical of hard-coded servers.</summary>
    public bool DirectIp { get; init; }

    public IReadOnlyList<long> EventSequences { get; init; } = [];

    /// <summary>"203.0.113.5:443", "[2001:db8::1]:443", or the domain when there is no address.</summary>
    [JsonIgnore]
    public string Endpoint
    {
        get
        {
            var host = Address is null ? Domain ?? "?" : Address.Contains(':', StringComparison.Ordinal) ? $"[{Address}]" : Address;
            return Port is { } p ? $"{host}:{p}" : host;
        }
    }
}

public enum HostResolutionStatus { Resolved, NotFound, Failed }

/// <summary>
/// The current addresses of a domain the sample contacted, looked up from this computer
/// AFTER the analysis (opt-in, over DNS-over-HTTPS). The sample may have received
/// different addresses: these are context, never evidence of what it reached.
/// </summary>
public sealed record HostResolution
{
    public required string Domain { get; init; }
    public required HostResolutionStatus Status { get; init; }
    public IReadOnlyList<string> Addresses { get; init; } = [];

    /// <summary>The resolver's host name (e.g. "cloudflare-dns.com").</summary>
    public string Resolver { get; init; } = string.Empty;

    public DateTimeOffset ResolvedAt { get; init; }
    public string? Error { get; init; }
}
