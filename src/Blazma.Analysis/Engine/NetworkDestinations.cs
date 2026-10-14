using System.Globalization;
using System.Net;
using Blazma.Analysis.Text;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Text;

namespace Blazma.Analysis.Engine;

/// <summary>
/// Folds the network events of the analyzed programs into one row per destination: every
/// address and name they tried to reach, whether it worked, was answered by the simulated
/// internet, failed, or was only looked up. Deterministic: same events, same rows.
/// </summary>
public static class NetworkDestinations
{
    public const int MaxRows = 500;
    private const int MaxSequences = 50;
    private const int MaxProcesses = 5;
    private static readonly TimeSpan LookupWindow = TimeSpan.FromSeconds(30);

    public static IReadOnlyList<NetworkDestination> Build(IReadOnlyList<AnalysisEvent> events, ProcessGraph graph, NetworkMap map)
    {
        // Without an identified sample there is no tree to scope to; every event counts (as in the noise filter).
        var scoped = graph.Sample is null ? events : events.Where(graph.InAnalyzedTree).ToList();
        return Build(scoped, map);
    }

    /// <summary>Builds the rows from events already scoped to the analyzed programs.</summary>
    public static IReadOnlyList<NetworkDestination> Build(IReadOnlyList<AnalysisEvent> events, NetworkMap map)
    {
        var simulatedPorts = events.Where(IsSimulated).Select(e => Port(e)).OfType<int>().ToHashSet();
        var lookups = events.Where(e => e.Action == EventAction.DnsQuery).ToList();
        var rows = new Dictionary<(string Key, int? Port, string Protocol), Row>(KeyComparer.Instance);

        Row RowFor(string key, int? port, string protocol, AnalysisEvent e)
        {
            if (!rows.TryGetValue((key, port, protocol), out var row)) rows[(key, port, protocol)] = row = new Row(e.RelativeTime);
            row.Add(e);
            return row;
        }

        foreach (var e in events)
        {
            if (IsSimulated(e))
            {
                var (domain, address, source) = SimulatedName(e, lookups);
                var row = RowFor(domain ?? address ?? "127.0.0.1", Port(e), "TCP", e);
                row.Simulated = true;
                row.Domain ??= domain;
                row.DomainSource ??= source;
                row.Address ??= address;
                switch (e.Action)
                {
                    case EventAction.TlsHandshake:
                        row.Tls = true;
                        row.SimulatedConnections++;
                        break;
                    case EventAction.HttpRequest:
                        var https = string.Equals(e.Detail(DetailKeys.Protocol), "https", StringComparison.OrdinalIgnoreCase);
                        if (https) row.Https = true;
                        else
                        {
                            row.Http = true;
                            row.SimulatedConnections++; // an HTTPS request was already counted by its TLS handshake
                        }
                        row.BytesSent += Number(e, DetailKeys.BytesSent);
                        break;
                    default:
                        row.SimulatedConnections++;
                        row.BytesSent += Number(e, DetailKeys.BytesReceived); // what the simulated server received is what the program sent
                        break;
                }
                continue;
            }

            if (e.Action is not (EventAction.NetworkConnect or EventAction.NetworkSend)) continue;
            if (NetworkMap.Normalize(e.Detail(DetailKeys.RemoteAddress) ?? e.Target) is not { } ip) continue;
            var port = Port(e);
            // The program's own connection to the simulated internet: already listed under the name it asked for.
            if (IPAddress.IsLoopback(IPAddress.Parse(ip)) && port is { } p && simulatedPorts.Contains(p)) continue;

            var protocol = (e.Detail(DetailKeys.Protocol) ?? string.Empty).ToUpperInvariant() is "UDP" ? "UDP" : "TCP";
            if (e.Action == EventAction.NetworkSend && e.Detail(DetailKeys.Protocol) is null && rows.ContainsKey((ip, port, "UDP")) && !rows.ContainsKey((ip, port, "TCP")))
                protocol = "UDP"; // byte totals do not name the protocol
            var r = RowFor(ip, port, protocol, e);
            r.Address = ip;
            if (e.Action == EventAction.NetworkSend)
            {
                var sent = Number(e, DetailKeys.BytesSent);
                var received = Number(e, DetailKeys.BytesReceived);
                r.BytesSent += sent;
                r.BytesReceived += received;
                if (sent + received > 0) r.Traffic = true; // data went both ways or out: it worked, but a total is not one more connection
                continue;
            }
            if (e.Detail(DetailKeys.ErrorCode) is { Length: > 0 } code) r.ErrorCode = code;
            var attempts = (int)Math.Min(int.MaxValue, Number(e, DetailKeys.Attempts));
            if (attempts > 0)
            {
                // The agent's end-of-run total for a destination it tried more than once.
                r.Attempts = Math.Max(r.Attempts, attempts);
                if (e.Detail(DetailKeys.Status) == ConnectStatus.Failed) r.Failed++;
                continue;
            }
            switch (e.Detail(DetailKeys.Status))
            {
                case ConnectStatus.Failed: r.Failed++; break;
                case ConnectStatus.Attempted: r.Attempted++; break;
                default: r.Connected++; break; // older agents only reported connections that succeeded
            }
        }

        var list = new List<NetworkDestination>();
        foreach (var ((key, port, protocol), row) in rows)
        {
            var domain = row.Domain ?? map.DomainFor(row.Address);
            var external = row.Address is { } a ? PathRules.IsExternalAddress(a) : domain is not null;
            list.Add(new NetworkDestination
            {
                Address = row.Address,
                Port = port,
                Protocol = row.Simulated ? row.Https ? "HTTPS" : row.Tls ? "TLS" : row.Http ? "HTTP" : protocol : protocol,
                Domain = domain,
                DomainSource = row.Domain is not null ? row.DomainSource : domain is not null ? "dns" : null,
                Processes = row.Processes,
                Status = row.Connected > 0 || row.Traffic ? DestinationStatus.Connected
                    : row.Simulated ? DestinationStatus.Simulated
                    : row.Failed > 0 ? DestinationStatus.Failed
                    : DestinationStatus.Attempted,
                ErrorCode = row.Connected > 0 || row.Traffic || row.Simulated ? null : row.ErrorCode,
                Count = Math.Max(1, new[] { row.Attempts, row.Connected, row.Attempted, row.SimulatedConnections, row.Attempted == 0 ? row.Failed : 0 }.Max()),
                FirstSeen = row.First,
                BytesSent = row.BytesSent,
                BytesReceived = row.BytesReceived,
                External = external,
                DirectIp = external && row.Address is not null && domain is null && !row.Simulated,
                EventSequences = row.Sequences,
            });
        }

        // Names that were looked up but never reached: with networking off this is often all there is.
        var reached = list.Where(d => d.Domain is not null).Select(d => d.Domain!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var g in lookups.GroupBy(e => (e.Detail(DetailKeys.QueryName) ?? e.Target ?? string.Empty).TrimEnd('.'), StringComparer.OrdinalIgnoreCase))
        {
            if (g.Key.Length == 0 || reached.Contains(g.Key) || IPAddress.TryParse(g.Key, out _)) continue;
            var row = new Row(g.First().RelativeTime);
            foreach (var e in g) row.Add(e);
            list.Add(new NetworkDestination
            {
                Protocol = "DNS",
                Domain = g.Key,
                DomainSource = "lookup",
                Processes = row.Processes,
                Status = DestinationStatus.LookupOnly,
                Count = g.Count(),
                FirstSeen = row.First,
                External = !g.Key.EndsWith(".local", StringComparison.OrdinalIgnoreCase) && g.Key.Contains('.', StringComparison.Ordinal),
                EventSequences = row.Sequences,
            });
        }

        return list.OrderBy(d => d.FirstSeen).ThenBy(d => d.Endpoint, StringComparer.OrdinalIgnoreCase).Take(MaxRows).ToList();
    }

    /// <summary>Domains worth looking up from the host afterwards: names the programs contacted or looked up, never IP addresses.</summary>
    public static IReadOnlyList<string> ContactedDomains(IEnumerable<NetworkDestination> destinations) =>
        destinations.Where(d => d.Domain is { Length: > 0 } && d.External).Select(d => d.Domain!.TrimEnd('.').ToLowerInvariant())
            .Where(n => !IPAddress.TryParse(n, out _)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>Why an attempt failed, in words, from the Windows status code the agent recorded.</summary>
    public static LocalizedText DescribeError(string? errorCode)
    {
        if (string.IsNullOrEmpty(errorCode)) return new("No answer was seen", "لم يُرصد أي رد");
        var hex = errorCode.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? errorCode[2..] : errorCode;
        if (!uint.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var status)) return LocalizedText.Same(errorCode);
        return status switch
        {
            0xC000023C or 0xC000023D or 0xC000023E or 0xC00000C4 =>
                new($"No network: the sandbox has no route to it ({errorCode})", $"لا توجد شبكة: لا طريق إليه من البيئة المعزولة ({errorCode})"),
            0xC0000236 or 0xC000023F => new($"Refused ({errorCode})", $"رُفض الاتصال ({errorCode})"),
            0xC00000B5 => new($"Timed out ({errorCode})", $"انتهت المهلة ({errorCode})"),
            0xC0000022 or (>= 0xC0220000 and <= 0xC022FFFF) => new($"Blocked by the firewall ({errorCode})", $"حظره جدار الحماية ({errorCode})"),
            0xC0000120 or 0xC0000240 or 0xC0000241 or 0xC000020C => new($"Cancelled or reset ({errorCode})", $"أُلغي أو قُطع ({errorCode})"),
            _ => new($"Failed ({errorCode})", $"فشل ({errorCode})"),
        };
    }

    private static bool IsSimulated(AnalysisEvent e) =>
        e.Action is EventAction.HttpRequest or EventAction.TlsHandshake or EventAction.NetworkSend
        && string.Equals(e.Detail(DetailKeys.Simulated), "true", StringComparison.OrdinalIgnoreCase);

    /// <summary>The domain a simulated HTTP request or TLS connection named (Host header or server name); null for an IP literal.</summary>
    public static string? ContactedName(AnalysisEvent e)
    {
        var host = e.Detail(DetailKeys.HttpHost) is { Length: > 0 } h ? StripPort(h) : e.Detail(DetailKeys.ServerName);
        if (string.IsNullOrWhiteSpace(host)) return null;
        host = host.Trim().TrimEnd('.').ToLowerInvariant();
        return NetworkMap.Normalize(host) is null && host.Contains('.', StringComparison.Ordinal) ? host : null;
    }

    /// <summary>
    /// The name a simulated connection was made to: the HTTP Host header or the TLS server name. A raw
    /// connection carries neither; the program's own lookup just before it names it.
    /// </summary>
    private static (string? Domain, string? Address, string? Source) SimulatedName(AnalysisEvent e, List<AnalysisEvent> lookups)
    {
        var (host, source) = e.Detail(DetailKeys.HttpHost) is { Length: > 0 } h ? (StripPort(h), "http-host")
            : e.Detail(DetailKeys.ServerName) is { Length: > 0 } sni ? (sni, "tls-sni")
            : e.Action == EventAction.TlsHandshake && e.Target is { Length: > 0 } t && !IPAddress.TryParse(t, out _) ? (t, "tls-sni")
            : (null, null);
        if (host is not null)
        {
            host = host.TrimEnd('.').ToLowerInvariant();
            return NetworkMap.Normalize(host) is { } literal ? (null, literal, null) : (host, null, source);
        }
        var previous = lookups.LastOrDefault(q => q.ProcessId == e.ProcessId && q.RelativeTime <= e.RelativeTime && e.RelativeTime - q.RelativeTime <= LookupWindow);
        var name = previous?.Detail(DetailKeys.QueryName) ?? previous?.Target;
        return name is { Length: > 0 } ? (name.TrimEnd('.').ToLowerInvariant(), null, "lookup") : (null, null, null);
    }

    private static string StripPort(string host)
    {
        host = host.Trim();
        if (host.StartsWith('[')) return host.IndexOf(']', StringComparison.Ordinal) is var end and > 0 ? host[1..end] : host;
        var colon = host.LastIndexOf(':');
        return colon > 0 && host.IndexOf(':', StringComparison.Ordinal) == colon ? host[..colon] : host;
    }

    private static int? Port(AnalysisEvent e) =>
        int.TryParse(e.Detail(DetailKeys.RemotePort), NumberStyles.Integer, CultureInfo.InvariantCulture, out var p) && p is >= 0 and <= 65535 ? p : null;

    private static long Number(AnalysisEvent e, string key) =>
        long.TryParse(e.Detail(key), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) && n > 0 ? n : 0;

    private sealed class Row(TimeSpan first)
    {
        private readonly List<long> _sequences = [];
        private readonly List<string> _processes = [];

        public TimeSpan First { get; private set; } = first;
        public string? Address;
        public string? Domain;
        public string? DomainSource;
        public string? ErrorCode;
        public bool Simulated, Http, Https, Tls, Traffic;
        public int Connected, Attempted, Failed, Attempts, SimulatedConnections;
        public long BytesSent, BytesReceived;

        public IReadOnlyList<long> Sequences => _sequences;
        public IReadOnlyList<string> Processes => _processes;

        public void Add(AnalysisEvent e)
        {
            if (e.RelativeTime < First) First = e.RelativeTime;
            if (_sequences.Count < MaxSequences) _sequences.Add(e.Sequence);
            if (e.ProcessName.Length > 0 && _processes.Count < MaxProcesses && !_processes.Contains(e.ProcessName, StringComparer.OrdinalIgnoreCase)) _processes.Add(e.ProcessName);
        }
    }

    private sealed class KeyComparer : IEqualityComparer<(string Key, int? Port, string Protocol)>
    {
        public static readonly KeyComparer Instance = new();

        public bool Equals((string Key, int? Port, string Protocol) x, (string Key, int? Port, string Protocol) y) =>
            string.Equals(x.Key, y.Key, StringComparison.OrdinalIgnoreCase) && x.Port == y.Port && string.Equals(x.Protocol, y.Protocol, StringComparison.Ordinal);

        public int GetHashCode((string Key, int? Port, string Protocol) obj) =>
            HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Key), obj.Port, obj.Protocol);
    }
}
