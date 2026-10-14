using System.Net;
using Blazma.Analysis.Text;
using Blazma.Core.Events;

namespace Blazma.Analysis.Engine;

/// <summary>Links IP addresses back to the domain names that resolved to them.</summary>
public sealed class NetworkMap
{
    private readonly Dictionary<string, string> _ipToDomain = new(StringComparer.OrdinalIgnoreCase);

    public static NetworkMap Build(IEnumerable<AnalysisEvent> events)
    {
        var map = new NetworkMap();
        foreach (var e in events.Where(e => e.Action == EventAction.DnsQuery))
        {
            var domain = e.Detail(DetailKeys.QueryName) ?? e.Target;
            var answer = e.Detail(DetailKeys.QueryResult);
            if (string.IsNullOrEmpty(domain) || string.IsNullOrEmpty(answer)) continue;
            foreach (var part in answer.Split([';', ',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                // The simulated internet's hosts file answers 127.0.0.1 for every name: that links nothing.
                if (Normalize(part) is { } ip && !IPAddress.IsLoopback(IPAddress.Parse(ip))) map._ipToDomain.TryAdd(ip, domain);
            }
        }
        return map;
    }

    public string? DomainFor(string? ip) => Normalize(ip) is { } key && _ipToDomain.TryGetValue(key, out var d) ? d : null;

    /// <summary>The canonical text of an address ("::ffff:1.2.3.4" becomes "1.2.3.4"), or null when it is not an IP address.</summary>
    public static string? Normalize(string? address)
    {
        if (string.IsNullOrWhiteSpace(address) || !IPAddress.TryParse(address.Trim(), out var ip)) return null;
        return (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
    }

    public static string Endpoint(AnalysisEvent e)
    {
        var ip = e.Detail(DetailKeys.RemoteAddress) ?? e.Target ?? "?";
        var port = e.Detail(DetailKeys.RemotePort);
        return port is null ? ip : ip.Contains(':') ? $"[{ip}]:{port}" : $"{ip}:{port}";
    }

    public static bool IsExternal(AnalysisEvent e) => PathRules.IsExternalAddress(e.Detail(DetailKeys.RemoteAddress) ?? e.Target);
}
