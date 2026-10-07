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
                map._ipToDomain.TryAdd(part.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase) ? part[7..] : part, domain);
        }
        return map;
    }

    public string? DomainFor(string? ip) => ip is not null && _ipToDomain.TryGetValue(ip, out var d) ? d : null;

    public static string Endpoint(AnalysisEvent e)
    {
        var ip = e.Detail(DetailKeys.RemoteAddress) ?? e.Target ?? "?";
        var port = e.Detail(DetailKeys.RemotePort);
        return port is null ? ip : ip.Contains(':') ? $"[{ip}]:{port}" : $"{ip}:{port}";
    }

    public static bool IsExternal(AnalysisEvent e) => PathRules.IsExternalAddress(e.Detail(DetailKeys.RemoteAddress) ?? e.Target);
}
