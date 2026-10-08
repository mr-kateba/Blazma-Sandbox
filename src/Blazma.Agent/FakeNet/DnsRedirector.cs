using System.Collections.Concurrent;
using System.Runtime.Versioning;
using Microsoft.Win32;
using static Blazma.Agent.Native.NativeMethods;

namespace Blazma.Agent.FakeNet;

/// <summary>
/// Sends every name the sample looks up to the simulated internet. Lookups are seen through
/// ETW; each new name is written to the hosts file and the resolver cache is flushed, so the
/// program's next attempt resolves to 127.0.0.1. Negative caching is turned off first so a
/// failed first attempt is not remembered.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class DnsRedirector(string hostsPath, Action<string> note) : IDisposable
{
    private readonly ConcurrentQueue<string> _pending = new();
    private readonly ConcurrentDictionary<string, byte> _seen = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _timer;

    public int Redirected => _seen.Count;

    public void Start()
    {
        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters");
            key.SetValue("MaxNegativeCacheTtl", 0, RegistryValueKind.DWord);
            key.SetValue("NegativeCacheTime", 0, RegistryValueKind.DWord);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            note("Could not disable negative DNS caching; the simulated internet may answer a little later.");
        }
        DnsFlushResolverCache();
        _timer = new Timer(_ => Apply(), null, TimeSpan.FromMilliseconds(300), TimeSpan.FromMilliseconds(300));
    }

    /// <summary>Called for every observed DNS lookup (any process; the hosts file is shared anyway).</summary>
    public void OnLookup(string name)
    {
        if (_seen.Count < HostsFile.MaxEntries && HostsFile.IsValidHostName(name) && _seen.TryAdd(name.TrimEnd('.'), 0)) _pending.Enqueue(name.TrimEnd('.'));
    }

    private void Apply()
    {
        var batch = new List<string>();
        while (batch.Count < 100 && _pending.TryDequeue(out var n)) batch.Add(n);
        if (batch.Count == 0) return;
        try
        {
            if (HostsFile.Add(hostsPath, batch) > 0) DnsFlushResolverCache();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            note("Could not update the hosts file for the simulated internet.");
        }
    }

    public void Dispose() => _timer?.Dispose();
}
