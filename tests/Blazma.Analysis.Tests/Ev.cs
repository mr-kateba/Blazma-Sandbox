using Blazma.Core.Events;

namespace Blazma.Analysis.Tests;

/// <summary>Synthetic event builder. Tests never use real malware; everything is hand-made data.</summary>
internal sealed class Ev
{
    private long _seq;
    private readonly DateTimeOffset _start = new(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);
    public List<AnalysisEvent> Events { get; } = [];

    public ProcessKey Start(int ms, int pid, int ppid, string name, string? image = null, string? cmd = null, bool sample = false)
    {
        var key = new ProcessKey(pid, TimeSpan.FromMilliseconds(ms).Ticks);
        var d = new Dictionary<string, string> { [DetailKeys.ImagePath] = image ?? $@"C:\Windows\System32\{name}" };
        if (cmd is not null) d[DetailKeys.CommandLine] = cmd;
        if (sample) d[DetailKeys.IsSample] = "true";
        Add(ms, EventAction.ProcessStart, pid, ppid, key, name, image, d);
        return key;
    }

    public void Exit(int ms, int pid, ProcessKey key, string name) => Add(ms, EventAction.ProcessExit, pid, 0, key, name, null, []);

    public void File(int ms, int pid, ProcessKey? key, string name, EventAction action, string path) => Add(ms, action, pid, 0, key, name, path, []);

    public void Reg(int ms, int pid, ProcessKey? key, string name, string regKey, string value, string data) =>
        Add(ms, EventAction.RegistryValueSet, pid, 0, key, name, regKey, new() { [DetailKeys.ValueName] = value, [DetailKeys.ValueData] = data });

    public void Connect(int ms, int pid, ProcessKey? key, string name, string ip, int port) =>
        Add(ms, EventAction.NetworkConnect, pid, 0, key, name, ip, new() { [DetailKeys.RemoteAddress] = ip, [DetailKeys.RemotePort] = port.ToString(System.Globalization.CultureInfo.InvariantCulture) });

    public void Dns(int ms, int pid, ProcessKey? key, string name, string domain, string? answer = null)
    {
        var d = new Dictionary<string, string> { [DetailKeys.QueryName] = domain };
        if (answer is not null) d[DetailKeys.QueryResult] = answer;
        Add(ms, EventAction.DnsQuery, pid, 0, key, name, domain, d);
    }

    private void Add(int ms, EventAction action, int pid, int ppid, ProcessKey? key, string name, string? target, Dictionary<string, string> details) =>
        Events.Add(new AnalysisEvent
        {
            Sequence = ++_seq,
            Timestamp = _start.AddMilliseconds(ms),
            RelativeTime = TimeSpan.FromMilliseconds(ms),
            Category = action.DefaultCategory(),
            Action = action,
            ProcessId = pid,
            ParentProcessId = ppid,
            Process = key,
            ProcessName = name,
            Target = target,
            Details = details,
            Source = "test",
        });
}
