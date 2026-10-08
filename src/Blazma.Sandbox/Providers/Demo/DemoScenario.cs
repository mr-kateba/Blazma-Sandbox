using Blazma.Core.Events;
using Blazma.Core.Snapshots;

namespace Blazma.Sandbox.Providers.Demo;

/// <summary>
/// Synthetic, harmless analysis data. No file is executed: these events are written by
/// hand to look like a realistic run so the whole product (timeline, process tree,
/// persistence, network, scoring, reports) can be explored and developed without
/// samples. Every analysis that uses it is labelled DEMO.
/// </summary>
public sealed class DemoScenario
{
    public required string Name { get; init; }
    public required IReadOnlyList<AnalysisEvent> Events { get; init; }
    public required SystemSnapshot Baseline { get; init; }
    public required SystemSnapshot After { get; init; }

    internal const string User = @"C:\Users\WDAGUtilityAccount";

    public static DemoScenario For(string sampleFileName, DateTimeOffset start, int backgroundNoise = 40)
    {
        var lower = sampleFileName.ToLowerInvariant();
        if (lower.Contains("stress", StringComparison.Ordinal)) return Stress(sampleFileName, start, 100_000);
        if (lower.Contains("tool", StringComparison.Ordinal) || lower.Contains("calc", StringComparison.Ordinal) || lower.Contains("viewer", StringComparison.Ordinal))
            return QuietTool(sampleFileName, start, backgroundNoise);
        return PersistentUpdater(sampleFileName, start, backgroundNoise);
    }

    /// <summary>An installer that drops an updater, which makes itself persistent and phones home.</summary>
    public static DemoScenario PersistentUpdater(string sampleName, DateTimeOffset start, int backgroundNoise = 40)
    {
        var b = new Builder(start);
        var sample = b.Start(5120, 4412, sampleName, $@"{User}\Desktop\{sampleName}", $"\"{User}\\Desktop\\{sampleName}\"", 0, isSample: true, parentName: "explorer.exe");
        b.At(120).File(sample, EventAction.FileCreate, $@"{User}\AppData\Local\Temp\setup_4f1a\install.log");
        b.At(300).Registry(sample, EventAction.RegistryKeyCreate, @"HKCU\Software\ContosoUpdate", null, null);
        b.At(310).Registry(sample, EventAction.RegistryValueSet, @"HKCU\Software\ContosoUpdate", "InstallId", "7d2c-11ef");
        b.At(840).File(sample, EventAction.FileCreate, $@"{User}\AppData\Roaming\ContosoUpdate\updater.exe", sha256: "9b2c4ad54b1e5f0e8a6b9d3f71c0e2a4b8d6f1a3c5e7092b4d6f8a1c3e5b7d90", size: "1843200");
        b.At(860).File(sample, EventAction.FileWrite, $@"{User}\AppData\Roaming\ContosoUpdate\updater.exe");
        b.At(900).File(sample, EventAction.FileCreate, $@"{User}\AppData\Roaming\ContosoUpdate\config.dat", size: "2048");
        var updater = b.At(1210).Start(6044, 5120, "updater.exe", $@"{User}\AppData\Roaming\ContosoUpdate\updater.exe", $"\"{User}\\AppData\\Roaming\\ContosoUpdate\\updater.exe\" /silent", 1210);
        b.At(1704).Registry(updater, EventAction.RegistryValueSet, @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "ContosoUpdater", $"\"{User}\\AppData\\Roaming\\ContosoUpdate\\updater.exe\" /background");
        var ps = b.At(2130).Start(6312, 6044, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", 2130);
        var cmd = b.At(2480).Start(6400, 6312, "cmd.exe", @"C:\Windows\System32\cmd.exe",
            $"cmd.exe /c schtasks /create /tn \"ContosoUpdateTask\" /tr \"{User}\\AppData\\Roaming\\ContosoUpdate\\updater.exe /check\" /sc hourly /f", 2480);
        var schtasks = b.At(2520).Start(6428, 6400, "schtasks.exe", @"C:\Windows\System32\schtasks.exe",
            $"schtasks /create /tn \"ContosoUpdateTask\" /tr \"{User}\\AppData\\Roaming\\ContosoUpdate\\updater.exe /check\" /sc hourly /f", 2520);
        b.At(2610).Task(schtasks, "ContosoUpdateTask", $"{User}\\AppData\\Roaming\\ContosoUpdate\\updater.exe /check");
        b.At(2615).File(schtasks, EventAction.FileCreate, @"C:\Windows\System32\Tasks\ContosoUpdateTask");
        b.At(2700).Exit(schtasks, 0);
        b.At(2720).Exit(cmd, 0);
        b.At(3020).Dns(ps, "api.contoso-update.example", "203.0.113.24");
        b.At(3400).Connect(ps, "203.0.113.24", 443);
        b.At(3900).Dns(updater, "cdn.contoso-update.example", "198.51.100.7");
        b.At(4100).Connect(updater, "198.51.100.7", 443);
        b.At(4150).Connect(updater, "198.51.100.7", 4443);
        b.At(3450).Http(ps, "api.contoso-update.example", "POST", "/v2/register?id=7d2c-11ef", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ContosoUpdate/2.1", "host=DESKTOP-DEMO&user=demo&av=Defender");
        b.At(4120).Tls(updater, "cdn.contoso-update.example");
        b.At(4300).Note("Simulated user pressed \"next\"");
        b.At(4600).Exit(ps, 0);
        b.At(5200).File(updater, EventAction.FileWrite, $@"{User}\AppData\Roaming\ContosoUpdate\config.dat");
        b.At(6100).Registry(updater, EventAction.RegistryValueSet, @"HKCU\Software\ContosoUpdate", "LastCheck", "2026-10-07T10:00:00Z");
        b.At(7200).Exit(sample, 0);
        b.At(9000).Dns(updater, "telemetry.contoso-update.example", null);

        b.Background(backgroundNoise, 60_000);

        var baseline = BaseSnapshot(start);
        var after = baseline with
        {
            TakenAt = start.AddSeconds(60),
            Files =
            [
                .. baseline.Files,
                new FileEntry($@"{User}\AppData\Roaming\ContosoUpdate\updater.exe", 1843200, start.AddSeconds(1)),
                new FileEntry($@"{User}\AppData\Roaming\ContosoUpdate\config.dat", 2048, start.AddSeconds(5)),
                new FileEntry($@"{User}\AppData\Local\Temp\setup_4f1a\install.log", 512, start),
                new FileEntry(@"C:\Windows\System32\Tasks\ContosoUpdateTask", 3900, start.AddSeconds(2)),
            ],
            Registry =
            [
                .. baseline.Registry,
                new RegistryEntry(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "ContosoUpdater", $"\"{User}\\AppData\\Roaming\\ContosoUpdate\\updater.exe\" /background"),
                new RegistryEntry(@"HKCU\Software\ContosoUpdate", "InstallId", "7d2c-11ef"),
                new RegistryEntry(@"HKCU\Software\ContosoUpdate", "LastCheck", "2026-10-07T10:00:00Z"),
            ],
            ScheduledTasks = [.. baseline.ScheduledTasks, @"\ContosoUpdateTask"],
            StartupItems = [.. baseline.StartupItems, "ContosoUpdater"],
        };

        return new DemoScenario { Name = "persistent-updater", Events = b.Events, Baseline = baseline, After = after };
    }

    /// <summary>A portable tool that opens, writes a settings file and exits. Low risk.</summary>
    public static DemoScenario QuietTool(string sampleName, DateTimeOffset start, int backgroundNoise = 40)
    {
        var b = new Builder(start);
        var sample = b.Start(4800, 4412, sampleName, $@"{User}\Downloads\{sampleName}", $"\"{User}\\Downloads\\{sampleName}\"", 0, isSample: true, parentName: "explorer.exe");
        b.At(400).Registry(sample, EventAction.RegistryKeyCreate, @"HKCU\Software\FabrikamTools\Viewer", null, null);
        b.At(410).Registry(sample, EventAction.RegistryValueSet, @"HKCU\Software\FabrikamTools\Viewer", "WindowPlacement", "0,0,1024,768");
        b.At(800).File(sample, EventAction.FileCreate, $@"{User}\AppData\Roaming\FabrikamTools\viewer.ini", size: "312");
        b.At(1500).Dns(sample, "updates.fabrikam.example", null);
        b.At(8000).Exit(sample, 0);
        b.Background(backgroundNoise, 30_000);

        var baseline = BaseSnapshot(start);
        var after = baseline with
        {
            TakenAt = start.AddSeconds(30),
            Files = [.. baseline.Files, new FileEntry($@"{User}\AppData\Roaming\FabrikamTools\viewer.ini", 312, start.AddSeconds(1))],
            Registry = [.. baseline.Registry, new RegistryEntry(@"HKCU\Software\FabrikamTools\Viewer", "WindowPlacement", "0,0,1024,768")],
        };
        return new DemoScenario { Name = "quiet-tool", Events = b.Events, Baseline = baseline, After = after };
    }

    /// <summary>A large synthetic run for performance testing of storage and virtualised views.</summary>
    public static DemoScenario Stress(string sampleName, DateTimeOffset start, int count)
    {
        var b = new Builder(start);
        var sample = b.Start(7000, 4412, sampleName, $@"{User}\Desktop\{sampleName}", sampleName, 0, isSample: true, parentName: "explorer.exe");
        for (var i = 0; i < count; i++)
        {
            b.At(i);
            switch (i % 4)
            {
                case 0: b.File(sample, EventAction.FileWrite, $@"{User}\AppData\Local\Temp\stress\file{i % 5000}.tmp"); break;
                case 1: b.Registry(sample, EventAction.RegistryValueSet, @"HKCU\Software\StressTest", $"Value{i % 1000}", i.ToString(System.Globalization.CultureInfo.InvariantCulture)); break;
                case 2: b.File(sample, EventAction.FileCreate, $@"{User}\AppData\Local\Temp\stress\new{i}.dat"); break;
                default: b.Dns(sample, $"host{i % 200}.stress.example", null); break;
            }
        }
        var baseline = BaseSnapshot(start);
        return new DemoScenario { Name = "stress", Events = b.Events, Baseline = baseline, After = baseline };
    }

    private static SystemSnapshot BaseSnapshot(DateTimeOffset start) => new()
    {
        TakenAt = start.AddSeconds(-2),
        Files =
        [
            new FileEntry($@"{User}\Desktop\readme.txt", 120, start.AddDays(-1)),
            new FileEntry($@"{User}\AppData\Local\Microsoft\Windows\UsrClass.dat", 262144, start.AddMinutes(-5)),
        ],
        Registry =
        [
            new RegistryEntry(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "OneDriveSetup", @"C:\Windows\SysWOW64\OneDriveSetup.exe /thfirstsetup"),
        ],
        Services = ["Dnscache", "EventLog", "Schedule", "WinDefend"],
        ScheduledTasks = [@"\Microsoft\Windows\Defrag\ScheduledDefrag"],
        StartupItems = ["OneDriveSetup"],
    };

    private sealed class Builder(DateTimeOffset start)
    {
        private long _seq;
        private TimeSpan _at;
        public List<AnalysisEvent> Events { get; } = [];

        public Builder At(int ms) { _at = TimeSpan.FromMilliseconds(ms); return this; }

        public (int Pid, ProcessKey Key, string Name) Start(int pid, int ppid, string name, string image, string cmd, int startMs, bool isSample = false, string? parentName = null)
        {
            var key = new ProcessKey(pid, TimeSpan.FromMilliseconds(startMs).Ticks);
            var details = new Dictionary<string, string>
            {
                [DetailKeys.ImagePath] = image,
                [DetailKeys.CommandLine] = cmd,
                [DetailKeys.User] = @"WDAGUtilityAccount",
                [DetailKeys.IntegrityLevel] = isSample ? "Medium" : "Medium",
                [DetailKeys.Architecture] = "x64",
            };
            if (isSample) details[DetailKeys.IsSample] = "true";
            Add(EventAction.ProcessStart, pid, ppid, key, name, image, details, isSample ? Severity.Informational : Severity.Low);
            return (pid, key, name);
        }

        public void Exit((int Pid, ProcessKey Key, string Name) p, int code) =>
            Add(EventAction.ProcessExit, p.Pid, 0, p.Key, p.Name, null, new Dictionary<string, string> { [DetailKeys.ExitCode] = code.ToString(System.Globalization.CultureInfo.InvariantCulture) });

        public void File((int Pid, ProcessKey Key, string Name) p, EventAction action, string path, string? sha256 = null, string? size = null)
        {
            var d = new Dictionary<string, string>();
            if (sha256 is not null) d[DetailKeys.Sha256] = sha256;
            if (size is not null) d[DetailKeys.Size] = size;
            Add(action, p.Pid, 0, p.Key, p.Name, path, d);
        }

        public void Registry((int Pid, ProcessKey Key, string Name) p, EventAction action, string key, string? valueName, string? data)
        {
            var d = new Dictionary<string, string>();
            if (valueName is not null) d[DetailKeys.ValueName] = valueName;
            if (data is not null) d[DetailKeys.ValueData] = data;
            Add(action, p.Pid, 0, p.Key, p.Name, key, d);
        }

        public void Task((int Pid, ProcessKey Key, string Name) p, string name, string command) =>
            Add(EventAction.ScheduledTaskCreate, p.Pid, 0, p.Key, p.Name, @"\" + name,
                new Dictionary<string, string> { [DetailKeys.TaskName] = name, [DetailKeys.CommandLine] = command });

        public void Dns((int Pid, ProcessKey Key, string Name) p, string domain, string? answer)
        {
            var d = new Dictionary<string, string> { [DetailKeys.QueryName] = domain };
            if (answer is not null) d[DetailKeys.QueryResult] = answer;
            Add(EventAction.DnsQuery, p.Pid, 0, p.Key, p.Name, domain, d);
        }

        /// <summary>A request answered by the simulated internet.</summary>
        public void Http((int Pid, ProcessKey Key, string Name) p, string host, string method, string path, string userAgent, string? body = null)
        {
            var d = new Dictionary<string, string>
            {
                [DetailKeys.HttpMethod] = method,
                [DetailKeys.HttpPath] = path,
                [DetailKeys.HttpHost] = host,
                [DetailKeys.UserAgent] = userAgent,
                [DetailKeys.Protocol] = "http",
                [DetailKeys.RemoteAddress] = "127.0.0.1",
                [DetailKeys.RemotePort] = "80",
                [DetailKeys.Simulated] = "true",
            };
            if (body is not null) d[DetailKeys.BodyPreview] = body;
            Add(EventAction.HttpRequest, p.Pid, 0, p.Key, p.Name, $"http://{host}{path}", d);
        }

        public void Tls((int Pid, ProcessKey Key, string Name) p, string serverName) =>
            Add(EventAction.TlsHandshake, p.Pid, 0, p.Key, p.Name, serverName, new Dictionary<string, string>
            {
                [DetailKeys.ServerName] = serverName,
                [DetailKeys.RemoteAddress] = "127.0.0.1",
                [DetailKeys.RemotePort] = "443",
                [DetailKeys.Simulated] = "true",
            });

        public void Note(string text) =>
            Add(EventAction.AnalysisNote, 0, 0, new ProcessKey(0, 0), "blazma-agent", null, new Dictionary<string, string> { [DetailKeys.Reason] = text });

        public void Connect((int Pid, ProcessKey Key, string Name) p, string ip, int port) =>
            Add(EventAction.NetworkConnect, p.Pid, 0, p.Key, p.Name, ip, new Dictionary<string, string>
            {
                [DetailKeys.RemoteAddress] = ip,
                [DetailKeys.RemotePort] = port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                [DetailKeys.Protocol] = "TCP",
            });

        /// <summary>Activity from Windows itself, outside the sample's tree. Blazma should filter it as noise.</summary>
        public void Background(int count, int spanMs)
        {
            var services = new[] { ("svchost.exe", 1204), ("SearchIndexer.exe", 2210), ("MsMpEng.exe", 3100), ("WmiPrvSE.exe", 3880) };
            var saved = _at;
            for (var i = 0; i < count; i++)
            {
                var (name, pid) = services[i % services.Length];
                var key = new ProcessKey(pid, -TimeSpan.FromMinutes(5).Ticks);
                _at = TimeSpan.FromMilliseconds(i * (double)spanMs / Math.Max(1, count));
                if (i % 3 == 0)
                    Add(EventAction.FileWrite, pid, 0, key, name, $@"C:\ProgramData\Microsoft\Search\Data\Applications\Windows\tmp{i}.edb", new Dictionary<string, string>());
                else if (i % 3 == 1)
                    Add(EventAction.RegistryValueSet, pid, 0, key, name, @"HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates", new Dictionary<string, string> { [DetailKeys.ValueName] = "LastCheck", [DetailKeys.ValueData] = i.ToString(System.Globalization.CultureInfo.InvariantCulture) });
                else
                    Add(EventAction.DnsQuery, pid, 0, key, name, "settings-win.data.microsoft.com", new Dictionary<string, string> { [DetailKeys.QueryName] = "settings-win.data.microsoft.com" });
            }
            _at = saved;
            Events.Sort((a, b) => a.RelativeTime != b.RelativeTime ? a.RelativeTime.CompareTo(b.RelativeTime) : a.Sequence.CompareTo(b.Sequence));
            for (var i = 0; i < Events.Count; i++) Events[i] = Events[i] with { Sequence = i + 1 };
        }

        private void Add(EventAction action, int pid, int ppid, ProcessKey key, string name, string? target, Dictionary<string, string> details, Severity severity = Severity.Informational) =>
            Events.Add(new AnalysisEvent
            {
                Sequence = ++_seq,
                Timestamp = start + _at,
                RelativeTime = _at,
                Category = action.DefaultCategory(),
                Action = action,
                ProcessId = pid,
                ParentProcessId = ppid,
                Process = key,
                ProcessName = name,
                Target = target,
                Details = details,
                Severity = severity,
                Source = "demo",
            });
    }
}
