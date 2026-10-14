using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.Versioning;
using Blazma.Contracts;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Win32;

namespace Blazma.Agent;

/// <summary>
/// Kernel and user-mode ETW collection inside the sandbox. Converts raw ETW records into
/// protocol events, drops the agent's own activity and de-duplicates noisy file writes.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class EtwMonitor(EventSink sink, SessionConfigDto config, string inDir, string outDir) : IDisposable
{
    private static readonly Guid DnsClient = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
    private static readonly Guid TaskScheduler = new("DE7B24EA-73C8-4A09-985D-5BDADCFA9017");

    /// <summary>
    /// A private kernel ("system logger") session, not the shared "NT Kernel Logger". On that name
    /// TraceEvent starts the session through its native KernelTraceControl.dll, which it looks for in
    /// an "amd64" folder next to its own DLL: there is no such folder in a single-file app (no assembly
    /// location) nor in the sandbox (the host copies only the agent folder's files). A private session
    /// (Windows 8 and later) is started with advapi32 alone, and does not stop another kernel logger.
    /// </summary>
    internal const string KernelSessionName = "BlazmaAgentKernel";
    internal const string UserSessionName = "BlazmaAgentUser";

    private readonly int _self = Environment.ProcessId;
    private readonly ConcurrentDictionary<int, (long StartMs, string Name)> _processes = new();
    private readonly ConcurrentDictionary<(int, string), long> _lastWrite = new();
    private readonly ConcurrentDictionary<(int, string, int), (long Sent, long Received, string Name)> _traffic = new();
    private readonly ConnectAttempts _attempts = new();
    private readonly ConcurrentDictionary<ulong, string> _socketProtocols = new();
    private readonly ConcurrentDictionary<ulong, (int Pid, string Address, int Port, string Protocol)> _pendingConnects = new();
    private TraceEventSession? _kernel;
    private TraceEventSession? _user;
    private Thread? _kernelThread;
    private Thread? _userThread;
    private volatile bool _sampleExpected;

    public ConcurrentDictionary<int, bool> Tree { get; } = new();

    /// <summary>Raised for every DNS lookup seen (any process): feeds the simulated internet.</summary>
    public event Action<string>? DnsLookup;

    /// <summary>
    /// Ports the simulated internet listens on. A loopback attempt to one of them is the sample
    /// reaching a name redirected by the hosts file: the simulated internet records it with the name.
    /// </summary>
    public Func<int, bool>? IsSimulatedPort { get; set; }

    /// <summary>Raised when a process of the analyzed tree creates, writes or renames a file.</summary>
    public event Action<string, int, string>? TreeFileWritten;

    public (long StartMs, string Name) ProcessInfo(int pid) => Info(pid, "?");

    public IReadOnlyList<(int Pid, string Name)> LiveTreeProcesses() =>
        Tree.Keys.Where(_processes.ContainsKey).Select(pid => (pid, _processes[pid].Name)).ToList();

    public void Start()
    {
        var keywords = KernelTraceEventParser.Keywords.Process;
        if (config.CaptureFiles) keywords |= KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.FileIO | KernelTraceEventParser.Keywords.DiskFileIO;
        if (config.CaptureRegistry) keywords |= KernelTraceEventParser.Keywords.Registry;
        if (config.CaptureNetwork) keywords |= KernelTraceEventParser.Keywords.NetworkTCPIP;

        try
        {
            _kernel = new TraceEventSession(KernelSessionName) { StopOnDispose = true };
            _kernel.EnableKernelProvider(keywords);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Windows kernel event tracing could not start: {ex.Message}", ex);
        }
        AgentLog.Info($"Kernel trace session {KernelSessionName} started ({keywords})");
        var k = _kernel.Source.Kernel;

        k.ProcessStart += Safe<ProcessTraceData>("ProcessStart", OnProcessStart);
        k.ProcessStop += Safe<ProcessTraceData>("ProcessStop", d =>
        {
            if (d.ProcessID == _self) return;
            var info = Info(d.ProcessID, d.ProcessName);
            sink.Add("ProcessExit", d.ProcessID, d.ParentID, info.StartMs, info.Name, null,
                new() { ["ExitCode"] = d.ExitStatus.ToString(CultureInfo.InvariantCulture) }, "etw.kernel.process");
            _processes.TryRemove(d.ProcessID, out _);
        });

        if (config.CaptureFiles)
        {
            k.FileIOCreate += Safe<FileIOCreateTraceData>("FileIOCreate", d =>
            {
                // Only dispositions that create or replace a file: supersede(0), create(2), overwrite(4), overwrite-if(5).
                var disposition = (int)d.CreateDisposition;
                if (disposition is not (0 or 2 or 4 or 5)) return;
                File("FileCreate", d.ProcessID, d.FileName, null);
            });
            k.FileIOWrite += Safe<FileIOReadWriteTraceData>("FileIOWrite", d =>
            {
                var key = (d.ProcessID, d.FileName ?? string.Empty);
                var now = sink.NowRelativeMs;
                if (_lastWrite.TryGetValue(key, out var last) && now - last < 2000) return;
                _lastWrite[key] = now;
                File("FileWrite", d.ProcessID, d.FileName, null);
            });
            k.FileIODelete += Safe<FileIOInfoTraceData>("FileIODelete", d => File("FileDelete", d.ProcessID, d.FileName, null));
            k.FileIORename += Safe<FileIOInfoTraceData>("FileIORename", d => File("FileRename", d.ProcessID, d.FileName, null));
        }

        if (config.CaptureRegistry)
        {
            k.RegistryCreate += Safe<RegistryTraceData>("RegistryCreate", d => Registry("RegistryKeyCreate", d));
            k.RegistrySetValue += Safe<RegistryTraceData>("RegistrySetValue", d => Registry("RegistryValueSet", d));
            k.RegistryDeleteValue += Safe<RegistryTraceData>("RegistryDeleteValue", d => Registry("RegistryValueDelete", d));
            k.RegistryDelete += Safe<RegistryTraceData>("RegistryDelete", d => Registry("RegistryKeyDelete", d));
        }

        if (config.CaptureNetwork)
        {
            k.TcpIpConnect += Safe<TcpIpConnectTraceData>("TcpIpConnect", d => Connect(d.ProcessID, d.daddr.ToString(), d.dport, "TCP"));
            k.TcpIpConnectIPV6 += Safe<TcpIpV6ConnectTraceData>("TcpIpConnectIPV6", d => Connect(d.ProcessID, d.daddr.ToString(), d.dport, "TCP"));
            k.TcpIpSend += Safe<TcpIpSendTraceData>("TcpIpSend", d => Count(d.ProcessID, d.daddr.ToString(), d.dport, d.size, sent: true));
            k.TcpIpRecv += Safe<TcpIpTraceData>("TcpIpRecv", d => Count(d.ProcessID, d.daddr.ToString(), d.dport, d.size, sent: false));
            k.UdpIpSend += Safe<UdpIpTraceData>("UdpIpSend", d =>
            {
                if (d.dport == 53) return; // DNS is reported by the DNS client provider with names
                if (_traffic.ContainsKey((d.ProcessID, d.daddr.ToString(), d.dport))) { Count(d.ProcessID, d.daddr.ToString(), d.dport, d.size, sent: true); return; }
                Connect(d.ProcessID, d.daddr.ToString(), d.dport, "UDP");
                Count(d.ProcessID, d.daddr.ToString(), d.dport, d.size, sent: true);
            });
        }

        var kernel = _kernel;
        _kernelThread = new Thread(() => Pump("kernel", kernel)) { IsBackground = true, Name = "etw-kernel" };
        _kernelThread.Start();

        // DNS names and scheduled tasks add detail; without them the run is still worth having.
        if (config.CaptureNetwork)
        {
            try
            {
                _user = new TraceEventSession(UserSessionName) { StopOnDispose = true };
                _user.EnableProvider(DnsClient, TraceEventLevel.Informational);
                _user.EnableProvider(TaskScheduler, TraceEventLevel.Informational);
                EnableAttemptProviders(_user);
                var parser = new RegisteredTraceEventParser(_user.Source);
                parser.All += Safe<TraceEvent>("user-mode event", OnUserEvent);
                var user = _user;
                _userThread = new Thread(() => Pump("user-mode", user)) { IsBackground = true, Name = "etw-user" };
                _userThread.Start();
                AgentLog.Info($"User-mode trace session {UserSessionName} started");
            }
            catch (Exception ex)
            {
                AgentLog.Error("The DNS and task scheduler trace session could not start; the analysis continues without DNS names and scheduled tasks", ex);
                sink.Add("AnalysisNote", 0, 0, 0, "blazma-agent", null, new() { ["Reason"] = $"DNS and scheduled task events are unavailable: {ex.Message}" }, "agent");
                _user?.Dispose();
                _user = null;
            }
        }
    }

    /// <summary>
    /// Connection attempts, including the ones that fail. Only the listed event ids are enabled
    /// (filtered by Windows, so sends and receives never reach the agent). Each provider is
    /// optional: without it, successful connections are still reported by the kernel session.
    /// </summary>
    private static void EnableAttemptProviders(TraceEventSession session)
    {
        try
        {
            session.EnableProvider(AttemptEvents.WinsockAfd, TraceEventLevel.Informational, AttemptEvents.Afd.KeywordSourceWinsock, new TraceEventProviderOptions { EventIDsToEnable = [.. AttemptEvents.Afd.Enabled] });
            AgentLog.Info("Winsock connection attempts are traced");
        }
        catch (Exception ex)
        {
            AgentLog.Warn("Winsock connection attempts cannot be traced; failed connections may be missing", ex);
        }
        try
        {
            session.EnableProvider(AttemptEvents.TcpIp, TraceEventLevel.Informational, AttemptEvents.Tcp.KeywordConnectPath, new TraceEventProviderOptions { EventIDsToEnable = [.. AttemptEvents.Tcp.Enabled] });
            AgentLog.Info("TCP/IP connection failures are traced");
        }
        catch (Exception ex)
        {
            AgentLog.Warn("TCP/IP connection failures cannot be traced", ex);
        }
    }

    /// <summary>Called right before the agent starts the sample: from now on its children are the analyzed tree.</summary>
    public void ExpectSample() => _sampleExpected = true;

    /// <summary>Processes events until the session stops. An event that cannot be handled is skipped (see <see cref="Safe{T}"/>).</summary>
    private static void Pump(string name, TraceEventSession session)
    {
        try
        {
            session.Source.Process();
            AgentLog.Info($"The {name} trace session stopped");
        }
        catch (Exception ex)
        {
            AgentLog.Error($"Processing of {name} events stopped with an error", ex);
        }
    }

    /// <summary>
    /// Wraps an ETW callback: one event that fails (an odd payload, a process that went away) is
    /// logged and skipped; it must not escape into the processing thread and end the agent.
    /// </summary>
    private static Action<T> Safe<T>(string what, Action<T> handler) => d =>
    {
        try { handler(d); }
        catch (Exception ex) { AgentLog.Limited("etw:" + what, $"Handling a {what} event failed", ex); }
    };

    public void TrackSample(int pid)
    {
        Tree[pid] = true;
        var info = Info(pid, "sample");
        sink.Add("SampleExecuted", pid, 0, info.StartMs, info.Name, null, new() { ["IsSample"] = "true" }, "agent");
    }

    public bool TreeAlive() => Tree.Keys.Any(pid => _processes.ContainsKey(pid));

    private void OnProcessStart(ProcessTraceData d)
    {
        if (d.ProcessID == _self) return;
        var start = sink.NowRelativeMs;
        _processes[d.ProcessID] = (start, d.ImageFileName);
        // After ExpectSample() the agent only starts the sample, so its children belong to the analyzed tree even if
        // this event beats TrackSample(). Before that, a child is a helper of the agent (pktmon), not the sample.
        var startedBySample = d.ParentID == _self && _sampleExpected;
        if (Tree.ContainsKey(d.ParentID) || startedBySample) Tree[d.ProcessID] = true;

        var details = new Dictionary<string, string>
        {
            ["CommandLine"] = d.CommandLine ?? string.Empty,
            ["ImagePath"] = ImagePath(d.ProcessID, d.CommandLine, d.ImageFileName),
        };
        if (startedBySample) details["IsSample"] = "true";
        sink.Add("ProcessStart", d.ProcessID, d.ParentID, start, d.ImageFileName, null, details, "etw.kernel.process");
    }

    private void File(string action, int pid, string? path, Dictionary<string, string>? details)
    {
        if (pid == _self || string.IsNullOrEmpty(path)) return;
        if (path.StartsWith(outDir, StringComparison.OrdinalIgnoreCase) || path.StartsWith(inDir, StringComparison.OrdinalIgnoreCase)) return;
        var info = Info(pid, "?");
        sink.Add(action, pid, 0, info.StartMs, info.Name, path, details, "etw.kernel.file");
        if (action is "FileCreate" or "FileWrite" or "FileRename" && Tree.ContainsKey(pid)) TreeFileWritten?.Invoke(path, pid, info.Name);
    }

    private void Registry(string action, RegistryTraceData d)
    {
        if (d.ProcessID == _self || string.IsNullOrEmpty(d.KeyName)) return;
        var info = Info(d.ProcessID, d.ProcessName);
        var details = new Dictionary<string, string>();
        if (!string.IsNullOrEmpty(d.ValueName)) details["ValueName"] = d.ValueName;
        if (action == "RegistryValueSet" && ReadValue(d.KeyName, d.ValueName) is { } data) details["ValueData"] = data;
        sink.Add(action, d.ProcessID, 0, info.StartMs, info.Name, d.KeyName, details, "etw.kernel.registry");
    }

    private void Connect(int pid, string ip, int port, string protocol)
    {
        if (pid == _self) return;
        var info = Info(pid, "?");
        _traffic.TryAdd((pid, ip, port), (0, 0, info.Name));
        sink.Add("NetworkConnect", pid, 0, info.StartMs, info.Name, ip, new()
        {
            ["RemoteAddress"] = ip,
            ["RemotePort"] = port.ToString(CultureInfo.InvariantCulture),
            ["Protocol"] = protocol,
            ["Status"] = "Connected",
        }, "etw.kernel.tcpip");
    }

    /// <summary>
    /// Records an attempt seen by Winsock-AFD or the TCP/IP stack: the first one and the first failure
    /// per destination become events, retries only raise the count (written by <see cref="FlushTraffic"/>).
    /// </summary>
    private void Attempt(int pid, string ip, int port, string protocol, bool outcomeOnly, long? status, string source)
    {
        if (pid == _self || pid <= 4) return;
        if (System.Net.IPAddress.TryParse(ip, out var address) && System.Net.IPAddress.IsLoopback(address) && IsSimulatedPort?.Invoke(port) == true) return;
        var failed = EtwValue.IsFailure(status);
        var report = outcomeOnly
            ? failed || status is null ? _attempts.Failure(pid, ip, port, protocol, failed ? status : null) : AttemptReport.None
            : _attempts.Attempt(pid, ip, port, protocol, failed, failed ? status : null);
        if (report == AttemptReport.None) return;
        var info = Info(pid, "?");
        var details = new Dictionary<string, string>
        {
            ["RemoteAddress"] = ip,
            ["RemotePort"] = port.ToString(CultureInfo.InvariantCulture),
            ["Protocol"] = protocol,
            ["Status"] = report == AttemptReport.Failed ? "Failed" : "Attempted",
        };
        if (failed) details["ErrorCode"] = EtwValue.Hex(status!.Value);
        sink.Add("NetworkConnect", pid, 0, info.StartMs, info.Name, ip, details, source);
    }

    private void OnAfdEvent(TraceEvent d)
    {
        var id = (int)d.ID;
        var endpoint = unchecked((ulong)(EtwValue.Number(d.PayloadByName("Endpoint")) ?? 0));
        var status = EtwValue.Number(d.PayloadByName("Status"));
        switch (id)
        {
            case AttemptEvents.Afd.Create:
                if (endpoint != 0 && _socketProtocols.Count < 65_536)
                    _socketProtocols[endpoint] = EtwValue.Number(d.PayloadByName("Protocol")) == 17 || EtwValue.Number(d.PayloadByName("SocketType")) == 2 ? "UDP" : "TCP";
                break;
            case AttemptEvents.Afd.Close:
                _socketProtocols.TryRemove(endpoint, out _);
                _pendingConnects.TryRemove(endpoint, out _);
                break;
            case AttemptEvents.Afd.ConnectWithAddress or AttemptEvents.Afd.ConnectExWithAddress or AttemptEvents.Afd.SendToWithAddress:
                if (!SocketAddressParser.TryParse(d.PayloadByName("Address"), out var ip, out var port)) return;
                var protocol = id == AttemptEvents.Afd.SendToWithAddress ? "UDP" : _socketProtocols.GetValueOrDefault(endpoint, "TCP");
                if (id != AttemptEvents.Afd.SendToWithAddress && endpoint != 0)
                {
                    // The same endpoint is logged again when the call returns: that is the outcome, not a second attempt.
                    if (_pendingConnects.TryGetValue(endpoint, out var pending) && pending == (d.ProcessID, ip, port, protocol))
                    {
                        if (EtwValue.IsFailure(status)) Attempt(d.ProcessID, ip, port, protocol, outcomeOnly: true, status, "etw.winsock-afd");
                        return;
                    }
                    if (_pendingConnects.Count < 65_536) _pendingConnects[endpoint] = (d.ProcessID, ip, port, protocol);
                }
                Attempt(d.ProcessID, ip, port, protocol, outcomeOnly: false, status, "etw.winsock-afd");
                break;
            case AttemptEvents.Afd.Connect or AttemptEvents.Afd.ConnectEx:
                // Completion without the address: tie it to the endpoint's attempt.
                if (EtwValue.IsFailure(status) && _pendingConnects.TryGetValue(endpoint, out var c))
                    Attempt(c.Pid, c.Address, c.Port, c.Protocol, outcomeOnly: true, status, "etw.winsock-afd");
                break;
        }
    }

    private void OnTcpIpEvent(TraceEvent d)
    {
        if ((int)d.ID is not (AttemptEvents.Tcp.FailedAddressFamily or AttemptEvents.Tcp.FailedCompartment or AttemptEvents.Tcp.FailedInspect or AttemptEvents.Tcp.FailedRoute or AttemptEvents.Tcp.Failure or AttemptEvents.Tcp.FailedPortAcquire)) return;
        if (!SocketAddressParser.TryParse(d.PayloadByName("RemoteAddress"), out var ip, out var port)) return;
        // The stack may log this outside the program's thread; version 1 of these events names the process.
        var pid = (int)(EtwValue.Number(d.PayloadByName("ProcessId")) ?? 0);
        if (pid <= 0) pid = d.ProcessID;
        var status = EtwValue.Number(d.PayloadByName("Status"));
        Attempt(pid, ip, port, "TCP", outcomeOnly: true, EtwValue.IsFailure(status) ? status : null, "etw.tcpip");
    }

    private void Count(int pid, string ip, int port, int size, bool sent) =>
        _traffic.AddOrUpdate((pid, ip, port), _ => (sent ? size : 0, sent ? 0 : size, Info(pid, "?").Name),
            (_, t) => (t.Sent + (sent ? size : 0), t.Received + (sent ? 0 : size), t.Name));

    private void OnUserEvent(TraceEvent d)
    {
        if (d.ProviderGuid == AttemptEvents.WinsockAfd) { OnAfdEvent(d); return; }
        if (d.ProviderGuid == AttemptEvents.TcpIp) { OnTcpIpEvent(d); return; }
        if (d.ProcessID == _self) return;
        var info = Info(d.ProcessID, d.ProcessName);
        if (d.ProviderGuid == DnsClient && (int)d.ID == 3008)
        {
            var name = d.PayloadByName("QueryName") as string;
            if (string.IsNullOrEmpty(name)) return;
            DnsLookup?.Invoke(name);
            var details = new Dictionary<string, string> { ["QueryName"] = name };
            // The answer links a name to the addresses connected to later. With the simulated internet every answer
            // is the hosts file's 127.0.0.1, which says nothing about the name, so it is left out.
            var addresses = DnsAnswers.Addresses(d.PayloadByName("QueryResults") as string, dropLoopback: config.NetworkMode == "simulated");
            if (addresses.Count > 0) details["QueryResult"] = string.Join(';', addresses);
            sink.Add("DnsQuery", d.ProcessID, 0, info.StartMs, info.Name, name, details, "etw.dns-client");
        }
        else if (d.ProviderGuid == TaskScheduler && (int)d.ID == 106 && d.PayloadByName("TaskName") is string task)
        {
            sink.Add("ScheduledTaskCreate", d.ProcessID, 0, info.StartMs, info.Name, task, new() { ["TaskName"] = task.TrimStart('\\') }, "etw.task-scheduler");
        }
    }

    /// <summary>Emits per-endpoint byte totals and attempt counts. Called once when collection stops.</summary>
    public void FlushTraffic()
    {
        foreach (var ((pid, ip, port), t) in _traffic)
        {
            if (t.Sent == 0 && t.Received == 0) continue;
            sink.Add("NetworkSend", pid, 0, Info(pid, t.Name).StartMs, t.Name, ip, new()
            {
                ["RemoteAddress"] = ip,
                ["RemotePort"] = port.ToString(CultureInfo.InvariantCulture),
                ["BytesSent"] = t.Sent.ToString(CultureInfo.InvariantCulture),
                ["BytesReceived"] = t.Received.ToString(CultureInfo.InvariantCulture),
            }, "etw.kernel.tcpip");
        }

        // Retries were only counted; one summary per destination carries the total.
        foreach (var a in _attempts.Totals().Where(a => a.Count > 1))
        {
            var info = Info(a.Pid, "?");
            var details = new Dictionary<string, string>
            {
                ["RemoteAddress"] = a.Address,
                ["RemotePort"] = a.Port.ToString(CultureInfo.InvariantCulture),
                ["Protocol"] = a.Protocol,
                ["Status"] = a.Failed ? "Failed" : "Attempted",
                ["Attempts"] = a.Count.ToString(CultureInfo.InvariantCulture),
            };
            if (a.LastFailure is { } f) details["ErrorCode"] = EtwValue.Hex(f);
            sink.Add("NetworkConnect", a.Pid, 0, info.StartMs, info.Name, a.Address, details, "etw.winsock-afd");
        }
        if (_attempts.Overflow > 0)
            sink.Add("AnalysisNote", 0, 0, 0, "blazma-agent", null, new()
            {
                ["Reason"] = $"{_attempts.Overflow} further connection attempts went to more than {ConnectAttempts.DefaultMaxDestinations} different addresses and were not listed one by one.",
            }, "agent");
    }

    private (long StartMs, string Name) Info(int pid, string fallback) =>
        _processes.TryGetValue(pid, out var p) ? p : (0, string.IsNullOrEmpty(fallback) ? "?" : fallback);

    private static string ImagePath(int pid, string? commandLine, string imageName)
    {
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            if (p.MainModule?.FileName is { Length: > 0 } f) return f;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { }
        if (!string.IsNullOrEmpty(commandLine))
        {
            var cl = commandLine.Trim();
            var path = cl.StartsWith('"') ? cl[1..Math.Max(1, cl.IndexOf('"', 1))] : cl.Split(' ')[0];
            if (path.Contains('\\', StringComparison.Ordinal)) return path;
        }
        return imageName;
    }

    /// <summary>Kernel registry events carry no value data; read it right away (best effort, may race).</summary>
    private static string? ReadValue(string kernelKey, string? valueName)
    {
        try
        {
            RegistryKey? root = null;
            string sub;
            if (kernelKey.StartsWith(@"\REGISTRY\MACHINE\", StringComparison.OrdinalIgnoreCase)) { root = Microsoft.Win32.Registry.LocalMachine; sub = kernelKey[18..]; }
            else if (kernelKey.StartsWith(@"\REGISTRY\USER\", StringComparison.OrdinalIgnoreCase)) { root = Microsoft.Win32.Registry.Users; sub = kernelKey[15..]; }
            else return null;
            using var key = root.OpenSubKey(sub);
            var value = key?.GetValue(valueName ?? string.Empty);
            var text = value switch
            {
                null => null,
                string s => s,
                string[] a => string.Join(";", a),
                byte[] b => Convert.ToHexString(b.AsSpan(0, Math.Min(b.Length, 256))),
                _ => Convert.ToString(value, CultureInfo.InvariantCulture),
            };
            return text is { Length: > 2048 } ? text[..2048] : text;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException or ArgumentException)
        {
            return null;
        }
    }

    public void Dispose()
    {
        _kernel?.Dispose();
        _user?.Dispose();
        _kernelThread?.Join(TimeSpan.FromSeconds(5));
        _userThread?.Join(TimeSpan.FromSeconds(5));
    }
}
