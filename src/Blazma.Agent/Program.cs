using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Blazma.Agent;
using Blazma.Agent.Capture;
using Blazma.Agent.Collect;
using Blazma.Agent.FakeNet;
using Blazma.Agent.Simulation;
using Blazma.Contracts;

// Blazma Sandbox monitoring agent. Started by the sandbox's LogonCommand:
//   Blazma.Agent.exe <in folder (read-only)> <out folder (writable)>
// It never runs on the host.

if (!OperatingSystem.IsWindows() || args.Length < 2)
{
    Console.Error.WriteLine("Blazma.Agent runs only inside a Windows analysis sandbox: Blazma.Agent.exe <in> <out>");
    return 2;
}
return await AgentHost.RunAsync(args[0], args[1]);

[SupportedOSPlatform("windows")]
internal static class AgentHost
{
    private const int MaxEvents = 500_000;

    public static async Task<int> RunAsync(string inDir, string outDir)
    {
        using var log = new AgentLog(Path.Combine(outDir, Protocol.AgentLogFile));
        AgentLog.Use(log);
        AppDomain.CurrentDomain.UnhandledException += (_, e) => AgentLog.Error("Unhandled exception; the agent is stopping", e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            AgentLog.Limited("background-task", "A background task failed", e.Exception);
            e.SetObserved();
        };
        var code = 1;
        try
        {
            code = await RunCoreAsync(inDir, outDir);
            return code;
        }
        catch (Exception ex)
        {
            // Also on stderr: if out/ itself is the problem, the launcher's output is all there is.
            AgentLog.Error("The agent stopped with an error", ex);
            Console.Error.WriteLine($"Blazma.Agent stopped with an error: {ex}");
            return code;
        }
        finally
        {
            AgentLog.Info($"Agent stopped (exit code {code})");
            AgentLog.Use(null);
        }
    }

    private static async Task<int> RunCoreAsync(string inDir, string outDir)
    {
        var elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        var version = typeof(AgentHost).Assembly.GetName().Version?.ToString(3) ?? "0";
        using (var self = Process.GetCurrentProcess())
            AgentLog.Info($"Blazma agent {version} starting on {RuntimeInformation.OSDescription} ({Environment.OSVersion.VersionString}, {RuntimeInformation.OSArchitecture}) as {Environment.UserDomainName}\\{Environment.UserName}, session {self.SessionId}, elevated: {elevated}");
        AgentLog.Info($"Executable {Environment.ProcessPath}, in {inDir}, out {outDir}, temp {Path.GetTempPath()}");

        AgentLog.Info($"Waiting for {Protocol.SessionFile}");
        var config = await WaitForJsonAsync(Path.Combine(inDir, Protocol.SessionFile), ProtocolJson.Default.SessionConfigDto, TimeSpan.FromMinutes(5));
        if (config?.ChannelKey is null)
        {
            AgentLog.Error(config is null ? $"No readable {Protocol.SessionFile} within 5 minutes; stopping." : $"{Protocol.SessionFile} has no channel key; stopping.");
            return 3;
        }
        // Never log the key itself: agent.log is not secret.
        var key = Convert.FromBase64String(config.ChannelKey);
        AgentLog.Info($"Session {config.AnalysisId}: {config.DurationSeconds} s, network {config.NetworkMode}, processes {config.CaptureProcesses}, files {config.CaptureFiles}, registry {config.CaptureRegistry}, " +
                      $"network events {config.CaptureNetwork}, snapshots {config.TakeSnapshots}, screenshots every {config.ScreenshotIntervalSeconds} s, simulated user {config.SimulateUser}, " +
                      $"dropped files {config.CollectDroppedFiles}, memory {config.DumpMemory}, pcap {config.CapturePcap}, interactive {config.Interactive}");
        var sink = new EventSink(outDir, key, MaxEvents);
        sink.StartClock();

        sink.WriteAtomic(Protocol.HelloFile, JsonSerializer.SerializeToUtf8Bytes(new HelloDto
        {
            ProtocolVersion = Protocol.Version,
            AgentVersion = version,
            OsVersion = Environment.OSVersion.VersionString,
            At = DateTimeOffset.UtcNow,
            Elevated = elevated,
        }, ProtocolJson.Default.HelloDto));
        AgentLog.Info($"{Protocol.HelloFile} written");

        var done = new DoneDto();
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            // Last resort: tell the host why instead of leaving it to time out on missing heartbeats.
            try
            {
                done.Reason = "error";
                done.Error = "The monitoring agent stopped unexpectedly: " + (e.ExceptionObject as Exception)?.Message;
                done.At = DateTimeOffset.UtcNow;
                done.EventsWritten = sink.Written;
                sink.WriteSigned(Protocol.DoneFile, JsonSerializer.SerializeToUtf8Bytes(done, ProtocolJson.Default.DoneDto));
            }
            catch (Exception) { }
        };
        void Note(string text) => sink.Add("AnalysisNote", 0, 0, 0, "blazma-agent", null, new() { ["Reason"] = text }, "agent");

        // One part failing (screenshots, the simulated internet, a snapshot...) is noted and the run goes on.
        void Guard(string what, Action action)
        {
            try { action(); }
            catch (Exception ex)
            {
                AgentLog.Error($"{what} failed; the analysis continues without it", ex);
                Note($"{what} failed: {ex.Message}");
            }
        }

        using var heartbeat = new Heartbeat(() => Beat(sink, "running"), TimeSpan.FromSeconds(Math.Max(1, config.HeartbeatSeconds)));
        try
        {
            if (!elevated)
                throw new InvalidOperationException("The monitoring agent is not running as administrator, so Windows event tracing cannot start and nothing would be observed. The sample was not started.");

            AgentLog.Info($"Waiting for {Protocol.GoFile}");
            var go = await WaitForJsonAsync(Path.Combine(inDir, Protocol.GoFile), ProtocolJson.Default.GoDto, TimeSpan.FromMinutes(10))
                     ?? throw new TimeoutException("No go signal from the host.");
            AgentLog.Info(go.Url is { Length: > 0 } ? $"Go: open a web address (SHA-256 {go.Sha256})" : $"Go: run {go.SampleFileName} (SHA-256 {go.Sha256})");

            if (config.TakeSnapshots)
                Guard("The snapshot before the run", () => sink.WriteSigned(Protocol.BaselineFile, JsonSerializer.SerializeToUtf8Bytes(Snapshotter.Take(Path.GetPathRoot(outDir) + "Blazma"), ProtocolJson.Default.SnapshotDto)));

            using var monitor = new EtwMonitor(sink, config, inDir, outDir);

            // Simulated internet: names resolve to 127.0.0.1, where fake servers answer. There is still no real network.
            using var dns = config.NetworkMode == "simulated" ? new DnsRedirector(HostsFile.DefaultPath, Note) : null;
            using var fakeNet = config.NetworkMode == "simulated" ? new FakeInternet(r => RecordSimulated(sink, monitor, r)) : null;
            if (dns is not null) monitor.DnsLookup += dns.OnLookup;

            var dropped = config.CollectDroppedFiles ? new DroppedFileCollector(sink, config.MaxDroppedFiles, config.MaxDroppedFileBytes) : null;
            if (dropped is not null) monitor.TreeFileWritten += dropped.Observe;
            var memory = config.DumpMemory ? new MemoryDumper(sink, config.MaxMemoryBytes) : null;

            // Without kernel tracing nothing is observed, so that one failure ends the run.
            monitor.Start();
            AgentLog.Info("Event tracing started");
            if (dns is not null) Guard("The simulated DNS", dns.Start);
            if (fakeNet is not null)
            {
                Guard("The simulated internet", () => fakeNet.Start(FakeInternet.DefaultHttpPorts, FakeInternet.DefaultTlsPorts, FakeInternet.DefaultRawPorts));
                AgentLog.Info($"Simulated internet listening on {fakeNet.ListeningPorts.Count} ports");
            }
            var work = Path.Combine(Path.GetTempPath(), "blazma-agent");
            var capture = config.CapturePcap && config.NetworkMode == "on" ? new PacketCapture(sink, work, Note) : null;
            if (capture is not null) Guard("The network capture", capture.Start);
            await Task.Delay(1500); // let the ETW sessions attach before the sample starts

            string? samplePath = null;
            Process? process;
            try
            {
                if (go.Url is not { Length: > 0 }) samplePath = PrepareSample(inDir, go);
                monitor.ExpectSample();
                sink.MarkSampleStart();
                process = go.Url is { Length: > 0 } url ? OpenUrl(url, go.Sha256) : Launch(samplePath!);
            }
            catch (Exception ex)
            {
                var message = SampleLauncher.DescribeFailure(ex);
                Note(message);
                throw new InvalidOperationException(message, ex);
            }
            done.SampleStarted = true;
            if (process is not null)
            {
                var pid = process.Id;
                monitor.TrackSample(pid);
                Guard("Watching the sample's exit", () =>
                {
                    process.EnableRaisingEvents = true;
                    process.Exited += (_, _) => AgentLog.Info($"The sample (process {pid}) exited with code {ExitCode(process)}");
                });
            }

            using var screens = config.ScreenshotIntervalSeconds > 0 ? new ScreenCapturer(sink, config.ScreenshotIntervalSeconds, config.MaxScreenshots) : null;
            if (screens is not null) Guard("Screenshots", screens.Start);
            using var user = config.SimulateUser ? new UserSimulator(Note) : null;
            if (user is not null) Guard("The simulated user", user.Start);

            var control = new ControlWatcher(inDir, Math.Clamp(config.DurationSeconds, 15, 1800));
            var watch = Stopwatch.StartNew();
            var quietSince = (TimeSpan?)null;
            var nextMemoryScan = TimeSpan.FromSeconds(20);
            var finishedEarly = false;
            while (true)
            {
                await Task.Delay(1000);
                Repeat("Writing events", sink.Flush);
                control.Poll();
                if (control.FinishRequested) { finishedEarly = true; break; }
                if (watch.Elapsed >= TimeSpan.FromSeconds(control.DurationSeconds)) break;
                if (memory is not null && watch.Elapsed >= nextMemoryScan)
                {
                    nextMemoryScan = watch.Elapsed + TimeSpan.FromSeconds(20);
                    Repeat("Memory scan", () => memory.Scan(monitor.LiveTreeProcesses()));
                }
                if (!config.StopWhenTreeExits) continue;
                if (monitor.TreeAlive()) { quietSince = null; continue; }
                quietSince ??= watch.Elapsed;
                if (watch.Elapsed - quietSince > TimeSpan.FromSeconds(10)) break;
            }
            done.Reason = finishedEarly ? "finished-by-analyst" : watch.Elapsed >= TimeSpan.FromSeconds(control.DurationSeconds) ? "duration" : "tree-exited";
            AgentLog.Info($"Collection ends ({done.Reason}) after {watch.Elapsed.TotalSeconds:F0} s");

            screens?.CaptureOnce();
            if (memory is not null) Guard("The last memory scan", () => memory.Scan(monitor.LiveTreeProcesses()));
            user?.Dispose();
            if (process is not null) Guard("Reading the sample's exit code", () => { if (process.HasExited) done.SampleExitCode = process.ExitCode; });
            Guard("Network totals", monitor.FlushTraffic);
            Repeat("Writing events", sink.Flush);
            Guard("Stopping event tracing", monitor.Dispose);
            if (capture is not null) Guard("The network capture", capture.StopAndSend);
            if (dropped is not null)
            {
                IReadOnlyCollection<string> excluded = samplePath is null ? [inDir, outDir, work] : [inDir, outDir, work, samplePath];
                Guard("Collecting dropped files", () => AgentLog.Info($"{dropped.Collect(go.Sha256, excluded)} dropped files collected"));
            }
            Repeat("Writing events", sink.Flush);

            if (config.TakeSnapshots)
                Guard("The snapshot after the run", () => sink.WriteSigned(Protocol.AfterFile, JsonSerializer.SerializeToUtf8Bytes(Snapshotter.Take(Path.GetPathRoot(outDir) + "Blazma"), ProtocolJson.Default.SnapshotDto)));
        }
        catch (Exception ex)
        {
            AgentLog.Error("The analysis stopped with an error", ex);
            done.Error = ex.Message;
            done.Reason = "error";
        }
        finally
        {
            Repeat("Writing events", sink.Flush);
            done.At = DateTimeOffset.UtcNow;
            done.EventsWritten = sink.Written;
            sink.WriteSigned(Protocol.DoneFile, JsonSerializer.SerializeToUtf8Bytes(done, ProtocolJson.Default.DoneDto));
            AgentLog.Info($"{Protocol.DoneFile} written: {done.Reason}, {done.EventsWritten} events, {sink.Dropped} events over the limit, sample started: {done.SampleStarted}, exit code: {done.SampleExitCode?.ToString(CultureInfo.InvariantCulture) ?? "-"}");
        }
        return done.Error is null ? 0 : 1;
    }

    /// <summary>For steps repeated every second: a failure is logged (a few times) and the next round tries again.</summary>
    private static void Repeat(string what, Action action)
    {
        try { action(); }
        catch (Exception ex) { AgentLog.Limited(what, $"{what} failed", ex); }
    }

    private static string ExitCode(Process process)
    {
        try { return process.ExitCode.ToString(CultureInfo.InvariantCulture); }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { return "unknown"; }
    }

    private static void Beat(EventSink sink, string state) =>
        sink.WriteSigned(Protocol.HeartbeatFile, JsonSerializer.SerializeToUtf8Bytes(
            new HeartbeatDto { At = DateTimeOffset.UtcNow, EventsWritten = sink.Written, State = state }, ProtocolJson.Default.HeartbeatDto));

    /// <summary>
    /// Copies the sample out of the read-only shared folder to the (writable) desktop, under its own
    /// name so Windows treats it by its extension, and checks it is exactly what the host sent.
    /// </summary>
    private static string PrepareSample(string inDir, GoDto go)
    {
        var source = Path.Combine(inDir, Protocol.SampleFolder, Path.GetFileName(go.SampleFileName));
        var target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Path.GetFileName(go.SampleFileName));
        File.Copy(source, target, overwrite: true);
        // A read-only attribute carried over from the mapped folder would stop a sample that moves or
        // deletes itself, and a Mark-of-the-Web would make Windows show a security prompt instead of running it.
        File.SetAttributes(target, File.GetAttributes(target) & ~FileAttributes.ReadOnly);
        try { File.Delete(target + ":Zone.Identifier"); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { AgentLog.Warn("Could not remove the Mark-of-the-Web from the sample", ex); }
        using var s = File.OpenRead(target);
        var hash = Convert.ToHexStringLower(SHA256.HashData(s));
        if (!hash.Equals(go.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Sample hash mismatch.");
        AgentLog.Info($"Sample copied to {target} and verified");
        return target;
    }

    /// <summary>Records what the simulated internet saw, attributed to the process that connected.</summary>
    private static void RecordSimulated(EventSink sink, EtwMonitor monitor, FakeNetRecord r)
    {
        var pid = ConnectionOwners.Find(r.ClientPort, r.ServerPort) ?? 0;
        var info = monitor.ProcessInfo(pid);
        var details = new Dictionary<string, string>(r.Details) { ["Simulated"] = "true", ["RemoteAddress"] = "127.0.0.1" };
        switch (r.Kind)
        {
            case "http":
                var host = r.Host is { Length: > 0 } h ? h : "127.0.0.1";
                var scheme = details.GetValueOrDefault("Protocol", "http");
                sink.Add("HttpRequest", pid, 0, info.StartMs, info.Name, $"{scheme}://{host}{details.GetValueOrDefault("HttpPath", "/")}", details, "agent.fakenet");
                break;
            case "tls":
                sink.Add("TlsHandshake", pid, 0, info.StartMs, info.Name, r.Host ?? "127.0.0.1", details, "agent.fakenet");
                break;
            default:
                sink.Add("NetworkSend", pid, 0, info.StartMs, info.Name, "127.0.0.1", details, "agent.fakenet");
                break;
        }
    }

    /// <summary>Opens a web address in the sandbox's Edge. The hash ties it to exactly what the host analyzed.</summary>
    private static Process? OpenUrl(string url, string sha256)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) throw new InvalidDataException("The address is not a web address.");
        var hash = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(url)));
        if (!hash.Equals(sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Address hash mismatch.");
        var edge = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        }.Select(root => Path.Combine(root, "Microsoft", "Edge", "Application", "msedge.exe")).FirstOrDefault(File.Exists)
            ?? throw new FileNotFoundException("Microsoft Edge was not found in the sandbox.");
        var psi = new ProcessStartInfo(edge) { UseShellExecute = false };
        psi.ArgumentList.Add("--no-first-run");
        psi.ArgumentList.Add("--no-default-browser-check");
        psi.ArgumentList.Add(uri.AbsoluteUri);
        AgentLog.Info($"Opening the address in {edge}");
        var process = Process.Start(psi) ?? throw new InvalidOperationException("Microsoft Edge did not start.");
        AgentLog.Info($"Microsoft Edge started as process {process.Id}");
        return process;
    }

    /// <summary>Starts the sample the way Windows would when a user opens it (see <see cref="SampleLauncher"/>).</summary>
    private static Process? Launch(string path)
    {
        var head = new byte[4096];
        int read;
        using (var s = File.OpenRead(path)) read = s.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
        var plan = SampleLauncher.Plan(path, head.AsSpan(0, read), Environment.GetFolderPath(Environment.SpecialFolder.System));
        var folder = Path.GetDirectoryName(path)!;
        AgentLog.Info($"Starting the sample: {plan.CommandLine} (through the shell: {plan.UseShellExecute}, in {folder})");
        var process = Process.Start(new ProcessStartInfo(plan.FileName, plan.Arguments) { UseShellExecute = plan.UseShellExecute, WorkingDirectory = folder });
        // The shell may hand a document to an application without starting a new process; its children are still seen.
        if (process is null && !plan.UseShellExecute) throw new InvalidOperationException("The sample did not start.");
        AgentLog.Info(process is null ? "Windows opened the sample without starting a new process" : $"The sample started as process {process.Id}");
        return process;
    }

    private static async Task<T?> WaitForJsonAsync<T>(string path, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type, TimeSpan timeout) where T : class
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                if (File.Exists(path)) return JsonSerializer.Deserialize(await File.ReadAllBytesAsync(path), type);
            }
            catch (Exception ex) when (ex is IOException or JsonException) { }
            await Task.Delay(500);
        }
        return null;
    }
}
