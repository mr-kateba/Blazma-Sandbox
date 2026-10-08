using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Blazma.Agent;
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
        var config = await WaitForJsonAsync(Path.Combine(inDir, Protocol.SessionFile), ProtocolJson.Default.SessionConfigDto, TimeSpan.FromMinutes(5));
        if (config?.ChannelKey is null) return 3;
        var key = Convert.FromBase64String(config.ChannelKey);
        var sink = new EventSink(outDir, key, MaxEvents);
        sink.StartClock();

        var elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        sink.WriteAtomic(Protocol.HelloFile, JsonSerializer.SerializeToUtf8Bytes(new HelloDto
        {
            ProtocolVersion = Protocol.Version,
            AgentVersion = typeof(AgentHost).Assembly.GetName().Version?.ToString(3) ?? "0",
            OsVersion = Environment.OSVersion.VersionString,
            At = DateTimeOffset.UtcNow,
            Elevated = elevated,
        }, ProtocolJson.Default.HelloDto));

        var done = new DoneDto();
        using var heartbeat = new Timer(_ => Beat(sink, "running"), null, TimeSpan.Zero, TimeSpan.FromSeconds(Math.Max(1, config.HeartbeatSeconds)));
        try
        {
            if (!elevated) throw new InvalidOperationException("The agent is not elevated; kernel tracing is unavailable.");

            var go = await WaitForJsonAsync(Path.Combine(inDir, Protocol.GoFile), ProtocolJson.Default.GoDto, TimeSpan.FromMinutes(10))
                     ?? throw new TimeoutException("No go signal from the host.");

            if (config.TakeSnapshots)
                sink.WriteSigned(Protocol.BaselineFile, JsonSerializer.SerializeToUtf8Bytes(Snapshotter.Take(Path.GetPathRoot(outDir) + "Blazma"), ProtocolJson.Default.SnapshotDto));

            using var monitor = new EtwMonitor(sink, config, inDir, outDir);
            monitor.Start();
            await Task.Delay(1500); // let the ETW sessions attach before the sample starts

            var sample = PrepareSample(inDir, go);
            sink.MarkSampleStart();
            var process = Launch(sample);
            done.SampleStarted = true;
            monitor.TrackSample(process.Id);

            var duration = TimeSpan.FromSeconds(Math.Clamp(config.DurationSeconds, 15, 1800));
            var watch = Stopwatch.StartNew();
            var quietSince = (TimeSpan?)null;
            while (watch.Elapsed < duration)
            {
                await Task.Delay(1000);
                sink.Flush();
                if (!config.StopWhenTreeExits) continue;
                if (monitor.TreeAlive()) { quietSince = null; continue; }
                quietSince ??= watch.Elapsed;
                if (watch.Elapsed - quietSince > TimeSpan.FromSeconds(10)) break;
            }

            if (process.HasExited) done.SampleExitCode = process.ExitCode;
            monitor.FlushTraffic();
            sink.Flush();
            monitor.Dispose();
            sink.Flush();

            if (config.TakeSnapshots)
                sink.WriteSigned(Protocol.AfterFile, JsonSerializer.SerializeToUtf8Bytes(Snapshotter.Take(Path.GetPathRoot(outDir) + "Blazma"), ProtocolJson.Default.SnapshotDto));
            done.Reason = watch.Elapsed >= duration ? "duration" : "tree-exited";
        }
        catch (Exception ex)
        {
            done.Error = ex.Message;
            done.Reason = "error";
        }
        finally
        {
            sink.Flush();
            done.At = DateTimeOffset.UtcNow;
            done.EventsWritten = sink.Written;
            sink.WriteSigned(Protocol.DoneFile, JsonSerializer.SerializeToUtf8Bytes(done, ProtocolJson.Default.DoneDto));
        }
        return done.Error is null ? 0 : 1;
    }

    private static void Beat(EventSink sink, string state)
    {
        try
        {
            sink.WriteSigned(Protocol.HeartbeatFile, JsonSerializer.SerializeToUtf8Bytes(
                new HeartbeatDto { At = DateTimeOffset.UtcNow, EventsWritten = sink.Written, State = state }, ProtocolJson.Default.HeartbeatDto));
        }
        catch (IOException) { }
    }

    /// <summary>Copies the sample out of the shared folder and checks it is exactly what the host sent.</summary>
    private static string PrepareSample(string inDir, GoDto go)
    {
        var source = Path.Combine(inDir, Protocol.SampleFolder, Path.GetFileName(go.SampleFileName));
        var target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Path.GetFileName(go.SampleFileName));
        File.Copy(source, target, overwrite: true);
        using var s = File.OpenRead(target);
        var hash = Convert.ToHexStringLower(SHA256.HashData(s));
        if (!hash.Equals(go.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Sample hash mismatch.");
        return target;
    }

    /// <summary>Starts the sample the way Windows would when a user opens it.</summary>
    private static Process Launch(string path)
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var ext = Path.GetExtension(path).ToLowerInvariant();
        var psi = ext switch
        {
            ".dll" => new ProcessStartInfo(Path.Combine(system, "rundll32.exe"), $"\"{path}\",#1"),
            ".msi" => new ProcessStartInfo(Path.Combine(system, "msiexec.exe"), $"/i \"{path}\" /qn"),
            ".ps1" => new ProcessStartInfo(Path.Combine(system, @"WindowsPowerShell\v1.0\powershell.exe"), $"-NoProfile -ExecutionPolicy Bypass -File \"{path}\""),
            ".bat" or ".cmd" => new ProcessStartInfo(Path.Combine(system, "cmd.exe"), $"/c \"{path}\""),
            ".vbs" or ".vbe" or ".js" or ".jse" or ".wsf" => new ProcessStartInfo(Path.Combine(system, "wscript.exe"), $"\"{path}\""),
            ".lnk" => new ProcessStartInfo(path) { UseShellExecute = true },
            _ => new ProcessStartInfo(path),
        };
        psi.WorkingDirectory = Path.GetDirectoryName(path)!;
        return Process.Start(psi) ?? throw new InvalidOperationException("The sample did not start.");
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
