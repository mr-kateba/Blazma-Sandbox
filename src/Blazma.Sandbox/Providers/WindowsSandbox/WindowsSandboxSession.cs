using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using Blazma.Contracts;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Sandbox.Channel;
using Blazma.Sandbox.Isolation;
using Microsoft.Extensions.Logging;

namespace Blazma.Sandbox.Providers.WindowsSandbox;

/// <summary>
/// One Windows Sandbox run. Host side only: it prepares the two mapped folders, starts
/// the sandbox with a generated .wsb file, talks to the agent through files, and tears
/// everything down. It never opens, loads or executes the sample on the host.
/// </summary>
internal sealed class WindowsSandboxSession(SandboxSessionRequest request, WindowsSandboxOptions options, ILogger logger) : ISandboxSession, IInteractiveSession
{
    private readonly string _work = Path.Combine(options.WorkRoot, request.AnalysisId.ToString("N"));
    private readonly byte[] _key = SignedFile.NewKey();
    private string In => Path.Combine(_work, "in");
    private string Out => Path.Combine(_work, "out");
    private OutboxReader? _reader;
    private Process? _sandbox;
    private DateTimeOffset _sampleStart;
    private bool _shutdown;
    private TimeSpan _duration = request.Options.Duration;
    private int _controlSequence;
    private readonly object _controlLock = new();
    private string ArtifactsFolder => request.ArtifactsFolder ?? Path.Combine(_work, "artifacts");

    public Task CreateEnvironmentAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.Combine(In, Protocol.AgentFolder));
        Directory.CreateDirectory(Path.Combine(In, Protocol.SampleFolder));
        Directory.CreateDirectory(Out);

        foreach (var file in Directory.EnumerateFiles(options.AgentFolder))
            File.Copy(file, Path.Combine(In, Protocol.AgentFolder, Path.GetFileName(file)), overwrite: true);

        var config = ChannelFiles.CreateConfig(request, _key, options.StopWhenTreeExits, options.AgentLimits);
        WriteAtomic(Path.Combine(In, Protocol.SessionFile), JsonSerializer.SerializeToUtf8Bytes(config, ProtocolJson.Default.SessionConfigDto));

        var policy = new IsolationPolicy
        {
            HostInFolder = In,
            HostOutFolder = Out,
            Network = request.Options.Network,
            MemoryMb = options.MemoryMb,
        };
        File.WriteAllText(Path.Combine(_work, "blazma.wsb"), policy.ToWsbXml());
        _reader = new OutboxReader(Out, _key, options.OutboxQuotaBytes);
        return Task.CompletedTask;
    }

    public Task BootAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows Sandbox requires Windows.");
        _sandbox = Process.Start(new ProcessStartInfo(WindowsSandboxProvider.SandboxExecutable, $"\"{Path.Combine(_work, "blazma.wsb")}\"")
        {
            UseShellExecute = false,
            CreateNoWindow = false,
        }) ?? throw new InvalidOperationException("Windows Sandbox did not start.");
        logger.LogInformation("Windows Sandbox started for analysis {AnalysisId}", request.AnalysisId);
        return Task.CompletedTask;
    }

    public async Task DeployAgentAsync(CancellationToken cancellationToken)
    {
        // The agent is launched by the sandbox's LogonCommand from the read-only folder; wait for it to say hello.
        var deadline = DateTimeOffset.UtcNow + options.AgentHelloTimeout;
        while (!_reader!.HasHello)
        {
            if (DateTimeOffset.UtcNow > deadline) throw new TimeoutException("The monitoring agent did not start inside the sandbox in time.");
            await Task.Delay(500, cancellationToken).ConfigureAwait(false);
        }
        var hello = _reader.ReadHello() ?? throw new InvalidDataException("The agent's hello message was unreadable.");
        if (hello.ProtocolVersion != Protocol.Version)
            throw new InvalidDataException($"Agent protocol {hello.ProtocolVersion} does not match host protocol {Protocol.Version}.");

        // The agent has read its key. Remove it from the shared folder before the sample can run.
        var config = JsonSerializer.Deserialize(await File.ReadAllBytesAsync(Path.Combine(In, Protocol.SessionFile), cancellationToken).ConfigureAwait(false), ProtocolJson.Default.SessionConfigDto)!;
        config.ChannelKey = null;
        WriteAtomic(Path.Combine(In, Protocol.SessionFile), JsonSerializer.SerializeToUtf8Bytes(config, ProtocolJson.Default.SessionConfigDto));
        logger.LogInformation("Agent {Version} connected (OS {Os})", hello.AgentVersion, hello.OsVersion);
    }

    public async Task TransferSampleAsync(CancellationToken cancellationToken)
    {
        var name = SafeFileName(request.Sample.FileName);
        var destination = Path.Combine(In, Protocol.SampleFolder, name);
        await using (var source = File.OpenRead(request.SamplePath))
        await using (var target = File.Create(destination))
            await source.CopyToAsync(target, cancellationToken).ConfigureAwait(false);

        await using (var check = File.OpenRead(destination))
        {
            var hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(check, cancellationToken).ConfigureAwait(false));
            if (!hash.Equals(request.Sample.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The sample changed on disk after it was analyzed. Start the analysis again.");
        }

        var go = ChannelFiles.CreateGo(request, name, DateTimeOffset.UtcNow);
        WriteAtomic(Path.Combine(In, Protocol.GoFile), JsonSerializer.SerializeToUtf8Bytes(go, ProtocolJson.Default.GoDto));
        _sampleStart = DateTimeOffset.UtcNow;
    }

    public Task ExtendAsync(TimeSpan extra, CancellationToken cancellationToken)
    {
        lock (_controlLock)
        {
            var next = _duration + extra;
            _duration = next > AnalysisOptions.MaxDuration ? AnalysisOptions.MaxDuration : next;
            WriteControl(finishNow: false);
        }
        return Task.CompletedTask;
    }

    public Task FinishNowAsync(CancellationToken cancellationToken)
    {
        lock (_controlLock) WriteControl(finishNow: true);
        return Task.CompletedTask;
    }

    /// <summary>The control file lives in the read-only folder, so a sample cannot forge it.</summary>
    private void WriteControl(bool finishNow) =>
        WriteAtomic(Path.Combine(In, Protocol.ControlFile), ChannelFiles.Serialize(new ControlDto
        {
            Sequence = ++_controlSequence,
            DurationSeconds = (int)_duration.TotalSeconds,
            FinishNow = finishNow,
        }));

    public async IAsyncEnumerable<SessionSignal> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var lastBeat = DateTimeOffset.UtcNow;
        var interrupted = false;

        while (!cancellationToken.IsCancellationRequested)
        {
            var deadline = _sampleStart + _duration + TimeSpan.FromSeconds(30);
            var batch = _reader!.ReadNewEvents(_sampleStart);
            if (batch.Count > 0) yield return new EventsSignal(batch);
            foreach (var shot in _reader.ReadNewScreenshots(ArtifactsFolder)) yield return new ScreenshotSignal(shot);

            if (_reader.ReadHeartbeat() is { } beat && beat.At > lastBeat - TimeSpan.FromHours(1))
            {
                lastBeat = DateTimeOffset.UtcNow;
                yield return new HeartbeatSignal(beat.At);
            }

            if (!interrupted && (DateTimeOffset.UtcNow - lastBeat > options.HeartbeatTimeout || _reader.TamperedFiles > 0 || _reader.QuotaExceeded))
            {
                interrupted = true;
                var reason = _reader.TamperedFiles > 0 ? "Monitoring output failed its integrity check."
                    : _reader.QuotaExceeded ? "The sandbox exceeded the output quota."
                    : "The agent stopped sending heartbeats.";
                yield return new MonitoringInterruptedSignal(reason);
            }

            if (_reader.HasDone || DateTimeOffset.UtcNow > deadline) yield break;
            if (_sandbox is { HasExited: true }) { yield return new MonitoringInterruptedSignal("The sandbox closed during the analysis."); yield break; }

            await Task.Delay(500, cancellationToken).ConfigureAwait(false);
        }
        cancellationToken.ThrowIfCancellationRequested();
    }

    public async Task<CollectedArtifacts> CollectAsync(CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(90);
        while (!_reader!.HasDone && DateTimeOffset.UtcNow < deadline && _sandbox is not { HasExited: true })
            await Task.Delay(500, cancellationToken).ConfigureAwait(false);

        var remaining = _reader.ReadNewEvents(_sampleStart).ToList();
        var done = _reader.ReadDone();
        foreach (var problem in _reader.Problems.Take(20))
        {
            logger.LogWarning("Outbox: {Problem}", problem);
            remaining.Add(new AnalysisEvent
            {
                Sequence = long.MaxValue - remaining.Count,
                Timestamp = DateTimeOffset.UtcNow,
                RelativeTime = DateTimeOffset.UtcNow - _sampleStart,
                Category = EventCategory.System,
                Action = EventAction.AnalysisNote,
                ProcessName = "blazma",
                Source = "host.channel",
                Severity = Severity.Medium,
                Details = new Dictionary<string, string> { [DetailKeys.Reason] = problem },
            });
        }
        var screenshots = _reader.ReadNewScreenshots(ArtifactsFolder);
        var dropped = _reader.ReadDroppedFiles(ArtifactsFolder, options.AgentLimits.MaxDroppedFiles);
        var memory = _reader.ReadMemoryRegions(ArtifactsFolder, Protocol.Limits.MaxMemoryRegions);
        var pcap = _reader.ReadPcap(ArtifactsFolder);
        return new CollectedArtifacts(remaining, _reader.ReadSnapshot(after: false), _reader.ReadSnapshot(after: true), done is not null && done.Error is null)
        {
            Screenshots = screenshots,
            DroppedFiles = dropped,
            MemoryRegions = memory,
            PcapPath = pcap,
        };
    }

    public Task ShutdownAsync(CancellationToken cancellationToken)
    {
        if (_shutdown) return Task.CompletedTask;
        _shutdown = true;
        foreach (var name in WindowsSandboxProvider.SandboxProcessNames)
        {
            foreach (var p in Process.GetProcessesByName(name))
            {
                try { p.Kill(entireProcessTree: true); }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { logger.LogDebug(ex, "Could not stop {Process}", name); }
                finally { p.Dispose(); }
            }
        }
        try { if (Directory.Exists(_work)) Directory.Delete(_work, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { logger.LogWarning(ex, "Could not delete the work folder {Folder}", _work); }
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await ShutdownAsync(CancellationToken.None).ConfigureAwait(false);
        _sandbox?.Dispose();
    }

    private static void WriteAtomic(string path, byte[] bytes) => ChannelFiles.WriteAtomic(path, bytes);

    internal static string SafeFileName(string name) => ChannelFiles.SafeFileName(name);
}
