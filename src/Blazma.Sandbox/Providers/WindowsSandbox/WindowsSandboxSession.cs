using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Blazma.Contracts;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Sandbox.Channel;
using Blazma.Sandbox.Isolation;
using Blazma.Sandbox.Processes;
using Microsoft.Extensions.Logging;

namespace Blazma.Sandbox.Providers.WindowsSandbox;

/// <summary>
/// One Windows Sandbox run. Host side only: it prepares the mapped folders, starts the sandbox
/// with a generated .wsb file, talks to the agent through files, and tears everything down. It
/// never opens, loads or executes the sample on the host.
/// <para>
/// The sandbox is known to be alive from the agent's hello and signed heartbeats, never from the
/// process this session started: from Windows 11 24H2, WindowsSandbox.exe hands the sandbox to
/// the Store app and exits at once. Where <c>wsb.exe</c> exists it identifies the sandbox, tells
/// when the user closed it, starts the agent again if the logon command did not, and stops it.
/// </para>
/// </summary>
internal sealed class WindowsSandboxSession : ISandboxSession, IInteractiveSession
{
    /// <summary>How long collection waits for the agent's done file at most, and without a new heartbeat.</summary>
    private static readonly TimeSpan CollectLimit = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan CollectQuietLimit = TimeSpan.FromSeconds(90);

    /// <summary>The sandbox can hold the mapped folders for a few seconds after it stops.</summary>
    private const int DeleteAttempts = 5;
    private static readonly TimeSpan DeleteRetryDelay = TimeSpan.FromSeconds(2);

    private readonly SandboxSessionRequest _request;
    private readonly WindowsSandboxOptions _options;
    private readonly ILogger _logger;
    private readonly IWindowsSandboxHost _host;
    private readonly WsbCli? _wsb;
    private readonly string _work;
    private readonly byte[] _key = SignedFile.NewKey();
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly SemaphoreSlim _shutdownLock = new(1, 1);
    private readonly object _controlLock = new();
    private readonly HashSet<string> _otherSandboxes = new(StringComparer.OrdinalIgnoreCase);
    private OutboxReader? _reader;
    private DateTimeOffset _sampleStart;
    private TimeSpan _duration;
    private int _controlSequence;
    private bool _launched;
    private string? _sandboxId;
    private int _missedChecks;
    private bool _sandboxClosed;
    private bool _shutdown;
    private bool _diagnosticsCopied;

    public WindowsSandboxSession(SandboxSessionRequest request, WindowsSandboxOptions options, ILogger logger)
        : this(request, options, logger, ProcessRunner.Instance, WindowsSandboxHost.Instance) { }

    internal WindowsSandboxSession(SandboxSessionRequest request, WindowsSandboxOptions options, ILogger logger, IProcessRunner runner, IWindowsSandboxHost host)
    {
        _request = request;
        _options = options;
        _logger = logger;
        _host = host;
        _wsb = host.WsbExecutable is { } wsb ? new WsbCli(runner, wsb) : null;
        _duration = request.Options.Duration;
        _work = Path.Combine(options.WorkRoot, request.AnalysisId.ToString("N"));
    }

    private string In => Path.Combine(_work, "in");
    private string Out => Path.Combine(_work, "out");
    private string Startup => Path.Combine(_work, "startup");
    private string WsbFile => Path.Combine(_work, "blazma.wsb");
    private string ArtifactsFolder => _request.ArtifactsFolder ?? Path.Combine(_work, "artifacts");

    /// <summary>The sandbox id reported by <c>wsb list</c>, once known.</summary>
    internal string? SandboxId => _sandboxId;

    public Task CreateEnvironmentAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.Combine(In, Protocol.AgentFolder));
        Directory.CreateDirectory(Path.Combine(In, Protocol.SampleFolder));
        Directory.CreateDirectory(Out);
        Directory.CreateDirectory(Startup);

        CopyAgent(_options.AgentFolder, Path.Combine(In, Protocol.AgentFolder));

        var config = ChannelFiles.CreateConfig(_request, _key, _options.StopWhenTreeExits, _options.AgentLimits);
        WriteAtomic(Path.Combine(In, Protocol.SessionFile), JsonSerializer.SerializeToUtf8Bytes(config, ProtocolJson.Default.SessionConfigDto));

        var launcher = Encoding.ASCII.GetBytes(IsolationPolicy.LauncherScript());
        WriteAtomic(Path.Combine(In, IsolationPolicy.LauncherName), launcher);
        WriteAtomic(Path.Combine(Startup, IsolationPolicy.LauncherName), launcher);

        var policy = new IsolationPolicy
        {
            HostInFolder = In,
            HostOutFolder = Out,
            HostStartupFolder = Startup,
            Network = _request.Options.Network,
            MemoryMb = _options.MemoryMb,
        };
        File.WriteAllText(WsbFile, policy.ToWsbXml(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        _reader = new OutboxReader(Out, _key, _options.OutboxQuotaBytes);
        Step("environment prepared");
        return Task.CompletedTask;
    }

    /// <summary>
    /// The whole agent folder, subfolders included: a self-contained publish can keep native helpers
    /// in subfolders (TraceEvent's <c>amd64</c>). Links are skipped.
    /// </summary>
    private static void CopyAgent(string source, string target)
    {
        Directory.CreateDirectory(target);
        foreach (var entry in new DirectoryInfo(source).EnumerateFileSystemInfos())
        {
            if (entry.Attributes.HasFlag(FileAttributes.ReparsePoint) || entry.LinkTarget is not null) continue;
            var destination = Path.Combine(target, entry.Name);
            if (entry is DirectoryInfo folder) CopyAgent(folder.FullName, destination);
            else File.Copy(entry.FullName, destination, overwrite: true);
        }
    }

    public async Task BootAsync(CancellationToken cancellationToken)
    {
        var executable = _host.SandboxExecutable
            ?? throw new InvalidOperationException("Windows Sandbox is not installed. Turn on \"Windows Sandbox\" in Windows Features, restart Windows, and start the analysis again.");

        // Windows runs one sandbox at a time; starting a second one fails or joins the first.
        IReadOnlyList<string>? running = null;
        if (_wsb is not null)
        {
            running = await _wsb.ListAsync(cancellationToken).ConfigureAwait(false);
            if (running is null) _logger.LogWarning("wsb list failed; checking for a running sandbox by process name instead");
        }
        if (running is { Count: > 0 } || (running is null && _host.RunningClients().Count > 0))
            throw new InvalidOperationException("Windows Sandbox is already running. Close the Windows Sandbox window (or stop it with \"wsb stop\"), then start the analysis again. Windows runs only one sandbox at a time.");
        if (running is not null) _otherSandboxes.UnionWith(running);

        _launched = true;
        _host.Launch(executable, [WsbFile], code =>
            _logger.LogInformation("{Program} exited with code {Code} after {Seconds:0.0} s; from Windows 11 24H2 it hands the sandbox over and exits, which does not mean the sandbox closed",
                Path.GetFileName(executable), code, _clock.Elapsed.TotalSeconds));
        Step(_wsb is null ? "Windows Sandbox started" : "Windows Sandbox started (wsb.exe available)");
    }

    public async Task DeployAgentAsync(CancellationToken cancellationToken)
    {
        // The agent is started inside the sandbox by the launcher (logon command, Startup folder, or wsb exec); wait for it to say hello.
        var started = DateTimeOffset.UtcNow;
        var deadline = started + _options.AgentHelloTimeout;
        var retryAt = started + _options.AgentStartRetryAfter;
        var nextCheck = started;
        var retried = false;
        while (!_reader!.HasHello)
        {
            var now = DateTimeOffset.UtcNow;
            if (now > deadline)
            {
                var minutes = Math.Max(1, (int)Math.Round(_options.AgentHelloTimeout.TotalMinutes));
                var diagnostics = AgentDiagnostics.Tail(Out);
                throw new TimeoutException(WithDiagnostics(
                    $"The monitoring agent did not start inside Windows Sandbox within {minutes} minutes."
                    + (diagnostics is null ? " Nothing inside the sandbox ran the Blazma launcher: check that the Windows Sandbox window reached the desktop, and that no security product blocks Blazma.Agent.exe." : ""),
                    diagnostics));
            }
            if (_wsb is not null && now >= nextCheck)
            {
                nextCheck = now + _options.SandboxCheckInterval;
                if (await SandboxGoneAsync(cancellationToken).ConfigureAwait(false))
                    throw new InvalidOperationException(WithDiagnostics("Windows Sandbox closed before the monitoring agent started.", AgentDiagnostics.Tail(Out)));
                if (!retried && _sandboxId is not null && now >= retryAt)
                {
                    retried = true;
                    await RetryLauncherAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            await Task.Delay(_options.PollInterval, cancellationToken).ConfigureAwait(false);
        }

        var hello = _reader.ReadHello() ?? throw new InvalidDataException("The agent's hello message was unreadable.");
        if (hello.ProtocolVersion != Protocol.Version)
            throw new InvalidDataException($"Agent protocol {hello.ProtocolVersion} does not match host protocol {Protocol.Version}. Reinstall Blazma so the agent and the application match.");
        if (!hello.Elevated)
            throw new InvalidOperationException(WithDiagnostics("The monitoring agent is not running as an administrator inside Windows Sandbox, so it cannot observe anything.", AgentDiagnostics.Tail(Out)));

        // The agent has read its key. Remove it from the shared folder before the sample can run.
        var config = JsonSerializer.Deserialize(await File.ReadAllBytesAsync(Path.Combine(In, Protocol.SessionFile), cancellationToken).ConfigureAwait(false), ProtocolJson.Default.SessionConfigDto)!;
        config.ChannelKey = null;
        WriteAtomic(Path.Combine(In, Protocol.SessionFile), JsonSerializer.SerializeToUtf8Bytes(config, ProtocolJson.Default.SessionConfigDto));
        _logger.LogInformation("Agent {Version} connected (OS {Os})", Clip(hello.AgentVersion), Clip(hello.OsVersion));
        Step("agent said hello");
    }

    /// <summary>Runs the launcher once more through <c>wsb exec</c>, for sandbox releases that skip the logon command. The launcher ignores a second start.</summary>
    private async Task RetryLauncherAsync(CancellationToken cancellationToken)
    {
        var result = await _wsb!.ExecAsync(_sandboxId!, IsolationPolicy.ExecCommand, cancellationToken).ConfigureAwait(false);
        if (result.Succeeded) Step("no hello yet; started the launcher again with wsb exec");
        else _logger.LogWarning("No hello yet; starting the launcher with wsb exec failed: {Problem}", result.Describe());
    }

    /// <summary>
    /// Asks <c>wsb list</c> whether our sandbox still runs. Learns its id the first time it appears.
    /// True only after two answers in a row without it; a failed command means "unknown", never "closed".
    /// </summary>
    private async Task<bool> SandboxGoneAsync(CancellationToken cancellationToken)
    {
        if (_wsb is null || _sandboxClosed) return _sandboxClosed;
        var ids = await _wsb.ListAsync(cancellationToken).ConfigureAwait(false);
        if (ids is null) return false;
        if (_sandboxId is null)
        {
            var ours = ids.Where(id => !_otherSandboxes.Contains(id)).ToList();
            if (ours.Count == 1)
            {
                _sandboxId = ours[0];
                Step($"sandbox id {_sandboxId}");
            }
            return false;
        }
        if (ids.Contains(_sandboxId, StringComparer.OrdinalIgnoreCase))
        {
            _missedChecks = 0;
            return false;
        }
        if (++_missedChecks < 2) return false;
        _sandboxClosed = true;
        Step("the sandbox is no longer running");
        return true;
    }

    public async Task TransferSampleAsync(CancellationToken cancellationToken)
    {
        var name = SafeFileName(_request.Sample.FileName);
        var destination = Path.Combine(In, Protocol.SampleFolder, name);
        await using (var source = File.OpenRead(_request.SamplePath))
        await using (var target = File.Create(destination))
            await source.CopyToAsync(target, cancellationToken).ConfigureAwait(false);

        await using (var check = File.OpenRead(destination))
        {
            var hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(check, cancellationToken).ConfigureAwait(false));
            if (!hash.Equals(_request.Sample.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The sample changed on disk after it was analyzed. Start the analysis again.");
        }

        var go = ChannelFiles.CreateGo(_request, name, DateTimeOffset.UtcNow);
        WriteAtomic(Path.Combine(In, Protocol.GoFile), JsonSerializer.SerializeToUtf8Bytes(go, ProtocolJson.Default.GoDto));
        _sampleStart = DateTimeOffset.UtcNow;
        Step("sample handed to the agent");
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
        var lastBeatSeen = DateTimeOffset.UtcNow;
        DateTimeOffset? lastBeatAt = null;
        var nextCheck = DateTimeOffset.UtcNow + _options.SandboxCheckInterval;
        var interrupted = false;

        while (!cancellationToken.IsCancellationRequested)
        {
            var deadline = _sampleStart + _duration + TimeSpan.FromSeconds(30);
            var batch = _reader!.ReadNewEvents(_sampleStart);
            if (batch.Count > 0) yield return new EventsSignal(batch);
            foreach (var shot in _reader.ReadNewScreenshots(ArtifactsFolder)) yield return new ScreenshotSignal(shot);

            // The sandbox clock is not trusted; a heartbeat counts when its content changes.
            if (_reader.ReadHeartbeat() is { } beat && beat.At != lastBeatAt)
            {
                lastBeatAt = beat.At;
                lastBeatSeen = DateTimeOffset.UtcNow;
                yield return new HeartbeatSignal(beat.At);
            }

            var reason = OutboxCollection.InterruptionReason(_reader, DateTimeOffset.UtcNow - lastBeatSeen > _options.HeartbeatTimeout);
            if (!interrupted && reason is not null)
            {
                interrupted = true;
                var full = WithDiagnostics(reason, AgentDiagnostics.Tail(Out));
                _logger.LogWarning("Windows Sandbox {AnalysisId}: {Reason}", _request.AnalysisId, full);
                yield return new MonitoringInterruptedSignal(full);
            }

            if (_reader.HasDone || DateTimeOffset.UtcNow > deadline) yield break;

            if (_wsb is not null && DateTimeOffset.UtcNow >= nextCheck)
            {
                nextCheck = DateTimeOffset.UtcNow + _options.SandboxCheckInterval;
                if (await SandboxGoneAsync(cancellationToken).ConfigureAwait(false))
                {
                    yield return new MonitoringInterruptedSignal(WithDiagnostics("Windows Sandbox was closed during the analysis.", AgentDiagnostics.Tail(Out)));
                    yield break;
                }
            }

            await Task.Delay(_options.PollInterval, cancellationToken).ConfigureAwait(false);
        }
        cancellationToken.ThrowIfCancellationRequested();
    }

    public async Task<CollectedArtifacts> CollectAsync(CancellationToken cancellationToken)
    {
        // The agent still takes the final snapshot and copies files out; wait while it is alive.
        var started = DateTimeOffset.UtcNow;
        var lastProgress = started;
        DateTimeOffset? beatAt = null;
        while (!_reader!.HasDone && !_sandboxClosed)
        {
            var now = DateTimeOffset.UtcNow;
            if (_reader.ReadHeartbeat() is { } beat && beat.At != beatAt)
            {
                beatAt = beat.At;
                lastProgress = now;
            }
            if (now - started > CollectLimit || now - lastProgress > CollectQuietLimit) break;
            await Task.Delay(_options.PollInterval, cancellationToken).ConfigureAwait(false);
        }
        Step(_reader.HasDone ? "agent finished" : "agent did not finish");

        var collected = OutboxCollection.Collect(_reader, _sampleStart, ArtifactsFolder, _options.AgentLimits, [], _logger);
        CopyDiagnostics();
        if (collected.AgentCompleted) return collected;

        var notes = new List<string>();
        if (_reader.ReadDone()?.Error is { Length: > 0 } error) notes.Add("The agent reported an error: " + Clip(error));
        if (AgentDiagnostics.Tail(Out) is { } tail) notes.Add(tail);
        if (notes.Count == 0) return collected;
        _logger.LogWarning("Windows Sandbox {AnalysisId}: the agent did not finish normally. {Details}", _request.AnalysisId, string.Join("\n", notes));
        var events = collected.RemainingEvents.ToList();
        foreach (var note in notes) events.Add(OutboxCollection.Note(note, _sampleStart, events.Count));
        return collected with { RemainingEvents = events };
    }

    /// <summary>
    /// Stops the sandbox if this session started it, keeps the agent's diagnostic logs with the
    /// artifacts, and deletes the work folder. Never throws, ignores the caller's cancellation (a
    /// cancelled analysis must still be cleaned up), and does its work only once.
    /// </summary>
    public async Task ShutdownAsync(CancellationToken cancellationToken)
    {
        await _shutdownLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            if (_shutdown) return;
            _shutdown = true;
            CopyDiagnostics();
            if (_launched)
            {
                try { await StopSandboxAsync().ConfigureAwait(false); }
                catch (Exception ex) { _logger.LogError(ex, "Windows Sandbox {AnalysisId}: the sandbox could not be stopped; close its window", _request.AnalysisId); }
            }
            try { await DeleteWorkFolderAsync().ConfigureAwait(false); }
            catch (Exception ex) { _logger.LogError(ex, "Windows Sandbox {AnalysisId}: the work folder {Folder} could not be deleted", _request.AnalysisId, _work); }
            Step("cleaned up");
        }
        finally
        {
            _shutdownLock.Release();
        }
    }

    private async Task StopSandboxAsync()
    {
        if (_wsb is not null)
        {
            try
            {
                if (_sandboxId is null) await SandboxGoneAsync(CancellationToken.None).ConfigureAwait(false);
                if (_sandboxClosed) return;
                if (_sandboxId is not null)
                {
                    var result = await _wsb.StopAsync(_sandboxId, CancellationToken.None).ConfigureAwait(false);
                    if (result.Succeeded)
                    {
                        Step("sandbox stopped with wsb stop");
                        return;
                    }
                    _logger.LogWarning("wsb stop failed ({Problem}); ending the Windows Sandbox processes instead", result.Describe());
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "wsb could not stop the sandbox; ending the Windows Sandbox processes instead");
            }
        }
        _host.KillAll(_logger);
        Step("Windows Sandbox processes ended");
    }

    /// <summary>Retries while a file is still in use; a folder that cannot be deleted is logged, never fatal.</summary>
    private async Task DeleteWorkFolderAsync()
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                if (Directory.Exists(_work)) Directory.Delete(_work, recursive: true);
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (attempt >= DeleteAttempts)
                {
                    _logger.LogWarning(ex, "Could not delete the work folder {Folder}; a file in it is still in use", _work);
                    return;
                }
            }
            await Task.Delay(DeleteRetryDelay).ConfigureAwait(false);
        }
    }

    /// <summary>Keeps cleaned copies of the agent's diagnostic logs with the analysis artifacts.</summary>
    private void CopyDiagnostics()
    {
        if (_diagnosticsCopied) return;
        _diagnosticsCopied = true;
        try
        {
            foreach (var file in AgentDiagnostics.CopyTo(Out, ArtifactsFolder))
                _logger.LogInformation("Agent diagnostic log kept at {Path}", file);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            _logger.LogDebug(ex, "Could not keep the agent's diagnostic logs");
        }
    }

    public async ValueTask DisposeAsync() => await ShutdownAsync(CancellationToken.None).ConfigureAwait(false);

    private void Step(string step) =>
        _logger.LogInformation("Windows Sandbox {AnalysisId}: {Step} after {Seconds:0.0} s", _request.AnalysisId, step, _clock.Elapsed.TotalSeconds);

    private static string WithDiagnostics(string reason, string? diagnostics) =>
        diagnostics is null ? reason : $"{reason}\n\n{diagnostics}";

    private static string Clip(string? text) => AgentDiagnostics.Clean(text is { Length: > 300 } ? text[..300] + "…" : text ?? "?");

    private static void WriteAtomic(string path, byte[] bytes) => ChannelFiles.WriteAtomic(path, bytes);

    internal static string SafeFileName(string name) => ChannelFiles.SafeFileName(name);
}
