using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using Blazma.Contracts;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Sandbox.Channel;
using Microsoft.Extensions.Logging;

namespace Blazma.Sandbox.Providers.VirtualMachine;

/// <summary>
/// One analysis in a user-prepared virtual machine. Host side only. The protocol is the same as
/// in Windows Sandbox (<c>in</c> written by the host, <c>out</c> written by the agent, signed
/// output, key removed after hello), but the folders live inside the guest and are copied with
/// the hypervisor's guest tools. Providers implement the guest operations; this class owns the
/// order, the channel and the guarantee that the VM is powered off and restored afterwards.
/// </summary>
internal abstract class VirtualMachineSession : ISandboxSession, IInteractiveSession
{
    private readonly SandboxSessionRequest _request;
    private readonly VirtualMachineOptions _options;
    private readonly string _work;
    private readonly byte[] _key = SignedFile.NewKey();
    private readonly SemaphoreSlim _controlLock = new(1, 1);
    private readonly SemaphoreSlim _shutdownLock = new(1, 1);
    private OutboxReader? _reader;
    private GuestOutboxSync? _sync;
    private DateTimeOffset _sampleStart;
    private TimeSpan _duration;
    private int _controlSequence;
    private int _syncFailures;
    private bool _machineTouched;
    private bool _machineReset;

    protected VirtualMachineSession(SandboxSessionRequest request, VirtualMachineOptions options, string guestPassword, ILogger logger)
    {
        _request = request;
        _options = options;
        _duration = request.Options.Duration;
        _work = Path.Combine(options.WorkRoot, request.AnalysisId.ToString("N"));
        GuestPassword = guestPassword;
        Logger = logger;
        Guest = GuestLayout.For(options.GuestWorkFolder, request.AnalysisId);
    }

    protected ILogger Logger { get; }
    protected SandboxSessionRequest Request => _request;
    protected GuestLayout Guest { get; }
    protected string GuestPassword { get; }

    /// <summary>Holds short-lived secret files; inside the per-analysis work folder, which is deleted afterwards.</summary>
    protected string SecretsFolder => Path.Combine(_work, "secrets");

    internal string HostIn => Path.Combine(_work, "in");
    internal string Staging => Path.Combine(_work, "out");
    internal string Incoming => Path.Combine(_work, "incoming");
    internal int ControlSequence => _controlSequence;
    private string ArtifactsFolder => _request.ArtifactsFolder ?? Path.Combine(_work, "artifacts");

    /// <summary>True when the VM may have a connected adapter for this analysis.</summary>
    protected bool NetworkAllowed => !_options.RequireDisconnectedNetwork || _request.Options.Network == NetworkPolicy.Enabled;

    // Guest operations, in the order they are used.

    /// <summary>Finds the VM and its snapshot without changing anything; throws when the VM is already running.</summary>
    protected abstract Task InspectMachineAsync(CancellationToken cancellationToken);
    protected abstract Task RestoreSnapshotAsync(CancellationToken cancellationToken);

    /// <summary>Connected network adapters as configured right now (after the restore), described for the user.</summary>
    protected abstract Task<IReadOnlyList<string>> GetConnectedAdaptersAsync(CancellationToken cancellationToken);
    protected abstract Task StartMachineAsync(CancellationToken cancellationToken);

    /// <summary>Waits until the guest accepts commands with the configured credentials.</summary>
    protected abstract Task WaitForGuestAsync(CancellationToken cancellationToken);
    protected abstract Task CreateGuestFoldersAsync(IReadOnlyList<string> guestFolders, CancellationToken cancellationToken);
    protected abstract Task CopyToGuestAsync(IReadOnlyList<string> hostFiles, string guestFolder, CancellationToken cancellationToken);

    /// <summary>Replaces a guest file that already exists (session.json without the key, control.json).</summary>
    protected virtual Task ReplaceGuestFileAsync(string hostFile, string guestFolder, CancellationToken cancellationToken) =>
        CopyToGuestAsync([hostFile], guestFolder, cancellationToken);

    /// <summary>Starts <see cref="GuestLayout.AgentExecutable"/> elevated and detached with the guest in and out folders.</summary>
    protected abstract Task StartAgentAsync(CancellationToken cancellationToken);

    /// <summary>Copies new guest output into the empty <paramref name="incomingFolder"/>. Returns false when the copy failed.</summary>
    protected abstract Task<bool> FetchOutboxAsync(GuestOutboxSync sync, string incomingFolder, CancellationToken cancellationToken);

    /// <summary>Powers the VM off and restores the snapshot. Called with no cancellation; must tolerate a VM that is already off.</summary>
    protected abstract Task ResetMachineAsync(CancellationToken cancellationToken);

    public async Task CreateEnvironmentAsync(CancellationToken cancellationToken)
    {
        if (!GuestPaths.IsValidWorkFolder(_options.GuestWorkFolder))
            throw new InvalidOperationException("The working folder inside the virtual machine is not valid. Use a simple folder such as C:\\Blazma.");

        Directory.CreateDirectory(Path.Combine(HostIn, Protocol.SampleFolder));
        Directory.CreateDirectory(Staging);
        Directory.CreateDirectory(Incoming);

        var config = ChannelFiles.CreateConfig(_request, _key, _options.StopWhenTreeExits, _options.AgentLimits);
        ChannelFiles.WriteAtomic(Path.Combine(HostIn, Protocol.SessionFile), JsonSerializer.SerializeToUtf8Bytes(config, ProtocolJson.Default.SessionConfigDto));
        _reader = new OutboxReader(Staging, _key, _options.OutboxQuotaBytes);
        _sync = new GuestOutboxSync(Staging, _options.OutboxQuotaBytes);

        await InspectMachineAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task BootAsync(CancellationToken cancellationToken)
    {
        // From here on the VM is ours: whatever happens, shutdown powers it off and restores the snapshot.
        _machineTouched = true;
        await RestoreSnapshotAsync(cancellationToken).ConfigureAwait(false);

        // Checked after the restore: the snapshot's own adapter settings are the ones that will run.
        var connected = await GetConnectedAdaptersAsync(cancellationToken).ConfigureAwait(false);
        if (connected.Count > 0 && !NetworkAllowed)
            throw new InvalidOperationException(
                $"The virtual machine has a connected network adapter ({string.Join(", ", connected)}). Disconnect every adapter in the snapshot, or enable network access for this analysis.");

        await StartMachineAsync(cancellationToken).ConfigureAwait(false);
        await WaitForGuestAsync(cancellationToken).ConfigureAwait(false);
        Logger.LogInformation("Virtual machine started for analysis {AnalysisId}", _request.AnalysisId);
    }

    public async Task DeployAgentAsync(CancellationToken cancellationToken)
    {
        await CreateGuestFoldersAsync([Guest.Agent, Guest.Sample, Guest.Out], cancellationToken).ConfigureAwait(false);
        var agentFiles = Directory.EnumerateFiles(_options.AgentFolder).Order(StringComparer.Ordinal).ToList();
        await CopyToGuestAsync(agentFiles, Guest.Agent, cancellationToken).ConfigureAwait(false);
        await CopyToGuestAsync([Path.Combine(HostIn, Protocol.SessionFile)], Guest.In, cancellationToken).ConfigureAwait(false);
        await StartAgentAsync(cancellationToken).ConfigureAwait(false);

        var deadline = DateTimeOffset.UtcNow + _options.AgentHelloTimeout;
        while (true)
        {
            await SyncOnceAsync(cancellationToken).ConfigureAwait(false);
            if (_reader!.HasHello) break;
            if (DateTimeOffset.UtcNow > deadline)
                throw new TimeoutException("The monitoring agent did not start inside the virtual machine in time. Check that the guest account is signed in and is an administrator (see docs/VIRTUAL-MACHINES.md).");
            await Task.Delay(_options.PollInterval, cancellationToken).ConfigureAwait(false);
        }

        var hello = _reader.ReadHello() ?? throw new InvalidDataException("The agent's hello message was unreadable.");
        if (hello.ProtocolVersion != Protocol.Version)
            throw new InvalidDataException($"Agent protocol {hello.ProtocolVersion} does not match host protocol {Protocol.Version}.");
        if (!hello.Elevated)
            throw new InvalidOperationException("The agent is not running as an administrator inside the virtual machine, so it cannot observe anything. Use the built-in Administrator account or turn off UAC in the analysis VM (see docs/VIRTUAL-MACHINES.md).");

        // The agent has read its key. Remove it from the guest before the sample can run.
        var sessionFile = Path.Combine(HostIn, Protocol.SessionFile);
        var config = JsonSerializer.Deserialize(await File.ReadAllBytesAsync(sessionFile, cancellationToken).ConfigureAwait(false), ProtocolJson.Default.SessionConfigDto)!;
        config.ChannelKey = null;
        ChannelFiles.WriteAtomic(sessionFile, JsonSerializer.SerializeToUtf8Bytes(config, ProtocolJson.Default.SessionConfigDto));
        await ReplaceGuestFileAsync(sessionFile, Guest.In, cancellationToken).ConfigureAwait(false);
        Logger.LogInformation("Agent {Version} connected (OS {Os})", hello.AgentVersion, hello.OsVersion);
    }

    public async Task TransferSampleAsync(CancellationToken cancellationToken)
    {
        var name = ChannelFiles.SafeFileName(_request.Sample.FileName);
        var destination = Path.Combine(HostIn, Protocol.SampleFolder, name);
        await using (var source = File.OpenRead(_request.SamplePath))
        await using (var target = File.Create(destination))
            await source.CopyToAsync(target, cancellationToken).ConfigureAwait(false);

        await using (var check = File.OpenRead(destination))
        {
            var hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(check, cancellationToken).ConfigureAwait(false));
            if (!hash.Equals(_request.Sample.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The sample changed on disk after it was analyzed. Start the analysis again.");
        }
        await CopyToGuestAsync([destination], Guest.Sample, cancellationToken).ConfigureAwait(false);

        // The go signal goes in a separate copy, after the sample is complete in the guest.
        var go = ChannelFiles.CreateGo(_request, name, DateTimeOffset.UtcNow);
        var goFile = Path.Combine(HostIn, Protocol.GoFile);
        ChannelFiles.WriteAtomic(goFile, JsonSerializer.SerializeToUtf8Bytes(go, ProtocolJson.Default.GoDto));
        await CopyToGuestAsync([goFile], Guest.In, cancellationToken).ConfigureAwait(false);
        _sampleStart = DateTimeOffset.UtcNow;
    }

    public async Task ExtendAsync(TimeSpan extra, CancellationToken cancellationToken)
    {
        await _controlLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var next = _duration + extra;
            _duration = next > AnalysisOptions.MaxDuration ? AnalysisOptions.MaxDuration : next;
            await SendControlAsync(finishNow: false, cancellationToken).ConfigureAwait(false);
        }
        finally { _controlLock.Release(); }
    }

    public async Task FinishNowAsync(CancellationToken cancellationToken)
    {
        await _controlLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { await SendControlAsync(finishNow: true, cancellationToken).ConfigureAwait(false); }
        finally { _controlLock.Release(); }
    }

    /// <summary>The control file goes to the guest's <c>in</c> folder with a higher sequence each time.</summary>
    private async Task SendControlAsync(bool finishNow, CancellationToken cancellationToken)
    {
        var path = Path.Combine(HostIn, Protocol.ControlFile);
        ChannelFiles.WriteAtomic(path, ChannelFiles.Serialize(new ControlDto
        {
            Sequence = ++_controlSequence,
            DurationSeconds = (int)_duration.TotalSeconds,
            FinishNow = finishNow,
        }));
        await ReplaceGuestFileAsync(path, Guest.In, cancellationToken).ConfigureAwait(false);
    }

    public async IAsyncEnumerable<SessionSignal> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var lastBeatSeen = DateTimeOffset.UtcNow;
        DateTimeOffset? lastBeatAt = null;
        var interrupted = false;

        while (!cancellationToken.IsCancellationRequested)
        {
            var deadline = _sampleStart + _duration + TimeSpan.FromSeconds(30);
            var synced = await SyncOnceAsync(cancellationToken).ConfigureAwait(false) >= 0;

            var batch = _reader!.ReadNewEvents(_sampleStart);
            if (batch.Count > 0) yield return new EventsSignal(batch);
            foreach (var shot in _reader.ReadNewScreenshots(ArtifactsFolder)) yield return new ScreenshotSignal(shot);

            // The guest clock is not trusted; a heartbeat counts when its content changes.
            if (_reader.ReadHeartbeat() is { } beat && beat.At != lastBeatAt)
            {
                lastBeatAt = beat.At;
                lastBeatSeen = DateTimeOffset.UtcNow;
                yield return new HeartbeatSignal(beat.At);
            }

            var reason = OutboxCollection.InterruptionReason(_reader, synced && DateTimeOffset.UtcNow - lastBeatSeen > _options.HeartbeatTimeout, _sync!.QuotaExceeded);
            if (!interrupted && reason is not null)
            {
                interrupted = true;
                yield return new MonitoringInterruptedSignal(reason);
            }

            if (_syncFailures >= _options.MaxSyncFailures)
            {
                yield return new MonitoringInterruptedSignal("Lost contact with the virtual machine during the analysis.");
                yield break;
            }
            if (_reader.HasDone || DateTimeOffset.UtcNow > deadline) yield break;

            await Task.Delay(_options.PollInterval, cancellationToken).ConfigureAwait(false);
        }
        cancellationToken.ThrowIfCancellationRequested();
    }

    public async Task<CollectedArtifacts> CollectAsync(CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(90);
        while (!_reader!.HasDone && DateTimeOffset.UtcNow < deadline && _syncFailures < _options.MaxSyncFailures)
        {
            await SyncOnceAsync(cancellationToken).ConfigureAwait(false);
            if (_reader.HasDone) break;
            await Task.Delay(_options.PollInterval, cancellationToken).ConfigureAwait(false);
        }

        // Drain whatever is still in the guest (each round fetches a bounded number of files).
        for (var round = 0; round < 50 && _syncFailures < _options.MaxSyncFailures; round++)
            if (await SyncOnceAsync(cancellationToken).ConfigureAwait(false) <= 0) break;

        return OutboxCollection.Collect(_reader, _sampleStart, ArtifactsFolder, _options.AgentLimits, _sync!.Problems, Logger);
    }

    /// <summary>One round: fetch into the empty incoming folder, then import. Returns files imported, or -1 when the copy failed.</summary>
    private async Task<int> SyncOnceAsync(CancellationToken cancellationToken)
    {
        ClearIncoming();
        bool fetched;
        try
        {
            fetched = await FetchOutboxAsync(_sync!, Incoming, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Logger.LogDebug(ex, "Copying the guest output failed");
            fetched = false;
        }
        if (!fetched)
        {
            _syncFailures++;
            ClearIncoming();
            return -1;
        }
        _syncFailures = 0;
        return _sync!.Import(Incoming);
    }

    private void ClearIncoming()
    {
        try
        {
            if (Directory.Exists(Incoming)) Directory.Delete(Incoming, recursive: true);
            Directory.CreateDirectory(Incoming);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Logger.LogDebug(ex, "Could not clear {Folder}", Incoming); }
    }

    /// <summary>
    /// Powers the VM off and restores the snapshot if this session ever started it, then deletes the
    /// host work folder. Ignores the caller's cancellation (a cancelled analysis must still be cleaned
    /// up). Safe to call repeatedly: a failed reset is retried on the next call.
    /// </summary>
    public async Task ShutdownAsync(CancellationToken cancellationToken)
    {
        await _shutdownLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            if (_machineTouched && !_machineReset)
            {
                try
                {
                    await ResetMachineAsync(CancellationToken.None).ConfigureAwait(false);
                    _machineReset = true;
                    Logger.LogInformation("Virtual machine powered off and restored for analysis {AnalysisId}", _request.AnalysisId);
                }
                catch (Exception ex)
                {
                    Logger.LogError(ex, "The virtual machine could not be powered off and restored after analysis {AnalysisId}; it is restored again before the next analysis", _request.AnalysisId);
                }
            }
            try { if (Directory.Exists(_work)) Directory.Delete(_work, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Logger.LogWarning(ex, "Could not delete the work folder {Folder}", _work); }
        }
        finally { _shutdownLock.Release(); }
    }

    public async ValueTask DisposeAsync()
    {
        await ShutdownAsync(CancellationToken.None).ConfigureAwait(false);
    }
}
