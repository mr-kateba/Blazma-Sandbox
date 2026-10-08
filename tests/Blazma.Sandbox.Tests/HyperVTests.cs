using System.Text;
using System.Text.RegularExpressions;
using Blazma.Contracts;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Settings;
using Blazma.Sandbox.Processes;
using Blazma.Sandbox.Providers.VirtualMachine;
using Blazma.Sandbox.Providers.VirtualMachine.HyperV;

namespace Blazma.Sandbox.Tests;

/// <summary>Reads PowerShell single-quoted literals the way PowerShell does (doubled quotes of any kind).</summary>
internal static class PsLiteral
{
    private const string Quotes = "'\u2018\u2019\u201A\u201B";

    /// <summary>Parses one literal starting at <paramref name="start"/>; returns the value and the index after it.</summary>
    public static (string Value, int End) Read(string text, int start)
    {
        if (!Quotes.Contains(text[start])) throw new FormatException("not a literal");
        var builder = new StringBuilder();
        for (var i = start + 1; i < text.Length; i++)
        {
            if (Quotes.Contains(text[i]))
            {
                if (i + 1 < text.Length && Quotes.Contains(text[i + 1])) { builder.Append(text[i]); i++; continue; }
                return (builder.ToString(), i + 1);
            }
            builder.Append(text[i]);
        }
        throw new FormatException("unterminated literal");
    }

    /// <summary>The value of <c>$name = '…'</c> or the items of <c>$name = @('…', '…')</c> in a script.</summary>
    public static List<string> Variable(string script, string name)
    {
        var marker = "\n$" + name + " = ";
        var at = script.IndexOf(marker, StringComparison.Ordinal);
        if (at < 0) throw new KeyNotFoundException(name);
        var i = at + marker.Length;
        var values = new List<string>();
        if (script[i] != '@') return [Read(script, i).Value];
        i += 2;
        while (script[i] != ')')
        {
            if (script[i] is ',' or ' ') { i++; continue; }
            var (value, end) = Read(script, i);
            values.Add(value);
            i = end;
        }
        return values;
    }
}

/// <summary>Answers the provider's PowerShell scripts like a Hyper-V host with one Windows guest.</summary>
internal sealed class FakeHyperV
{
    public static readonly Guid VmId = Guid.Parse("11111111-2222-3333-4444-555555555555");
    public static readonly Guid CheckpointId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    public string VmName { get; set; } = "Analysis VM";
    public string CheckpointName { get; set; } = "clean";
    public bool Module { get; set; } = true;
    public bool Access { get; set; } = true;
    public string State { get; set; } = "Off";
    public string[] Adapters { get; set; } = [];
    public string[] CheckpointAdapters { get; set; } = [];
    public FakeGuest Guest { get; } = new();
    public FakeProcessRunner Runner { get; }
    public List<string> Ops { get; } = [];
    public List<string> Scripts { get; } = [];

    public FakeHyperV() => Runner = new FakeProcessRunner(Handle);

    private ProcessResult Handle(ProcessRequest request)
    {
        var script = PowerShellText.DecodeBootstrap(request.StandardInput!)!;
        Scripts.Add(script);
        var op = script[(script.IndexOf(':') + 1)..script.IndexOf('\n')];
        Ops.Add(op);
        var output = new StringBuilder();
        try
        {
            Run(op, script, output);
            output.Append(PowerShellHost.OkMarker).Append('\n');
        }
        catch (InvalidOperationException ex)
        {
            output.Append(PowerShellHost.ErrorMarker).Append(ex.Message).Append('\n');
        }
        return FakeProcessRunner.Ok(output.ToString().Replace("\n", "\r\n"));
    }

    private string Var(string script, string name) => PsLiteral.Variable(script, name).Single();

    private void Run(string op, string script, StringBuilder output)
    {
        switch (op)
        {
            case "availability":
                output.Append($"module={Module}\n");
                if (!Module) return;
                output.Append($"access={Access}\n");
                if (!Access) return;
                var match = Var(script, "vmName") == VmName;
                output.Append($"vms={(match ? 1 : 0)}\n");
                if (!match) return;
                output.Append($"state={State}\ncheckpoints={(Var(script, "checkpointName") == CheckpointName ? 1 : 0)}\n");
                foreach (var a in Adapters) output.Append($"adapter={a}\n");
                return;
            case "inspect":
                if (Var(script, "vmName") != VmName) throw new InvalidOperationException("Found 0 virtual machines with the configured name.");
                if (Var(script, "checkpointName") != CheckpointName) throw new InvalidOperationException("Found 0 checkpoints with the configured name.");
                output.Append($"id={VmId}\ncheckpoint={CheckpointId}\nstate={State}\n");
                return;
            case "restore":
                if (State == "Running") throw new InvalidOperationException("The VM is running.");
                State = "Saved";
                Adapters = CheckpointAdapters;
                foreach (var a in Adapters) output.Append($"adapter={a}\n");
                return;
            case "start": State = "Running"; return;
            case "reset": State = "Saved"; return;
        }

        if (State != "Running") throw new InvalidOperationException("The virtual machine is not running.");
        switch (op)
        {
            case "probe" or "mkdir": return;
            case "copyto":
                var folder = Var(script, "guestFolder");
                foreach (var host in PsLiteral.Variable(script, "hostFiles")) Guest.Copied(FakeGuest.Join(folder, Path.GetFileName(host)), File.ReadAllBytes(host));
                return;
            case "start-agent": Guest.StartAgent(Var(script, "inFolder"), Var(script, "outFolder")); return;
            case "fetch":
                var have = PsLiteral.Variable(script, "have").ToHashSet(StringComparer.OrdinalIgnoreCase);
                var incoming = Var(script, "incoming");
                var pattern = new Regex(Var(script, "pattern"));
                foreach (var (name, content) in Guest.List(Var(script, "guestOut")))
                {
                    output.Append($"file={content.Length}|{name}\n");
                    if (pattern.IsMatch(name) && !have.Contains(name)) File.WriteAllBytes(Path.Combine(incoming, name), content);
                }
                return;
            default: throw new InvalidOperationException("unknown operation " + op);
        }
    }
}

public sealed class HyperVTests : IDisposable
{
    private readonly VmTestBed _bed = new();
    private readonly FakeHyperV _hv = new();

    public void Dispose() => _bed.Dispose();

    private HyperVOptions Options => new()
    {
        WorkRoot = _bed.WorkRoot,
        AgentFolder = _bed.AgentFolder,
        VmName = "Analysis VM",
        Checkpoint = "clean",
        GuestUser = @".\Administrator",
        ProtectedGuestPassword = "enc:" + VmTestBed.Password,
        PowerShellPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        PollInterval = TimeSpan.FromMilliseconds(1),
        AgentHelloTimeout = TimeSpan.FromSeconds(5),
    };

    private HyperVProvider Provider(HyperVOptions? options = null, bool isWindows = true) => new(options ?? Options, _bed.Secrets, _hv.Runner, null, isWindows);

    private async Task<ISandboxSession> SessionAsync(HyperVOptions? options = null, NetworkPolicy network = NetworkPolicy.Disabled) =>
        await Provider(options).CreateSessionAsync(_bed.Request(network), CancellationToken.None);

    private async Task<string[]> FailedChecksAsync(HyperVOptions? options = null, NetworkPolicy network = NetworkPolicy.Disabled)
    {
        var availability = await Provider(options).CheckAvailabilityAsync(network, CancellationToken.None);
        Assert.All(availability.Checks, c => Assert.False(string.IsNullOrWhiteSpace(c.Detail.Ar)));
        return availability.Checks.Where(c => !c.Passed).Select(c => c.Id).ToArray();
    }

    [Fact]
    public async Task A_prepared_vm_is_ready()
    {
        var availability = await Provider().CheckAvailabilityAsync(CancellationToken.None);
        Assert.Equal(ProviderReadiness.Ready, availability.Readiness);
        Assert.Equal(["os", "module", "access", "vm", "checkpoint", "network", "instance", "credentials", "guest-folder", "agent"], availability.Checks.Select(c => c.Id));
    }

    [Fact]
    public async Task Hyper_v_is_not_supported_off_windows()
    {
        var availability = await Provider(isWindows: false).CheckAvailabilityAsync(CancellationToken.None);
        Assert.Equal(ProviderReadiness.NotSupported, availability.Readiness);
        Assert.Empty(_hv.Runner.Calls);
    }

    [Fact]
    public async Task Each_failing_check_is_reported()
    {
        _hv.Module = false;
        Assert.Equal(["module", "access", "vm", "checkpoint", "network", "instance"], await FailedChecksAsync());
        _hv.Module = true;
        _hv.Access = false;
        Assert.Equal(["access", "vm", "checkpoint", "network", "instance"], await FailedChecksAsync());
        _hv.Access = true;
        Assert.Equal(["vm", "checkpoint", "network", "instance"], await FailedChecksAsync(Options with { VmName = "" }));
        Assert.Equal(["vm", "checkpoint", "network", "instance"], await FailedChecksAsync(Options with { VmName = "Missing" }));
        Assert.Equal(["checkpoint"], await FailedChecksAsync(Options with { Checkpoint = "other" }));
        Assert.Equal(["credentials"], await FailedChecksAsync(Options with { ProtectedGuestPassword = null }));
        Assert.Equal(["guest-folder"], await FailedChecksAsync(Options with { GuestWorkFolder = "Blazma" }));
        Assert.Equal(["agent"], await FailedChecksAsync(Options with { AgentFolder = _bed.Root.FullName }));

        _hv.Adapters = ["Network Adapter (Default Switch)"];
        Assert.Equal(["network"], await FailedChecksAsync());
        Assert.Empty(await FailedChecksAsync(network: NetworkPolicy.Enabled));
        Assert.Empty(await FailedChecksAsync(Options with { RequireDisconnectedNetwork = false }));
    }

    [Fact]
    public async Task A_running_vm_is_unavailable()
    {
        _hv.State = "Running";
        var availability = await Provider().CheckAvailabilityAsync(CancellationToken.None);
        Assert.Equal(ProviderReadiness.Unavailable, availability.Readiness);
        Assert.Equal(["instance"], availability.Checks.Where(c => !c.Passed).Select(c => c.Id));
    }

    [Fact]
    public async Task A_full_run_follows_the_lifecycle_and_restores_the_checkpoint()
    {
        var signals = new List<SessionSignal>();
        var collected = await VmTestBed.RunAllAsync(await SessionAsync(), signals: signals);

        Assert.True(collected.AgentCompleted);
        Assert.Single(signals.OfType<EventsSignal>().SelectMany(s => s.Events).Concat(collected.RemainingEvents), e => e.ProcessName == "sample.exe");
        Assert.Contains(collected.RemainingEvents, e => e.Details.Values.Any(v => v.Contains("evil.exe")));

        var expectedStart = new[] { "inspect", "restore", "start", "probe", "mkdir", "copyto", "copyto", "start-agent", "fetch" };
        Assert.Equal(expectedStart, _hv.Ops.Take(expectedStart.Length));
        var afterHello = _hv.Ops.Skip(expectedStart.Length).SkipWhile(o => o == "fetch").Take(3);
        Assert.Equal(["copyto", "copyto", "copyto"], afterHello); // key removal, sample, go
        Assert.Equal("reset", _hv.Ops[^1]);
        Assert.Single(_hv.Ops, o => o == "reset");
        Assert.Equal([null], _hv.Guest.KeysInGuestSessionAtGo);
    }

    [Fact]
    public async Task Scripts_go_to_standard_input_and_the_password_only_to_guest_scripts()
    {
        await VmTestBed.RunAllAsync(await SessionAsync());
        Assert.All(_hv.Runner.Calls, c =>
        {
            Assert.Equal(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", c.FileName);
            Assert.Equal(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"], c.Arguments);
            Assert.DoesNotContain("Pa$$", c.StandardInput, StringComparison.Ordinal); // base64 on the wire
        });
        for (var i = 0; i < _hv.Scripts.Count; i++)
        {
            var script = _hv.Scripts[i];
            var guestOperation = _hv.Ops[i] is not ("inspect" or "restore" or "start" or "reset");
            Assert.Equal(guestOperation, script.Contains("$guestPassword", StringComparison.Ordinal));
            if (guestOperation)
            {
                Assert.Equal([VmTestBed.Password], PsLiteral.Variable(script, "guestPassword"));
                Assert.Equal([@".\Administrator"], PsLiteral.Variable(script, "guestUser"));
            }
            Assert.StartsWith("# blazma:", script, StringComparison.Ordinal);
            Assert.Contains("'BLAZMA-OK'", script, StringComparison.Ordinal);
        }
        var startAgent = _hv.Scripts[_hv.Ops.IndexOf("start-agent")];
        Assert.Equal(["Administrator"], PsLiteral.Variable(startAgent, "taskUser"));
        Assert.Contains("-RunLevel Highest", startAgent, StringComparison.Ordinal);
        Assert.Equal([@"C:\Blazma\0f8fad5bd9cb469fa16570867728950e\in\agent\Blazma.Agent.exe"], PsLiteral.Variable(startAgent, "agent"));
    }

    [Fact]
    public async Task Hostile_names_stay_inside_their_literals()
    {
        const string vmName = "x'; Stop-Computer -Force; 'y\u2019); calc $(whoami) `n";
        const string checkpoint = "\u2018clean\u201B' + $env:USERNAME + '";
        _hv.VmName = vmName;
        _hv.CheckpointName = checkpoint;
        await VmTestBed.RunAllAsync(await SessionAsync(Options with { VmName = vmName, Checkpoint = checkpoint }));

        var inspect = _hv.Scripts[_hv.Ops.IndexOf("inspect")];
        Assert.Equal([vmName], PsLiteral.Variable(inspect, "vmName"));
        Assert.Equal([checkpoint], PsLiteral.Variable(inspect, "checkpointName"));
        Assert.Contains(PowerShellText.Quote(vmName), inspect, StringComparison.Ordinal);
        // After the first script, only the resolved ids are used.
        Assert.All(_hv.Scripts.Where((_, i) => _hv.Ops[i] != "inspect"), s => Assert.DoesNotContain("Stop-Computer", s, StringComparison.Ordinal));
        Assert.Equal("reset", _hv.Ops[^1]);
    }

    [Fact]
    public async Task A_checkpoint_with_a_connected_adapter_is_refused_and_restored()
    {
        _hv.CheckpointAdapters = ["Network Adapter (External)"];
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(async () => await VmTestBed.RunAllAsync(await SessionAsync()));
        Assert.Contains("External", ex.Message);
        Assert.Equal(["inspect", "restore", "reset"], _hv.Ops);
    }

    [Fact]
    public async Task A_connected_adapter_is_accepted_when_the_analysis_enables_the_network()
    {
        _hv.CheckpointAdapters = ["Network Adapter (External)"];
        Assert.True((await VmTestBed.RunAllAsync(await SessionAsync(network: NetworkPolicy.Enabled))).AgentCompleted);
    }

    [Fact]
    public async Task A_running_vm_is_left_alone()
    {
        _hv.State = "Running";
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await VmTestBed.RunAllAsync(await SessionAsync()));
        Assert.Equal(["inspect"], _hv.Ops);
    }

    [Fact]
    public async Task The_checkpoint_is_restored_after_a_failure()
    {
        _hv.Guest.AgentAnswers = false;
        await Assert.ThrowsAsync<TimeoutException>(async () => await VmTestBed.RunAllAsync(await SessionAsync(Options with { AgentHelloTimeout = TimeSpan.FromMilliseconds(50) })));
        Assert.Equal("reset", _hv.Ops[^1]);
    }

    [Fact]
    public async Task The_checkpoint_is_restored_after_cancellation()
    {
        using var cts = new CancellationTokenSource();
        var session = await SessionAsync();
        _hv.Runner.Before = _ => { if (_hv.Guest.KeysInGuestSessionAtGo.Count > 0 && _hv.Ops[^1] == "fetch") cts.Cancel(); };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => VmTestBed.RunAllAsync(session, cts.Token));
        Assert.Equal("reset", _hv.Ops[^1]);
    }

    [Fact]
    public async Task Control_files_carry_an_increasing_sequence()
    {
        var session = await SessionAsync();
        var interactive = Assert.IsAssignableFrom<IInteractiveSession>(session);
        await VmTestBed.RunAllAsync(session, whileRunning: async () =>
        {
            await interactive.ExtendAsync(TimeSpan.FromMinutes(40), CancellationToken.None);
            await interactive.FinishNowAsync(CancellationToken.None);
        });
        Assert.Equal([1, 2], _hv.Guest.Controls.Select(c => c.Sequence));
        Assert.Equal((int)AnalysisOptions.MaxDuration.TotalSeconds, _hv.Guest.Controls[0].DurationSeconds);
        Assert.True(_hv.Guest.Controls[1].FinishNow);
    }

    [Fact]
    public void The_guest_side_name_filter_matches_the_protocol()
    {
        var regex = new Regex(HyperVScripts.AllowedOutboxPattern);
        string[] names =
        [
            Protocol.HelloFile, Protocol.HeartbeatFile, Protocol.DoneFile, Protocol.BaselineFile, Protocol.AfterFile, Protocol.PcapFile,
            Protocol.EventChunkName(1), Protocol.ScreenshotName(12), Protocol.DroppedDataName(3), Protocol.DroppedMetaName(3), Protocol.MemoryDataName(4), Protocol.MemoryMetaName(4),
            "events-1.ndjson", "hello.json.tmp", "HELLO.JSON", "evil.exe", "dropped-0001.exe", "x/hello.json", "hello.json\n", "screen-000001.raw.lnk", "",
        ];
        Assert.All(names, n => Assert.Equal(Protocol.IsAllowedOutboxName(n), regex.IsMatch(n) && !n.EndsWith('\n')));
    }

    [Fact]
    public void Quoting_doubles_every_kind_of_single_quote()
    {
        Assert.Equal("'a''b'", PowerShellText.Quote("a'b"));
        Assert.Equal("'\u2018\u2018x\u2019\u2019'", PowerShellText.Quote("\u2018x\u2019"));
        Assert.Equal("'ab'", PowerShellText.Quote("a\0b"));
        Assert.Equal("@('a', 'b''c')", PowerShellText.QuoteArray(["a", "b'c"]));
        foreach (var hostile in new[] { "'; calc; '", "\u201A\u201B'", "$(calc)", "`\"x\"", "a\nb" })
            Assert.Equal(hostile, PsLiteral.Read(PowerShellText.Quote(hostile), 0).Value);
    }

    [Fact]
    public void Output_markers_decide_success()
    {
        var ok = PowerShellHost.Parse(FakeProcessRunner.Ok("\uFEFFid=1\r\nadapter=a (b=c)\r\nBLAZMA-OK\r\n"));
        Assert.True(ok.Ok);
        Assert.Equal("a (b=c)", ok.Get("adapter"));
        var failed = PowerShellHost.Parse(FakeProcessRunner.Ok("BLAZMA-ERROR: access denied\r\n"));
        Assert.False(failed.Ok);
        Assert.Equal("access denied", failed.Describe());
        Assert.False(PowerShellHost.Parse(FakeProcessRunner.Ok("id=1\r\n")).Ok);
        Assert.False(PowerShellHost.Parse(new ProcessResult(-1, "BLAZMA-OK\n", "") { TimedOut = true }).Ok);
    }

    [Fact]
    public void Options_are_built_from_settings()
    {
        var vm = new VirtualMachineSettings { HyperVVm = "Win11", HyperVCheckpoint = "base", GuestUser = "Administrator", GuestPassword = "enc:x" };
        var options = HyperVOptions.FromSettings(vm, null, "/work", "/agent", stopWhenTreeExits: false);
        Assert.Equal("Win11", options.VmName);
        Assert.Equal("base", options.Checkpoint);
        Assert.False(options.StopWhenTreeExits);
        Assert.Equal("Administrator", HyperVSession.TaskUser(@".\Administrator"));
    }
}
