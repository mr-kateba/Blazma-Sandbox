using Blazma.Contracts;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Settings;
using Blazma.Sandbox.Processes;
using Blazma.Sandbox.Providers.VirtualMachine;
using Blazma.Sandbox.Providers.VirtualMachine.VirtualBox;

namespace Blazma.Sandbox.Tests;

/// <summary>Answers VBoxManage command lines like a VirtualBox host with one Windows guest.</summary>
internal sealed class FakeVirtualBox
{
    public const string VmId = "11111111-2222-3333-4444-555555555555";
    public const string SnapshotId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    public List<(string Name, string Id)> Vms { get; } = [("Analysis VM", VmId), ("Other \"quoted\" VM", "99999999-2222-3333-4444-555555555555")];
    public Dictionary<string, string> Snapshots { get; } = new() { ["clean"] = SnapshotId };
    public string State { get; set; } = "poweroff";
    public string[] Nics { get; set; } = ["none", "null"];
    public string[] SnapshotNics { get; set; } = ["none", "null"];
    public FakeGuest Guest { get; } = new();
    public FakeProcessRunner Runner { get; }
    public List<string> ListingOutputs { get; } = [];

    public FakeVirtualBox() => Runner = new FakeProcessRunner(Handle);

    private ProcessResult Handle(ProcessRequest request)
    {
        var a = request.Arguments;
        switch (a[0])
        {
            case "list": return FakeProcessRunner.Ok(string.Join("\n", Vms.Select(v => $"\"{v.Name}\" {{{v.Id}}}")));
            case "showvminfo":
                return FakeProcessRunner.Ok($"name=\"x\"\nVMState=\"{State}\"\n" + string.Join("\n", Nics.Select((n, i) => $"nic{i + 1}=\"{n}\"")) + "\nnic8=\"none\"\n");
            case "snapshot" when a[2] == "list":
                return Snapshots.Count == 0 ? FakeProcessRunner.Fail("This machine does not have any snapshots")
                    : FakeProcessRunner.Ok(string.Join("\n", Snapshots.Select((s, i) => $"SnapshotName{(i == 0 ? "" : "-" + i)}=\"{Escape(s.Key)}\"\nSnapshotUUID{(i == 0 ? "" : "-" + i)}=\"{s.Value}\"")) + "\nCurrentSnapshotName=\"clean\"");
            case "snapshot" when a[2] == "restore":
                if (State is "running") return FakeProcessRunner.Fail("machine is locked");
                Nics = SnapshotNics;
                State = "saved";
                return FakeProcessRunner.Ok();
            case "startvm": State = "running"; return FakeProcessRunner.Ok();
            case "controlvm": State = "poweroff"; return FakeProcessRunner.Ok();
            case "guestproperty": return FakeProcessRunner.Ok(State == "running" ? "Value: 7.1.4r165100" : "No value set!");
            case "guestcontrol": return GuestControl(a[2], a.Skip(5).ToList());
            default: return FakeProcessRunner.Fail("unknown command");
        }
    }

    /// <summary>VBoxManage escapes backslashes and quotes in machine-readable values.</summary>
    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");

    private ProcessResult GuestControl(string command, List<string> rest)
    {
        if (State != "running") return FakeProcessRunner.Fail("VM is not running");
        switch (command)
        {
            case "run" when rest.Contains("-EncodedCommand"):
                var script = System.Text.Encoding.Unicode.GetString(Convert.FromBase64String(rest[^1]));
                var folder = script.Split('\'')[3];
                var listing = string.Join("\r\n", Guest.List(folder).Select(f => $"{f.Content.Length}|{f.Name}"));
                ListingOutputs.Add(listing);
                return FakeProcessRunner.Ok(listing);
            case "run": return FakeProcessRunner.Ok();
            case "mkdir": return FakeProcessRunner.Ok();
            case "rm": Guest.Files.Remove(rest[^1]); return FakeProcessRunner.Ok();
            case "copyto":
                var target = rest[0]["--target-directory=".Length..];
                foreach (var host in rest.Skip(1)) Guest.Copied(FakeGuest.Join(target, Path.GetFileName(host)), File.ReadAllBytes(host));
                return FakeProcessRunner.Ok();
            case "start":
                Guest.StartAgent(rest[^2], rest[^1]);
                return FakeProcessRunner.Ok();
            case "copyfrom":
                var destination = rest[0]["--target-directory=".Length..];
                foreach (var source in rest.Skip(1))
                {
                    if (!Guest.Files.TryGetValue(source, out var content)) return FakeProcessRunner.Fail("not found");
                    File.WriteAllBytes(Path.Combine(destination, source[(source.LastIndexOf('\\') + 1)..]), content);
                }
                return FakeProcessRunner.Ok();
            default: return FakeProcessRunner.Fail("unknown guestcontrol command");
        }
    }

    /// <summary>"snapshot restore", "startvm", "guestcontrol copyto"…: the command shape without values.</summary>
    public List<string> Ops() => Runner.Calls.Select(c => c.Arguments[0] switch
    {
        "snapshot" or "guestproperty" => c.Arguments[0] + " " + (c.Arguments[0] == "snapshot" ? c.Arguments[2] : c.Arguments[1]),
        "guestcontrol" => "guestcontrol " + c.Arguments[2] + (c.Arguments.Contains("-EncodedCommand") ? " list" : ""),
        _ => c.Arguments[0],
    }).ToList();
}

public sealed class VirtualBoxTests : IDisposable
{
    private readonly VmTestBed _bed = new();
    private readonly FakeVirtualBox _vbox = new();
    private readonly string _vboxManage;

    public VirtualBoxTests()
    {
        _vboxManage = Path.Combine(_bed.Root.FullName, "VBoxManage.exe");
        File.WriteAllText(_vboxManage, "");
    }

    public void Dispose() => _bed.Dispose();

    private VirtualBoxOptions Options => new()
    {
        WorkRoot = _bed.WorkRoot,
        AgentFolder = _bed.AgentFolder,
        VBoxManagePath = _vboxManage,
        VmName = "Analysis VM",
        Snapshot = "clean",
        GuestUser = "Administrator",
        ProtectedGuestPassword = "enc:" + VmTestBed.Password,
        PollInterval = TimeSpan.FromMilliseconds(1),
        AgentHelloTimeout = TimeSpan.FromSeconds(5),
        BootTimeout = TimeSpan.FromSeconds(5),
    };

    private VirtualBoxProvider Provider(VirtualBoxOptions? options = null) => new(options ?? Options, _bed.Secrets, _vbox.Runner);

    private async Task<ISandboxSession> SessionAsync(VirtualBoxOptions? options = null, NetworkPolicy network = NetworkPolicy.Disabled, bool interactive = false) =>
        await Provider(options).CreateSessionAsync(_bed.Request(network, interactive), CancellationToken.None);

    private async Task<string[]> FailedChecksAsync(VirtualBoxOptions? options = null, NetworkPolicy network = NetworkPolicy.Disabled)
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
        Assert.Equal(["vboxmanage", "vm", "snapshot", "network", "instance", "credentials", "guest-folder", "agent"], availability.Checks.Select(c => c.Id));
        Assert.Equal(["list", "snapshot list", "showvminfo"], _vbox.Ops());
    }

    [Fact]
    public async Task Each_failing_check_is_reported()
    {
        Assert.Equal(["vboxmanage", "vm", "snapshot", "network", "instance"], await FailedChecksAsync(Options with { VBoxManagePath = Path.Combine(_bed.Root.FullName, "missing.exe") }));
        Assert.Equal(["vm", "snapshot", "network", "instance"], await FailedChecksAsync(Options with { VmName = "" }));
        Assert.Equal(["vm", "snapshot", "network", "instance"], await FailedChecksAsync(Options with { VmName = "No such VM" }));
        Assert.Equal(["snapshot"], await FailedChecksAsync(Options with { Snapshot = "other" }));
        Assert.Equal(["credentials"], await FailedChecksAsync(Options with { GuestUser = " " }));
        Assert.Equal(["credentials"], await FailedChecksAsync(Options with { ProtectedGuestPassword = "unreadable" }));
        Assert.Equal(["guest-folder"], await FailedChecksAsync(Options with { GuestWorkFolder = @"C:\Blazma\..\Windows" }));
        Assert.Equal(["guest-folder"], await FailedChecksAsync(Options with { GuestWorkFolder = @"C:\x'; calc" }));
        Assert.Equal(["agent"], await FailedChecksAsync(Options with { AgentFolder = _bed.Root.FullName }));
    }

    [Fact]
    public async Task A_connected_adapter_fails_unless_the_network_is_enabled_or_allowed()
    {
        _vbox.Nics = ["none", "nat"];
        Assert.Equal(["network"], await FailedChecksAsync());
        Assert.Equal(["network"], await FailedChecksAsync(network: NetworkPolicy.Simulated));
        Assert.Empty(await FailedChecksAsync(network: NetworkPolicy.Enabled));
        Assert.Empty(await FailedChecksAsync(Options with { RequireDisconnectedNetwork = false }));
    }

    [Fact]
    public async Task A_running_vm_is_unavailable()
    {
        _vbox.State = "running";
        var availability = await Provider().CheckAvailabilityAsync(CancellationToken.None);
        Assert.Equal(ProviderReadiness.Unavailable, availability.Readiness);
        Assert.Equal(["instance"], availability.Checks.Where(c => !c.Passed).Select(c => c.Id));
    }

    [Fact]
    public async Task A_full_run_follows_the_lifecycle_and_restores_the_snapshot()
    {
        var signals = new List<SessionSignal>();
        var collected = await VmTestBed.RunAllAsync(await SessionAsync(), signals: signals);

        Assert.True(collected.AgentCompleted);
        Assert.Single(signals.OfType<EventsSignal>().SelectMany(s => s.Events).Concat(collected.RemainingEvents), e => e.ProcessName == "sample.exe");
        Assert.Contains(signals, s => s is HeartbeatSignal);
        Assert.DoesNotContain(signals, s => s is MonitoringInterruptedSignal);
        Assert.Contains(collected.RemainingEvents, e => e.Details.Values.Any(v => v.Contains("evil.exe")));

        var ops = _vbox.Ops();
        var expectedStart = new[]
        {
            "list", "snapshot list", "showvminfo",                  // inspect, read-only
            "snapshot restore", "showvminfo", "startvm",            // boot: network checked after the restore
            "guestproperty get", "guestcontrol run",                // guest additions and logon probe
            "guestcontrol mkdir", "guestcontrol copyto", "guestcontrol copyto", "guestcontrol start",
        };
        Assert.Equal(expectedStart, ops.Take(expectedStart.Length));
        var restoreKey = ops.IndexOf("guestcontrol rm");
        Assert.True(restoreKey > expectedStart.Length, "session.json is replaced after the hello");
        Assert.Equal(["guestcontrol rm", "guestcontrol copyto", "guestcontrol copyto", "guestcontrol copyto"], ops.Skip(restoreKey).Take(4)); // key removal, sample, go
        Assert.Equal(["controlvm", "showvminfo", "snapshot restore"], ops.TakeLast(3));
        Assert.Equal(1, ops.Count(o => o == "controlvm"));
        Assert.Equal("saved", _vbox.State); // restored from an online snapshot, not running
    }

    [Fact]
    public async Task The_channel_key_is_removed_from_the_guest_after_the_hello()
    {
        await VmTestBed.RunAllAsync(await SessionAsync());
        Assert.Equal([null], _vbox.Guest.KeysInGuestSessionAtGo);
        var firstSessionCopy = _vbox.Runner.Calls.First(c => c.Arguments.Count > 6 && c.Arguments[2] == "copyto" && c.Arguments[^1].EndsWith(Protocol.SessionFile, StringComparison.Ordinal));
        Assert.NotNull(firstSessionCopy);
    }

    [Fact]
    public async Task The_password_never_appears_in_arguments_and_its_file_is_deleted()
    {
        await VmTestBed.RunAllAsync(await SessionAsync());
        var guestCalls = _vbox.Runner.Calls.Where(c => c.Arguments[0] == "guestcontrol").ToList();
        Assert.NotEmpty(guestCalls);
        Assert.All(_vbox.Runner.Calls, c => Assert.DoesNotContain(c.Arguments, a => a.Contains("Pa$$", StringComparison.Ordinal)));
        Assert.All(_vbox.Runner.Calls, c => Assert.Null(c.StandardInput));
        Assert.All(guestCalls, c =>
        {
            Assert.Equal(VmTestBed.Password, c.PasswordFileContent);
            Assert.False(File.Exists(c.PasswordFile));
            Assert.Equal(["guestcontrol", FakeVirtualBox.VmId, c.Arguments[2], "--username=Administrator", "--passwordfile=" + c.PasswordFile], c.Arguments.Take(5));
        });
    }

    [Fact]
    public async Task Exact_arguments_for_the_main_commands()
    {
        await VmTestBed.RunAllAsync(await SessionAsync(Options with { Display = VmDisplay.Headless }));
        var calls = _vbox.Runner.Calls.Select(c => c.Arguments).ToList();
        Assert.Contains(calls, a => a.SequenceEqual(["snapshot", FakeVirtualBox.VmId, "restore", FakeVirtualBox.SnapshotId]));
        Assert.Contains(calls, a => a.SequenceEqual(["startvm", FakeVirtualBox.VmId, "--type", "headless"]));
        Assert.Contains(calls, a => a.SequenceEqual(["controlvm", FakeVirtualBox.VmId, "poweroff"]));
        Assert.Contains(calls, a => a.SequenceEqual(["guestproperty", "get", FakeVirtualBox.VmId, "/VirtualBox/GuestAdd/Version"]));

        const string root = @"C:\Blazma\0f8fad5bd9cb469fa16570867728950e";
        var start = calls.Single(a => a[0] == "guestcontrol" && a[2] == "start");
        Assert.Equal(["--exe=" + root + @"\in\agent\Blazma.Agent.exe", "--", root + @"\in\agent\Blazma.Agent.exe", root + @"\in", root + @"\out"], start.Skip(5));
        var mkdir = calls.Single(a => a[0] == "guestcontrol" && a[2] == "mkdir");
        Assert.Equal(["--parents", root + @"\in\agent", root + @"\in\sample", root + @"\out"], mkdir.Skip(5));
        var copyFrom = calls.First(a => a[0] == "guestcontrol" && a[2] == "copyfrom");
        Assert.StartsWith("--target-directory=", copyFrom[5], StringComparison.Ordinal);
        Assert.All(copyFrom.Skip(6), source => Assert.StartsWith(root + @"\out\", source, StringComparison.Ordinal));
        Assert.DoesNotContain(calls.Where(a => a[0] == "guestcontrol" && a[2] == "copyfrom").SelectMany(a => a.Skip(6)), a => a.EndsWith(".tmp", StringComparison.Ordinal) || a.EndsWith("evil.exe", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Interactive_analyses_always_get_a_window()
    {
        await VmTestBed.RunAllAsync(await SessionAsync(Options with { Display = VmDisplay.Headless }, interactive: true));
        Assert.Contains(_vbox.Runner.Calls, c => c.Arguments.SequenceEqual(["startvm", FakeVirtualBox.VmId, "--type", "gui"]));
    }

    [Fact]
    public async Task Hostile_vm_and_snapshot_names_are_only_used_to_find_the_uuid()
    {
        const string vmName = "--help\" & calc.exe & '";
        const string snapshot = "-x'; Remove-Item C:\\ -Recurse; '";
        _vbox.Vms.Add((vmName, "77777777-2222-3333-4444-555555555555"));
        _vbox.Snapshots.Clear();
        _vbox.Snapshots[snapshot] = FakeVirtualBox.SnapshotId;

        await VmTestBed.RunAllAsync(await SessionAsync(Options with { VmName = vmName, Snapshot = snapshot }));
        Assert.All(_vbox.Runner.Calls, c => Assert.DoesNotContain(c.Arguments, a => a.Contains("calc", StringComparison.Ordinal) || a.Contains("Remove-Item", StringComparison.Ordinal)));
        Assert.Contains(_vbox.Runner.Calls, c => c.Arguments.SequenceEqual(["startvm", "77777777-2222-3333-4444-555555555555", "--type", "gui"]));
    }

    [Fact]
    public async Task A_snapshot_with_a_connected_adapter_is_refused_and_restored()
    {
        _vbox.SnapshotNics = ["bridged", "none"];
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(async () => await VmTestBed.RunAllAsync(await SessionAsync()));
        Assert.Contains("adapter 1", ex.Message);
        Assert.DoesNotContain("startvm", _vbox.Ops());
        Assert.Equal("snapshot restore", _vbox.Ops()[^1]);
        Assert.Equal(2, _vbox.Ops().Count(o => o == "snapshot restore"));
    }

    [Fact]
    public async Task A_connected_adapter_is_accepted_when_the_analysis_enables_the_network()
    {
        _vbox.SnapshotNics = ["nat"];
        var collected = await VmTestBed.RunAllAsync(await SessionAsync(network: NetworkPolicy.Enabled));
        Assert.True(collected.AgentCompleted);
    }

    [Fact]
    public async Task A_vm_that_is_already_running_is_left_alone()
    {
        _vbox.State = "running";
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await VmTestBed.RunAllAsync(await SessionAsync()));
        Assert.Equal(["list", "snapshot list", "showvminfo"], _vbox.Ops());
        Assert.Equal("running", _vbox.State);
    }

    [Fact]
    public async Task The_snapshot_is_restored_after_a_failure()
    {
        _vbox.Guest.AgentAnswers = false;
        await Assert.ThrowsAsync<TimeoutException>(async () => await VmTestBed.RunAllAsync(await SessionAsync(Options with { AgentHelloTimeout = TimeSpan.FromMilliseconds(50) })));
        Assert.Equal(["controlvm", "showvminfo", "snapshot restore"], _vbox.Ops().TakeLast(3));
        Assert.False(Directory.Exists(Path.Combine(_bed.WorkRoot, "0f8fad5bd9cb469fa16570867728950e")));
    }

    [Fact]
    public async Task An_agent_without_administrator_rights_is_refused()
    {
        _vbox.Guest.Elevated = false;
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(async () => await VmTestBed.RunAllAsync(await SessionAsync()));
        Assert.Contains("Administrator", ex.Message);
        Assert.Equal("snapshot restore", _vbox.Ops()[^1]);
    }

    [Fact]
    public async Task The_snapshot_is_restored_after_cancellation()
    {
        using var cts = new CancellationTokenSource();
        var session = await SessionAsync();
        var sampleSent = false;
        _vbox.Runner.Before = r =>
        {
            if (r.Arguments.Count > 2 && r.Arguments[2] == "copyto" && r.Arguments[^1].EndsWith(Protocol.GoFile, StringComparison.Ordinal)) sampleSent = true;
            else if (sampleSent && r.Arguments.Contains("-EncodedCommand")) cts.Cancel();
        };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => VmTestBed.RunAllAsync(session, cts.Token));
        Assert.Equal(["controlvm", "showvminfo", "snapshot restore"], _vbox.Ops().TakeLast(3));
    }

    [Fact]
    public async Task Shutdown_is_idempotent()
    {
        var session = await SessionAsync();
        await VmTestBed.RunAllAsync(session);
        var count = _vbox.Runner.Calls.Count;
        await session.ShutdownAsync(CancellationToken.None);
        await session.DisposeAsync();
        Assert.Equal(count, _vbox.Runner.Calls.Count);
    }

    [Fact]
    public async Task Control_files_carry_an_increasing_sequence()
    {
        var session = await SessionAsync();
        var interactive = Assert.IsAssignableFrom<IInteractiveSession>(session);
        await VmTestBed.RunAllAsync(session, whileRunning: async () =>
        {
            await interactive.ExtendAsync(TimeSpan.FromSeconds(30), CancellationToken.None);
            await interactive.ExtendAsync(TimeSpan.FromSeconds(30), CancellationToken.None);
            await interactive.FinishNowAsync(CancellationToken.None);
        });
        Assert.Equal([1, 2, 3], _vbox.Guest.Controls.Select(c => c.Sequence));
        Assert.Equal([60, 90, 90], _vbox.Guest.Controls.Select(c => c.DurationSeconds));
        Assert.Equal([false, false, true], _vbox.Guest.Controls.Select(c => c.FinishNow));
    }

    [Fact]
    public async Task A_missing_password_stops_session_creation()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() => Provider(Options with { ProtectedGuestPassword = null }).CreateSessionAsync(_bed.Request(), CancellationToken.None));
        Assert.Empty(_vbox.Runner.Calls);
    }

    [Fact]
    public void Output_parsers_handle_quotes_escapes_and_attachment_types()
    {
        var vms = VBoxManage.ParseVmList("\"My \"odd\" VM\" {11111111-2222-3333-4444-555555555555}\r\n<inaccessible> {x}\n");
        Assert.Equal([new VBoxMachine("My \"odd\" VM", "11111111-2222-3333-4444-555555555555")], vms);

        var values = VBoxManage.ParseMachineReadable("name=\"a \\\"b\\\" \\\\ c\"\r\n\"SATA-0-0\"=\"disk.vdi\"\nnic1=\"nat\"\nnic2=\"null\"\nnic3=\"none\"\nnic10=\"intnet\"\nVMState=\"saved\"\n");
        Assert.Equal("a \"b\" \\ c", values["name"]);
        Assert.Equal("disk.vdi", values["SATA-0-0"]);
        Assert.Equal(["adapter 1: nat", "adapter 10: intnet"], VBoxManage.ConnectedAdapters(values));
        Assert.False(VBoxManage.IsRunning(values));

        var snapshots = VBoxManage.ParseMachineReadable("SnapshotName=\"clean\"\nSnapshotUUID=\"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\"\nSnapshotName-1=\"clean\"\nSnapshotUUID-1=\"bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee\"\nCurrentSnapshotName=\"clean\"\n");
        Assert.Equal(2, VBoxManage.FindSnapshots(snapshots, "clean").Count);

        Assert.Equal([new Channel.GuestFile("hello.json", 12)], VBoxManage.ParseListing("12|hello.json\r\nxx|bad\n-1|neg\n5|a|b\n"));
    }

    [Fact]
    public void Options_are_built_from_settings()
    {
        var vm = new VirtualMachineSettings { VirtualBoxVm = "Win11", VirtualBoxSnapshot = "base", VirtualBoxDisplay = VmDisplay.Headless, GuestUser = "Administrator", GuestPassword = "enc:x", GuestWorkFolder = @"D:\Work", RequireDisconnectedNetwork = false };
        var options = VirtualBoxOptions.FromSettings(vm, new AdvancedSettings { AgentHeartbeatTimeoutSeconds = 20, OutboxQuotaBytes = 1000 }, "/work", "/agent");
        Assert.Equal("Win11", options.VmName);
        Assert.Equal("base", options.Snapshot);
        Assert.Equal(VmDisplay.Headless, options.Display);
        Assert.Equal(@"D:\Work", options.GuestWorkFolder);
        Assert.False(options.RequireDisconnectedNetwork);
        Assert.Equal(TimeSpan.FromSeconds(20), options.HeartbeatTimeout);
        Assert.Equal(1000, options.OutboxQuotaBytes);
        Assert.DoesNotContain("enc:x", options.ToString());
        Assert.Equal(VirtualBoxOptions.DefaultVBoxManagePath, options.ResolvedVBoxManagePath);
    }

    [Fact]
    public void Guest_work_folders_are_validated()
    {
        Assert.True(GuestPaths.IsValidWorkFolder(@"C:\Blazma"));
        Assert.True(GuestPaths.IsValidWorkFolder(@"D:\Analysis Work (1)\تحليل\"));
        Assert.False(GuestPaths.IsValidWorkFolder(@"C:\"));
        Assert.False(GuestPaths.IsValidWorkFolder(@"C:\a\..\b"));
        Assert.False(GuestPaths.IsValidWorkFolder(@"\\server\share"));
        Assert.False(GuestPaths.IsValidWorkFolder(@"C:\a""b"));
        Assert.False(GuestPaths.IsValidWorkFolder(@"C:\%TEMP%"));
        Assert.False(GuestPaths.IsValidWorkFolder(@"C:\a&b"));
    }
}
