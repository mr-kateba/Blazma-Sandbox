using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Blazma.Contracts;
using Blazma.Core.Abstractions;
using Blazma.Sandbox.Channel;
using Blazma.Sandbox.Isolation;
using Blazma.Sandbox.Processes;
using Blazma.Sandbox.Providers.WindowsSandbox;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blazma.Sandbox.Tests;

/// <summary>
/// A simulated Windows Sandbox: WindowsSandbox.exe exits at once (as on Windows 11 24H2), wsb.exe
/// answers list/stop/exec, and an agent follows the protocol in the real host folders.
/// </summary>
internal sealed class FakeSandbox : IWindowsSandboxHost, IDisposable
{
    public const string Id = "6f1c2f0e-6a3b-4c2d-9e8f-0a1b2c3d4e5f";

    private readonly CancellationTokenSource _stop = new();
    private Task? _agent;
    private byte[]? _key;

    public string? SandboxExecutable { get; set; } = @"C:\Windows\System32\WindowsSandbox.exe";
    public string? WsbExecutable { get; set; }
    public List<string> Clients { get; } = [];
    public List<IReadOnlyList<string>> Launches { get; } = [];
    public FakeProcessRunner Runner { get; }

    /// <summary>The logon command works; false simulates the releases that skip it.</summary>
    public bool StartsAgentOnLaunch { get; set; } = true;
    public bool Elevated { get; set; } = true;
    public bool KeepsBeating { get; set; } = true;
    public bool FinishesOnGo { get; set; } = true;
    public bool ThrowsOnKill { get; set; }
    public string? OtherSandbox { get; set; }
    public bool Running { get; set; }
    public int Kills { get; private set; }
    public string? Work { get; private set; }

    public FakeSandbox() => Runner = new FakeProcessRunner(Wsb);

    public void Launch(string fileName, IReadOnlyList<string> arguments, Action<int>? exited = null)
    {
        Launches.Add([fileName, .. arguments]);
        Work = Path.GetDirectoryName(arguments[0]);
        Running = true;
        exited?.Invoke(0);
        if (StartsAgentOnLaunch) StartAgent();
    }

    public IReadOnlyList<string> RunningClients() => Clients;

    public void KillAll(ILogger logger)
    {
        Kills++;
        Running = false;
        if (ThrowsOnKill) throw new IOException("access denied");
    }

    private ProcessResult Wsb(ProcessRequest request)
    {
        switch (request.Arguments[0])
        {
            case "list":
                var lines = new List<string> { "Id                                    Status   Uptime" };
                if (OtherSandbox is not null) lines.Add($"{OtherSandbox}  Running  00:10:00");
                if (Running) lines.Add($"{Id}  Running  00:00:05");
                return FakeProcessRunner.Ok(string.Join("\r\n", lines));
            case "stop":
                Running = false;
                return FakeProcessRunner.Ok();
            case "exec":
                StartAgent();
                return FakeProcessRunner.Ok();
            default:
                return FakeProcessRunner.Fail("unknown command");
        }
    }

    public string Out => Path.Combine(Work!, "out");
    private string In => Path.Combine(Work!, "in");

    public void StartAgent()
    {
        if (_agent is not null) return;
        _agent = Task.Run(AgentAsync);
    }

    private async Task AgentAsync()
    {
        try
        {
            var config = JsonSerializer.Deserialize(await File.ReadAllBytesAsync(Path.Combine(In, Protocol.SessionFile)), ProtocolJson.Default.SessionConfigDto)!;
            _key = Convert.FromBase64String(config.ChannelKey!);
            Write(Protocol.HelloFile, JsonSerializer.SerializeToUtf8Bytes(new HelloDto { ProtocolVersion = Protocol.Version, AgentVersion = "1.0.0", OsVersion = "Windows 11", At = DateTimeOffset.UtcNow, Elevated = Elevated }, ProtocolJson.Default.HelloDto));
            Beat();
            var done = false;
            while (!_stop.IsCancellationRequested)
            {
                if (KeepsBeating) Beat();
                if (!done && FinishesOnGo && File.Exists(Path.Combine(In, Protocol.GoFile)))
                {
                    done = true;
                    var line = JsonSerializer.Serialize(new AgentEventDto { Sequence = 1, RelativeMs = 5, Action = "ProcessStart", ProcessId = 42, ProcessName = "sample.exe", Source = "etw" }, ProtocolJson.Default.AgentEventDto);
                    Write(Protocol.EventChunkName(1), SignedFile.Sign(Encoding.UTF8.GetBytes(line), _key));
                    Write(Protocol.DoneFile, SignedFile.Sign(JsonSerializer.SerializeToUtf8Bytes(new DoneDto { At = DateTimeOffset.UtcNow, Reason = "duration", EventsWritten = 1, SampleStarted = true }, ProtocolJson.Default.DoneDto), _key));
                }
                await Task.Delay(20, _stop.Token);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OperationCanceledException or DirectoryNotFoundException)
        {
            // The host deleted the work folder or the test ended.
        }
    }

    private void Beat() => Write(Protocol.HeartbeatFile, SignedFile.Sign(JsonSerializer.SerializeToUtf8Bytes(new HeartbeatDto { At = DateTimeOffset.UtcNow.AddTicks(Random.Shared.Next()), State = "running" }, ProtocolJson.Default.HeartbeatDto), _key!));

    private void Write(string name, byte[] content) => ChannelFiles.WriteAtomic(Path.Combine(Out, name), content);

    public void Dispose()
    {
        _stop.Cancel();
        try { _agent?.Wait(TimeSpan.FromSeconds(5)); }
        catch (AggregateException) { }
        _stop.Dispose();
    }
}

public sealed class WindowsSandboxTests : IDisposable
{
    private readonly VmTestBed _bed = new();
    private readonly FakeSandbox _sandbox = new();

    public void Dispose()
    {
        _sandbox.Dispose();
        _bed.Dispose();
    }

    private WindowsSandboxOptions Options => new()
    {
        WorkRoot = _bed.WorkRoot,
        AgentFolder = _bed.AgentFolder,
        PollInterval = TimeSpan.FromMilliseconds(20),
        SandboxCheckInterval = TimeSpan.FromMilliseconds(20),
        AgentHelloTimeout = TimeSpan.FromSeconds(10),
        AgentStartRetryAfter = TimeSpan.FromSeconds(10),
        HeartbeatTimeout = TimeSpan.FromSeconds(10),
    };

    private WindowsSandboxSession Session(WindowsSandboxOptions? options = null, SandboxSessionRequest? request = null) =>
        new(request ?? _bed.Request(), options ?? Options, NullLogger.Instance, _sandbox.Runner, _sandbox);

    private List<IReadOnlyList<string>> WsbCalls(string command) =>
        _sandbox.Runner.Calls.Where(c => c.Arguments.Count > 0 && c.Arguments[0] == command).Select(c => c.Arguments).ToList();

    [Fact]
    public async Task The_launcher_exiting_at_once_does_not_end_the_analysis()
    {
        var signals = new List<SessionSignal>();
        var collected = await VmTestBed.RunAllAsync(Session(), signals: signals);

        Assert.True(collected.AgentCompleted);
        Assert.Contains(collected.RemainingEvents.Concat(signals.OfType<EventsSignal>().SelectMany(s => s.Events)), e => e.ProcessName == "sample.exe");
        Assert.DoesNotContain(signals, s => s is MonitoringInterruptedSignal);
        var launch = Assert.Single(_sandbox.Launches);
        Assert.EndsWith("blazma.wsb", launch[1], StringComparison.Ordinal);
        Assert.Equal(1, _sandbox.Kills); // no wsb.exe: the processes are ended
        Assert.False(Directory.Exists(_sandbox.Work));
    }

    [Fact]
    public async Task With_wsb_the_sandbox_is_identified_and_stopped_by_id()
    {
        _sandbox.WsbExecutable = @"C:\Users\u\AppData\Local\Microsoft\WindowsApps\wsb.exe";
        var session = Session();
        await VmTestBed.RunAllAsync(session);

        Assert.Equal(FakeSandbox.Id, session.SandboxId);
        Assert.Equal(["stop", "--id", FakeSandbox.Id], Assert.Single(WsbCalls("stop")));
        Assert.Equal(0, _sandbox.Kills);
        Assert.Empty(WsbCalls("exec"));
    }

    [Fact]
    public async Task A_sandbox_that_is_already_running_is_reported_and_left_alone()
    {
        _sandbox.WsbExecutable = "wsb.exe";
        _sandbox.OtherSandbox = "11111111-2222-3333-4444-555555555555";
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => VmTestBed.RunAllAsync(Session()));

        Assert.Contains("already running", error.Message, StringComparison.Ordinal);
        Assert.Empty(_sandbox.Launches);
        Assert.Empty(WsbCalls("stop"));
        Assert.Equal(0, _sandbox.Kills);
    }

    [Fact]
    public async Task Without_wsb_an_open_sandbox_window_is_reported()
    {
        _sandbox.Clients.Add("WindowsSandboxRemoteSession");
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => VmTestBed.RunAllAsync(Session()));
        Assert.Contains("already running", error.Message, StringComparison.Ordinal);
        Assert.Equal(0, _sandbox.Kills);
    }

    [Fact]
    public async Task When_the_logon_command_is_skipped_wsb_exec_starts_the_launcher()
    {
        _sandbox.WsbExecutable = "wsb.exe";
        _sandbox.StartsAgentOnLaunch = false;
        var collected = await VmTestBed.RunAllAsync(Session(Options with { AgentStartRetryAfter = TimeSpan.FromMilliseconds(100) }));

        Assert.True(collected.AgentCompleted);
        var exec = Assert.Single(WsbCalls("exec"));
        Assert.Equal(["exec", "--id", FakeSandbox.Id, "-c", IsolationPolicy.ExecCommand, "-r", "ExistingLogin"], exec);
    }

    [Fact]
    public async Task A_silent_agent_fails_with_its_own_diagnostics()
    {
        _sandbox.StartsAgentOnLaunch = false;
        var artifacts = Path.Combine(_bed.Root.FullName, "artifacts");
        var session = Session(Options with { AgentHelloTimeout = TimeSpan.FromMilliseconds(300) }, _bed.Request() with { ArtifactsFolder = artifacts });
        await session.CreateEnvironmentAsync(CancellationToken.None);
        await session.BootAsync(CancellationToken.None);
        File.WriteAllText(Path.Combine(_sandbox.Out, AgentDiagnostics.StartLogFile), "[logon] starting the agent\r\n");
        File.WriteAllText(Path.Combine(_sandbox.Out, AgentDiagnostics.LogFile),
            string.Join("\n", Enumerable.Range(1, 40).Select(i => $"line {i}")) + "\nETW: access denied \u001b[31mred\u001b[0m \u202Eexe.txt\n");

        var error = await Assert.ThrowsAsync<TimeoutException>(() => session.DeployAgentAsync(CancellationToken.None));
        await session.ShutdownAsync(CancellationToken.None);

        Assert.Contains("did not start inside Windows Sandbox", error.Message, StringComparison.Ordinal);
        Assert.Contains("[logon] starting the agent", error.Message, StringComparison.Ordinal);
        Assert.Contains("ETW: access denied [31mred[0m exe.txt", error.Message, StringComparison.Ordinal);
        Assert.Contains("line 40", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("line 15\n", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain('\u001b', error.Message);
        Assert.DoesNotContain('\u202E', error.Message);
        Assert.Contains("line 1\n", File.ReadAllText(Path.Combine(artifacts, AgentDiagnostics.LogFile)));
        Assert.False(Directory.Exists(_sandbox.Work));
    }

    [Fact]
    public async Task Nothing_started_inside_the_sandbox_is_said_plainly()
    {
        _sandbox.StartsAgentOnLaunch = false;
        var error = await Assert.ThrowsAsync<TimeoutException>(() => VmTestBed.RunAllAsync(Session(Options with { AgentHelloTimeout = TimeSpan.FromMilliseconds(200) })));
        Assert.Contains("Nothing inside the sandbox ran the Blazma launcher", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_agent_without_administrator_rights_stops_the_analysis_early()
    {
        _sandbox.Elevated = false;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => VmTestBed.RunAllAsync(Session()));
        Assert.Contains("not running as an administrator", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Closing_the_sandbox_window_before_hello_fails_fast()
    {
        _sandbox.WsbExecutable = "wsb.exe";
        _sandbox.StartsAgentOnLaunch = false;
        var session = Session();
        await session.CreateEnvironmentAsync(CancellationToken.None);
        await session.BootAsync(CancellationToken.None);
        var deploy = session.DeployAgentAsync(CancellationToken.None);
        while (session.SandboxId is null) await Task.Delay(10);
        _sandbox.Running = false;

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => deploy);
        await session.ShutdownAsync(CancellationToken.None);
        Assert.Contains("closed before the monitoring agent started", error.Message, StringComparison.Ordinal);
        Assert.Empty(WsbCalls("stop"));
        Assert.Equal(0, _sandbox.Kills);
    }

    [Fact]
    public async Task Closing_the_sandbox_window_during_the_run_is_reported()
    {
        _sandbox.WsbExecutable = "wsb.exe";
        _sandbox.FinishesOnGo = false;
        var signals = new List<SessionSignal>();
        var collected = await VmTestBed.RunAllAsync(Session(), whileRunning: () => { _sandbox.Running = false; return Task.CompletedTask; }, signals: signals);

        Assert.Contains(signals.OfType<MonitoringInterruptedSignal>(), s => s.Reason.Contains("closed during the analysis", StringComparison.Ordinal));
        Assert.False(collected.AgentCompleted);
    }

    [Fact]
    public async Task A_heartbeat_file_that_stops_changing_counts_as_silence()
    {
        _sandbox.KeepsBeating = false;
        _sandbox.FinishesOnGo = false;
        var session = Session(Options with { HeartbeatTimeout = TimeSpan.FromMilliseconds(300) }, _bed.Request() with { Options = _bed.Request().Options with { Duration = TimeSpan.FromSeconds(1) } });
        var signals = new List<SessionSignal>();
        await session.CreateEnvironmentAsync(CancellationToken.None);
        await session.BootAsync(CancellationToken.None);
        await session.DeployAgentAsync(CancellationToken.None);
        await session.TransferSampleAsync(CancellationToken.None);
        File.WriteAllText(Path.Combine(_sandbox.Out, AgentDiagnostics.LogFile), "ETW session lost\n");
        await foreach (var signal in session.ExecuteAsync(CancellationToken.None))
        {
            signals.Add(signal);
            if (signal is MonitoringInterruptedSignal) break;
        }
        await session.ShutdownAsync(CancellationToken.None);

        var interrupted = Assert.Single(signals.OfType<MonitoringInterruptedSignal>());
        Assert.Contains("stopped sending heartbeats", interrupted.Reason, StringComparison.Ordinal);
        Assert.Contains("ETW session lost", interrupted.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Shutdown_never_throws_and_falls_back_when_wsb_stop_fails()
    {
        var failingStop = new FakeSandbox { WsbExecutable = "wsb.exe", ThrowsOnKill = true };
        var runner = new FakeProcessRunner(r => r.Arguments[0] == "stop" ? FakeProcessRunner.Fail("Access is denied.") : r.Arguments[0] == "list" ? FakeProcessRunner.Ok(failingStop.Running ? FakeSandbox.Id : "") : FakeProcessRunner.Ok());
        try
        {
            var session = new WindowsSandboxSession(_bed.Request(), Options, NullLogger.Instance, runner, failingStop);
            await VmTestBed.RunAllAsync(session);
            Assert.Single(runner.Calls, c => c.Arguments[0] == "stop");
            Assert.Equal(1, failingStop.Kills);
            Assert.False(Directory.Exists(failingStop.Work));
            await session.ShutdownAsync(CancellationToken.None);
            Assert.Equal(1, failingStop.Kills);
        }
        finally
        {
            failingStop.Dispose();
        }
    }

    [Fact]
    public void Diagnostic_logs_are_not_reported_as_unexpected_output()
    {
        var folder = Directory.CreateDirectory(Path.Combine(_bed.Root.FullName, "out")).FullName;
        var reader = new OutboxReader(folder, SignedFile.NewKey(), 1_000_000);
        File.WriteAllText(Path.Combine(folder, AgentDiagnostics.LogFile), "x");
        File.WriteAllText(Path.Combine(folder, AgentDiagnostics.StartLogFile), "x");
        File.WriteAllText(Path.Combine(folder, "evil.exe"), "MZ");
        reader.ReadNewEvents(DateTimeOffset.UtcNow);
        Assert.Equal(["Unexpected file in the output folder was ignored: evil.exe"], reader.Problems);
    }

    [Fact]
    public void Diagnostic_logs_are_read_as_untrusted_text()
    {
        var folder = _bed.Root.FullName;
        Assert.Null(AgentDiagnostics.Read(folder, AgentDiagnostics.LogFile));
        Assert.Null(AgentDiagnostics.Read(folder, "../secret.txt"));

        var big = new string('a', AgentDiagnostics.MaxBytes) + "\nlast line\n";
        File.WriteAllText(Path.Combine(folder, AgentDiagnostics.LogFile), big);
        var text = AgentDiagnostics.Read(folder, AgentDiagnostics.LogFile)!;
        Assert.True(text.Length <= AgentDiagnostics.MaxBytes);
        Assert.EndsWith("last line\n", text, StringComparison.Ordinal);

        File.WriteAllText(Path.Combine(_bed.Root.FullName, "secret.txt"), "host secret");
        File.Delete(Path.Combine(folder, AgentDiagnostics.LogFile));
        File.CreateSymbolicLink(Path.Combine(folder, AgentDiagnostics.LogFile), Path.Combine(_bed.Root.FullName, "secret.txt"));
        Assert.Null(AgentDiagnostics.Read(folder, AgentDiagnostics.LogFile));
        Assert.Null(AgentDiagnostics.Tail(folder));

        Assert.Equal("a\tb\nc\nd\u200Fe", AgentDiagnostics.Clean("a\tb\r\nc\rd\u0007\u202E\u2066\u200Fe"));
    }

    [Fact]
    public async Task A_wsb_that_cannot_start_is_treated_as_absent()
    {
        var runner = new FakeProcessRunner(_ => throw new System.ComponentModel.Win32Exception("The file cannot be accessed by the system."));
        var session = new WindowsSandboxSession(_bed.Request(), Options, NullLogger.Instance, runner, new FakeSandboxWithWsb(_sandbox));
        var collected = await VmTestBed.RunAllAsync(session);
        Assert.True(collected.AgentCompleted);
        Assert.Null(session.SandboxId);
        Assert.Equal(1, _sandbox.Kills);
    }

    /// <summary>The same sandbox, but reporting a wsb.exe that does not work.</summary>
    private sealed class FakeSandboxWithWsb(FakeSandbox inner) : IWindowsSandboxHost
    {
        public string? SandboxExecutable => inner.SandboxExecutable;
        public string? WsbExecutable => "wsb.exe";
        public void Launch(string fileName, IReadOnlyList<string> arguments, Action<int>? exited = null) => inner.Launch(fileName, arguments, exited);
        public IReadOnlyList<string> RunningClients() => inner.RunningClients();
        public void KillAll(ILogger logger) => inner.KillAll(logger);
    }

    [Theory]
    [InlineData("", new string[0])]
    [InlineData("No running Windows Sandbox environments.", new string[0])]
    [InlineData("6f1c2f0e-6a3b-4c2d-9e8f-0a1b2c3d4e5f\r\n", new[] { "6f1c2f0e-6a3b-4c2d-9e8f-0a1b2c3d4e5f" })]
    [InlineData("Id   Status  Uptime\r\n6F1C2F0E-6A3B-4C2D-9E8F-0A1B2C3D4E5F  Running  00:01:00\r\n11111111-2222-3333-4444-555555555555  Stopped  00:00:00", new[] { "6F1C2F0E-6A3B-4C2D-9E8F-0A1B2C3D4E5F" })]
    [InlineData("""[{"Id":"6f1c2f0e-6a3b-4c2d-9e8f-0a1b2c3d4e5f","Status":"Running"},{"Id":"11111111-2222-3333-4444-555555555555","Status":"Stopped"}]""", new[] { "6f1c2f0e-6a3b-4c2d-9e8f-0a1b2c3d4e5f" })]
    [InlineData("""{"WindowsSandboxEnvironments":[{"Id":"6f1c2f0e-6a3b-4c2d-9e8f-0a1b2c3d4e5f","Uptime":"00:00:10"}]}""", new[] { "6f1c2f0e-6a3b-4c2d-9e8f-0a1b2c3d4e5f" })]
    public void Wsb_list_output_is_read_defensively(string output, string[] expected) =>
        Assert.Equal(expected, WsbCli.ParseRunningIds(output));

    [Fact]
    public async Task Provider_reports_an_open_sandbox_window_but_not_a_lingering_server()
    {
        var provider = new WindowsSandboxProvider(Options, null, _sandbox.Runner, _sandbox);
        Assert.Equal(OperatingSystem.IsWindows() ? ProviderReadiness.Ready : ProviderReadiness.NotSupported, (await provider.CheckAvailabilityAsync(CancellationToken.None)).Readiness);
        if (OperatingSystem.IsWindows())
        {
            _sandbox.Clients.Add("WindowsSandboxRemoteSession");
            Assert.Equal(ProviderReadiness.Unavailable, (await provider.CheckAvailabilityAsync(CancellationToken.None)).Readiness);
        }
        Assert.DoesNotContain("WindowsSandboxServer", WindowsSandboxHost.ClientProcessNames);
        Assert.Contains("WindowsSandboxRemoteSession", WindowsSandboxHost.ClientProcessNames);
        Assert.Contains("WindowsSandboxClient", WindowsSandboxHost.ClientProcessNames);
    }

    [Fact]
    public async Task The_generated_files_start_the_agent_from_every_entry_point()
    {
        Directory.CreateDirectory(Path.Combine(_bed.AgentFolder, "amd64"));
        File.WriteAllText(Path.Combine(_bed.AgentFolder, "amd64", "helper.dll"), "native");
        var session = Session();
        await session.CreateEnvironmentAsync(CancellationToken.None);
        var work = Path.Combine(_bed.WorkRoot, _bed.Request().AnalysisId.ToString("N"));
        var wsb = XElement.Parse(File.ReadAllText(Path.Combine(work, "blazma.wsb")));

        var folders = wsb.Element("MappedFolders")!.Elements("MappedFolder").ToList();
        Assert.Equal(3, folders.Count);
        var startup = folders.Single(f => f.Element("SandboxFolder")!.Value == IsolationPolicy.SandboxStartup);
        Assert.Equal(Path.Combine(work, "startup"), startup.Element("HostFolder")!.Value);
        Assert.Equal("true", startup.Element("ReadOnly")!.Value);
        Assert.Single(folders, f => f.Element("ReadOnly")!.Value == "false");
        Assert.Equal(@"cmd.exe /c C:\Blazma\in\blazma-agent.cmd logon", wsb.Element("LogonCommand")!.Element("Command")!.Value);

        Assert.Equal("native", File.ReadAllText(Path.Combine(work, "in", "agent", "amd64", "helper.dll")));
        Assert.True(File.Exists(Path.Combine(work, "in", "agent", "Blazma.Agent.exe")));

        var launcher = File.ReadAllBytes(Path.Combine(work, "in", IsolationPolicy.LauncherName));
        Assert.Equal(launcher, File.ReadAllBytes(Path.Combine(work, "startup", IsolationPolicy.LauncherName)));
        Assert.Equal(new[] { IsolationPolicy.LauncherName }, Directory.GetFiles(Path.Combine(work, "startup")).Select(Path.GetFileName));
        await session.ShutdownAsync(CancellationToken.None);
    }

    [Fact]
    public void The_launcher_runs_the_agent_once_elevated_and_records_its_output()
    {
        var script = IsolationPolicy.LauncherScript();
        var lines = script.Split("\r\n");
        Assert.DoesNotContain('\n', script.Replace("\r\n", "", StringComparison.Ordinal));
        Assert.All(script, c => Assert.True(c < 128));
        Assert.Contains("fltmc >nul 2>&1 ||", script, StringComparison.Ordinal);
        Assert.Contains(@"mkdir ""%ProgramData%\Blazma.agent-started"" 2>nul ||", script, StringComparison.Ordinal);
        Assert.Contains(@"""C:\Blazma\in\agent\Blazma.Agent.exe"" ""C:\Blazma\in"" ""C:\Blazma\out"" >>""%LOG%"" 2>&1", script, StringComparison.Ordinal);
        Assert.Contains(@"set ""LOG=C:\Blazma\out\agent-start.txt""", script, StringComparison.Ordinal);
        // The elevation check comes before the lock, so an unelevated start cannot take the agent's place.
        Assert.True(Array.FindIndex(lines, l => l.Contains("fltmc", StringComparison.Ordinal)) < Array.FindIndex(lines, l => l.StartsWith("mkdir", StringComparison.Ordinal)));
        Assert.Equal(@"cmd.exe /c start /min cmd.exe /c C:\Blazma\in\blazma-agent.cmd exec", IsolationPolicy.ExecCommand);
    }
}
