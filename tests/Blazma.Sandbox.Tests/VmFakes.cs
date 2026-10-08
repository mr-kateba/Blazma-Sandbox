using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Blazma.Contracts;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Samples;
using Blazma.Sandbox.Processes;

namespace Blazma.Sandbox.Tests;

/// <summary>One recorded program start, with what a <c>--passwordfile=</c> held at the time of the call.</summary>
internal sealed record Invocation(string FileName, IReadOnlyList<string> Arguments, string? StandardInput, string? PasswordFile, string? PasswordFileContent);

/// <summary>Records every invocation and answers with a scripted result.</summary>
internal sealed class FakeProcessRunner(Func<ProcessRequest, ProcessResult> respond) : IProcessRunner
{
    private readonly object _lock = new();
    public List<Invocation> Calls { get; } = [];

    /// <summary>Called before answering; lets a test cancel at a chosen point.</summary>
    public Action<ProcessRequest>? Before { get; set; }

    public Task<ProcessResult> RunAsync(ProcessRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var passwordFile = request.Arguments.FirstOrDefault(a => a.StartsWith("--passwordfile=", StringComparison.Ordinal))?["--passwordfile=".Length..];
        var content = passwordFile is not null && File.Exists(passwordFile) ? File.ReadAllText(passwordFile) : null;
        lock (_lock) Calls.Add(new Invocation(request.FileName, request.Arguments.ToList(), request.StandardInput, passwordFile, content));
        Before?.Invoke(request);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(respond(request));
    }

    public static ProcessResult Ok(string stdout = "") => new(0, stdout, string.Empty);
    public static ProcessResult Fail(string stderr = "failed") => new(1, string.Empty, stderr);
}

internal sealed class FakeSecrets : ISecretProtector
{
    public bool IsStrong => true;
    public string Protect(string plaintext) => "enc:" + plaintext;
    public string? Unprotect(string stored) => stored.StartsWith("enc:", StringComparison.Ordinal) ? stored[4..] : null;
}

/// <summary>
/// A simulated Windows guest: a file system keyed by guest path and an agent that follows the
/// protocol (hello after start, events and done after the go signal).
/// </summary>
internal sealed class FakeGuest
{
    public Dictionary<string, byte[]> Files { get; } = new(StringComparer.OrdinalIgnoreCase);
    public bool Elevated { get; set; } = true;
    public bool AgentAnswers { get; set; } = true;
    public string? InFolder { get; private set; }
    public string? OutFolder { get; private set; }
    public List<string?> KeysInGuestSessionAtGo { get; } = [];
    public List<ControlDto> Controls { get; } = [];
    private byte[]? _key;

    public static string Join(string folder, string name) => folder.TrimEnd('\\') + "\\" + name;

    public void Copied(string guestPath, byte[] content)
    {
        Files[guestPath] = content;
        var name = guestPath[(guestPath.LastIndexOf('\\') + 1)..];
        if (InFolder is null || !guestPath.StartsWith(InFolder + "\\", StringComparison.OrdinalIgnoreCase)) return;
        if (name == Protocol.ControlFile) Controls.Add(JsonSerializer.Deserialize(content, ProtocolJson.Default.ControlDto)!);
        if (name == Protocol.GoFile && _key is not null) OnGo();
    }

    public void StartAgent(string inFolder, string outFolder)
    {
        InFolder = inFolder;
        OutFolder = outFolder;
        if (!AgentAnswers) return;
        var config = JsonSerializer.Deserialize(Files[Join(inFolder, Protocol.SessionFile)], ProtocolJson.Default.SessionConfigDto)!;
        _key = Convert.FromBase64String(config.ChannelKey!);
        Write(Protocol.HelloFile, JsonSerializer.SerializeToUtf8Bytes(new HelloDto { ProtocolVersion = Protocol.Version, AgentVersion = "1.0.0", OsVersion = "Windows 11", At = DateTimeOffset.UtcNow, Elevated = Elevated }, ProtocolJson.Default.HelloDto));
        Beat();
    }

    private void OnGo()
    {
        var session = JsonSerializer.Deserialize(Files[Join(InFolder!, Protocol.SessionFile)], ProtocolJson.Default.SessionConfigDto)!;
        KeysInGuestSessionAtGo.Add(session.ChannelKey);
        var line = JsonSerializer.Serialize(new AgentEventDto { Sequence = 1, RelativeMs = 5, Action = "ProcessStart", ProcessId = 42, ProcessName = "sample.exe", Source = "etw" }, ProtocolJson.Default.AgentEventDto);
        Write(Protocol.EventChunkName(1), SignedFile.Sign(Encoding.UTF8.GetBytes(line), _key!));
        Write(Protocol.EventChunkName(2) + Protocol.TempExtension, "half written"u8.ToArray());
        Write("evil.exe", "MZ"u8.ToArray());
        Beat();
        Write(Protocol.DoneFile, SignedFile.Sign(JsonSerializer.SerializeToUtf8Bytes(new DoneDto { At = DateTimeOffset.UtcNow, Reason = "duration", EventsWritten = 1, SampleStarted = true }, ProtocolJson.Default.DoneDto), _key!));
    }

    private void Beat() => Write(Protocol.HeartbeatFile, SignedFile.Sign(JsonSerializer.SerializeToUtf8Bytes(new HeartbeatDto { At = DateTimeOffset.UtcNow.AddTicks(Random.Shared.Next()), State = "running" }, ProtocolJson.Default.HeartbeatDto), _key!));

    private void Write(string name, byte[] content) => Files[Join(OutFolder!, name)] = content;

    /// <summary>Files directly in a guest folder, as (name, content).</summary>
    public IEnumerable<(string Name, byte[] Content)> List(string folder) =>
        Files.Where(f => f.Key.StartsWith(folder.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase) && f.Key.LastIndexOf('\\') == folder.TrimEnd('\\').Length)
             .Select(f => (f.Key[(f.Key.LastIndexOf('\\') + 1)..], f.Value))
             .ToList();
}

/// <summary>Temporary host folders, a fake agent build and a sample.</summary>
internal sealed class VmTestBed : IDisposable
{
    public DirectoryInfo Root { get; } = Directory.CreateTempSubdirectory("blz-vm");
    public string WorkRoot => Path.Combine(Root.FullName, "work");
    public string AgentFolder { get; }
    public string SamplePath { get; }
    public FakeSecrets Secrets { get; } = new();
    public const string Password = "Pa$$ w'ord\"; calc";

    public VmTestBed()
    {
        AgentFolder = Directory.CreateDirectory(Path.Combine(Root.FullName, "agent")).FullName;
        File.WriteAllText(Path.Combine(AgentFolder, Protocol.AgentExecutable), "agent");
        File.WriteAllText(Path.Combine(AgentFolder, "Blazma.Agent.dll"), "agent dll");
        SamplePath = Path.Combine(Root.FullName, "sample.exe");
        File.WriteAllText(SamplePath, "MZ sample");
    }

    public SandboxSessionRequest Request(NetworkPolicy network = NetworkPolicy.Disabled, bool interactive = false) =>
        new(Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"), SamplePath, new SampleInfo
        {
            FileName = "sample.exe",
            Size = new FileInfo(SamplePath).Length,
            Sha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(SamplePath))),
            Sha1 = new string('0', 40),
            Kind = FileKind.Executable,
        }, new AnalysisOptions { Duration = TimeSpan.FromSeconds(30), Network = network, Interactive = interactive });

    public void Dispose() => Root.Delete(recursive: true);

    /// <summary>Runs every stage the way the analysis runner does, with shutdown in a finally.</summary>
    public static async Task<CollectedArtifacts> RunAllAsync(ISandboxSession session, CancellationToken ct = default, Func<Task>? whileRunning = null, List<SessionSignal>? signals = null)
    {
        try
        {
            await session.CreateEnvironmentAsync(ct);
            await session.BootAsync(ct);
            await session.DeployAgentAsync(ct);
            await session.TransferSampleAsync(ct);
            if (whileRunning is not null) await whileRunning();
            await foreach (var signal in session.ExecuteAsync(ct)) signals?.Add(signal);
            var collected = await session.CollectAsync(ct);
            await session.ShutdownAsync(ct);
            return collected;
        }
        finally
        {
            await session.ShutdownAsync(CancellationToken.None);
            await session.DisposeAsync();
        }
    }
}
