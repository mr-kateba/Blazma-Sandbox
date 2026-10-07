using Blazma.Analysis.Engine;
using Blazma.Analysis.Pipeline;
using Blazma.Analysis.Rules;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Samples;
using Blazma.Sandbox.Providers.Demo;
using Blazma.Storage;

namespace Blazma.Integration.Tests;

public sealed class Fixture : IAsyncDisposable
{
    public DirectoryInfo Dir { get; } = Directory.CreateTempSubdirectory("blz-int");
    public SqliteAnalysisRepository Repository { get; }
    public AnalysisRunner Runner { get; }

    public Fixture()
    {
        Repository = new SqliteAnalysisRepository(Path.Combine(Dir.FullName, "test.db"));
        Runner = new AnalysisRunner(new AnalysisEngine(new RuleEngine(RuleEngine.BuiltInRules())), Repository, TimeProvider.System);
    }

    public static async Task<Fixture> CreateAsync()
    {
        var f = new Fixture();
        await f.Repository.InitializeAsync(CancellationToken.None);
        return f;
    }

    public AnalysisRequest Request(string name = "setup.exe", FileKind kind = FileKind.Executable, int maxEvents = 250_000) => new()
    {
        SamplePath = Path.Combine(Dir.FullName, name),
        Static = new StaticReport
        {
            Sample = new SampleInfo { FileName = name, Size = 10, Sha256 = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(name))), Sha1 = new string('0', 40), Kind = kind },
        },
        Options = new AnalysisOptions { Duration = TimeSpan.FromMinutes(2) },
        EngineSettings = new EngineSettings(),
        MaxEvents = maxEvents,
    };

    public Task<AnalysisResult> RunDemoAsync(string name = "setup.exe", IProgress<AnalysisProgress>? progress = null, CancellationToken ct = default) =>
        Runner.RunAsync(Request(name), new DemoSandboxProvider(TimeProvider.System, speed: 0), progress, null, ct);

    public ValueTask DisposeAsync()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Dir.Delete(recursive: true); } catch (IOException) { }
        return ValueTask.CompletedTask;
    }
}

/// <summary>Records every progress report synchronously (Progress&lt;T&gt; would post to the thread pool).</summary>
public sealed class SyncProgress<T> : IProgress<T>
{
    public List<T> Items { get; } = [];
    public void Report(T value) { lock (Items) Items.Add(value); }
}
