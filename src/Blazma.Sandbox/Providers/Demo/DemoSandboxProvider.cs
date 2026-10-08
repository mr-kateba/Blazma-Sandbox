using System.Runtime.CompilerServices;
using Blazma.Core.Abstractions;
using Blazma.Core.Events;
using Blazma.Core.Text;

namespace Blazma.Sandbox.Providers.Demo;

/// <summary>
/// Plays back a <see cref="DemoScenario"/> through the real pipeline (state machine,
/// engine, storage, reports). It never touches the submitted file beyond its name.
/// Speed 0 skips all delays (used by tests).
/// </summary>
public sealed class DemoSandboxProvider(TimeProvider time, double speed = 1.0) : ISandboxProvider
{
    public const string ProviderId = "demo";

    public string Id => ProviderId;
    public LocalizedText DisplayName { get; } = new("Demo (synthetic data)", "تجريبي (بيانات اصطناعية)");
    public bool IsDemo => true;

    public Task<ProviderAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new ProviderAvailability(ProviderReadiness.Ready,
            [new ProviderCheck("demo", new("Demo data", "بيانات تجريبية"), true, new("Synthetic events, nothing is executed.", "أحداث اصطناعية، لا يتم تشغيل أي شيء."))]));

    public Task<ISandboxSession> CreateSessionAsync(SandboxSessionRequest request, CancellationToken cancellationToken) =>
        Task.FromResult<ISandboxSession>(new Session(request, time, speed));

    private sealed class Session(SandboxSessionRequest request, TimeProvider time, double speed) : ISandboxSession, IInteractiveSession
    {
        private DemoScenario? _scenario;
        private int _emitted;
        private TimeSpan _cutoff = request.Options.Duration;
        private volatile bool _finish;
        private readonly List<CollectedScreenshot> _screens = [];

        public Task ExtendAsync(TimeSpan extra, CancellationToken cancellationToken)
        {
            _cutoff += extra;
            return Task.CompletedTask;
        }

        public Task FinishNowAsync(CancellationToken cancellationToken)
        {
            _finish = true;
            return Task.CompletedTask;
        }

        private bool Rich => request.ArtifactsFolder is not null && _scenario?.Name == "persistent-updater";

        private ScreenshotSignal? Shot(TimeSpan at, double progress)
        {
            if (request.ArtifactsFolder is null || !request.Options.CaptureScreenshots || _scenario?.Name == "stress") return null;
            var shot = DemoArtifacts.Screenshot(request.ArtifactsFolder, _screens.Count + 1, at, progress);
            _screens.Add(shot);
            return new ScreenshotSignal(shot);
        }

        private Task Pause(int ms, CancellationToken ct) =>
            speed <= 0 ? Task.CompletedTask : Task.Delay(TimeSpan.FromMilliseconds(ms / speed), time, ct);

        public async Task CreateEnvironmentAsync(CancellationToken ct)
        {
            _scenario = DemoScenario.For(request.Sample.FileName, time.GetUtcNow());
            await Pause(400, ct).ConfigureAwait(false);
        }

        public Task BootAsync(CancellationToken ct) => Pause(900, ct);
        public Task DeployAgentAsync(CancellationToken ct) => Pause(500, ct);
        public Task TransferSampleAsync(CancellationToken ct) => Pause(300, ct);

        public async IAsyncEnumerable<SessionSignal> ExecuteAsync([EnumeratorCancellation] CancellationToken ct)
        {
            var events = _scenario!.Events;
            var lastMs = 0.0;
            var batch = new List<AnalysisEvent>();
            if (Shot(TimeSpan.FromMilliseconds(500), 0.1) is { } first) yield return first;
            var shotAt = new Queue<(double Ms, double Progress)>([(2600, 0.55), (7300, 1.0)]);
            foreach (var e in events)
            {
                if (_finish || e.RelativeTime > _cutoff) break;
                while (shotAt.Count > 0 && e.RelativeTime.TotalMilliseconds >= shotAt.Peek().Ms)
                {
                    var (ms, progress) = shotAt.Dequeue();
                    if (Shot(TimeSpan.FromMilliseconds(ms), progress) is { } s) yield return s;
                }
                var wait = e.RelativeTime.TotalMilliseconds - lastMs;
                if (speed > 0 && wait > 30 && batch.Count > 0)
                {
                    yield return new EventsSignal(batch);
                    batch = [];
                    yield return new HeartbeatSignal(time.GetUtcNow());
                    await Pause((int)Math.Min(wait, 1500), ct).ConfigureAwait(false);
                }
                lastMs = e.RelativeTime.TotalMilliseconds;
                batch.Add(e);
                _emitted++;
                if (batch.Count >= 5000)
                {
                    yield return new EventsSignal(batch);
                    batch = [];
                }
            }
            if (batch.Count > 0) yield return new EventsSignal(batch);
        }

        public async Task<CollectedArtifacts> CollectAsync(CancellationToken ct)
        {
            await Pause(500, ct).ConfigureAwait(false);
            var s = _scenario!;
            return new CollectedArtifacts([], request.Options.TakeSnapshots ? s.Baseline : null, request.Options.TakeSnapshots ? s.After : null, AgentCompleted: true)
            {
                Screenshots = _screens,
                DroppedFiles = Rich && request.Options.CollectDroppedFiles ? [DemoArtifacts.DroppedUpdater(request.ArtifactsFolder!, DemoScenario.User)] : [],
                MemoryRegions = Rich && request.Options.DumpMemory ? [DemoArtifacts.InjectedRegion(request.ArtifactsFolder!)] : [],
            };
        }

        public Task ShutdownAsync(CancellationToken ct) => Task.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
