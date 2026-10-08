using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Text;

namespace Blazma.Intelligence;

/// <summary>The default: no AI. The UI shows AI features as planned rather than pretending.</summary>
public sealed class NullAiProvider : IAiProvider
{
    public string Id => "none";
    public bool IsAvailable => false;

    public Task<string> AskAsync(AnalysisResult result, string question, string language, CancellationToken cancellationToken) =>
        throw new NotSupportedException("No AI provider is configured. Ask Blazma answers from the analysis data instead.");
}

/// <summary>Reputation from the user's own history only: how often this hash was analyzed here before. Never remote.</summary>
public sealed class LocalHistoryReputationProvider(IAnalysisRepository repository, TimeProvider? time = null) : IReputationProvider
{
    public string Id => "local-history";
    public LocalizedText DisplayName { get; } = new("This computer's history", "سجل هذا الجهاز");
    public bool IsRemote => false;
    public bool IsConfigured => true;

    public async Task<ReputationResult> LookupAsync(string sha256, CancellationToken cancellationToken)
    {
        var history = await repository.ListAsync(500, 0, cancellationToken).ConfigureAwait(false);
        var previous = history.Where(h => h.Sha256.Equals(sha256, StringComparison.OrdinalIgnoreCase)).ToList();
        var now = (time ?? TimeProvider.System).GetUtcNow();
        if (previous.Count == 0)
            return new ReputationResult { ProviderId = Id, ProviderName = DisplayName.En, Verdict = ReputationVerdict.NotFound, CheckedAt = now };
        var highest = previous.Max(p => p.Score);
        return new ReputationResult
        {
            ProviderId = Id,
            ProviderName = DisplayName.En,
            Verdict = ReputationVerdict.Unknown,
            CheckedAt = now,
            FirstSeen = previous.Min(p => p.StartedAt),
            Tags = [$"analyzed-{previous.Count}x", $"highest-score-{highest}"],
        };
    }
}
