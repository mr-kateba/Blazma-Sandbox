using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;

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
public sealed class LocalHistoryReputationProvider(IAnalysisRepository repository) : IReputationProvider
{
    public string Id => "local-history";
    public bool IsRemote => false;

    public async Task<string?> LookupAsync(string sha256, CancellationToken cancellationToken)
    {
        var history = await repository.ListAsync(500, 0, cancellationToken).ConfigureAwait(false);
        var previous = history.Where(h => h.Sha256.Equals(sha256, StringComparison.OrdinalIgnoreCase)).ToList();
        return previous.Count == 0 ? null : $"Analyzed {previous.Count} time(s) on this computer; highest score {previous.Max(p => p.Score)}.";
    }
}
