using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;

namespace Blazma.Intelligence.Reputation;

/// <summary>
/// Asks every configured reputation provider at once. Results come back in provider order,
/// and one provider failing or throwing never affects the others.
/// </summary>
public sealed class ReputationService
{
    private readonly IReadOnlyList<IReputationProvider> _providers;
    private readonly TimeProvider _time;

    public ReputationService(IEnumerable<IReputationProvider> providers, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(providers);
        _providers = providers.ToList();
        _time = time ?? TimeProvider.System;
    }

    public IReadOnlyList<IReputationProvider> Providers => _providers;

    /// <summary>True when at least one online provider is enabled and has its key.</summary>
    public bool HasRemoteProviders => _providers.Any(p => p.IsRemote && IsConfigured(p));

    public Task<IReadOnlyList<ReputationResult>> LookupAsync(string sha256, CancellationToken cancellationToken) =>
        LookupAsync(sha256, includeRemote: true, cancellationToken);

    /// <param name="includeRemote">False keeps the lookup on this computer (local history only).</param>
    public async Task<IReadOnlyList<ReputationResult>> LookupAsync(string sha256, bool includeRemote, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var active = _providers.Where(p => (includeRemote || !p.IsRemote) && IsConfigured(p)).ToList();
        var results = await Task.WhenAll(active.Select(p => RunAsync(p, sha256, cancellationToken))).ConfigureAwait(false);
        return results;
    }

    private async Task<ReputationResult> RunAsync(IReputationProvider provider, string sha256, CancellationToken cancellationToken)
    {
        try
        {
            // Task.Run: a provider that blocks or throws before its first await cannot hold up the others.
            return await Task.Run(() => provider.LookupAsync(sha256, cancellationToken), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return new ReputationResult
            {
                ProviderId = provider.Id,
                ProviderName = provider.DisplayName.En,
                Verdict = ReputationVerdict.Unknown,
                CheckedAt = _time.GetUtcNow(),
                Error = "The lookup failed.",
            };
        }
    }

    private static bool IsConfigured(IReputationProvider provider)
    {
        try
        {
            return provider.IsConfigured;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
