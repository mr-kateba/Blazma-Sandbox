using System.Net;
using System.Text.Json;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Text;
using Blazma.Intelligence.Net;

namespace Blazma.Intelligence.Reputation;

/// <summary>Limits for one online lookup.</summary>
public sealed record ReputationProviderOptions
{
    public static ReputationProviderOptions Default { get; } = new();

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(20);

    /// <summary>Largest response body read, enforced while reading.</summary>
    public int MaxResponseBytes { get; init; } = SafeHttp.DefaultMaxResponseBytes;
}

/// <summary>
/// An online hash lookup. Sends the SHA-256 and the user's API key, nothing else: no file,
/// no file name, no path. Every failure becomes a <see cref="ReputationResult"/> with an
/// <see cref="ReputationResult.Error"/>; only the caller's own cancellation throws.
/// </summary>
public abstract class HashReputationProvider : IReputationProvider
{
    private readonly HttpClient _http;
    private readonly ISecretProtector _secrets;
    private readonly ReputationProviderOptions _options;
    private readonly TimeProvider _time;

    protected HashReputationProvider(HttpClient httpClient, ISecretProtector secrets, ReputationProviderOptions? options, TimeProvider? time)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(secrets);
        _http = httpClient;
        _secrets = secrets;
        _options = options ?? ReputationProviderOptions.Default;
        _time = time ?? TimeProvider.System;
    }

    public abstract string Id { get; }
    public abstract LocalizedText DisplayName { get; }
    public bool IsRemote => true;
    public bool IsConfigured => IsEnabled && ApiKey() is not null;

    /// <summary>The service's name in results and messages.</summary>
    protected abstract string ServiceName { get; }

    protected abstract bool IsEnabled { get; }

    /// <summary>The key as stored in settings (protected).</summary>
    protected abstract string? StoredApiKey { get; }

    /// <summary>Builds the request. <paramref name="sha256"/> is already validated and lower case.</summary>
    protected abstract HttpRequestMessage CreateRequest(string sha256, string apiKey);

    /// <summary>Reads a response that was not an authentication, rate-limit or redirect answer. May throw on bad data.</summary>
    protected abstract ReputationResult Interpret(HttpStatusCode status, JsonElement? json, string sha256);

    public async Task<ReputationResult> LookupAsync(string sha256, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!SafeText.IsSha256(sha256)) return Failed("Not a valid SHA-256 hash; nothing was sent.");
        if (!IsEnabled) return Failed($"{ServiceName} lookups are turned off.");
        var key = ApiKey();
        if (key is null) return Failed($"No {ServiceName} API key is set.");
        if (!SafeText.IsHeaderSafeKey(key)) return Failed($"The {ServiceName} API key contains characters that cannot be sent. Enter it again.");

        var hash = sha256.ToLowerInvariant();
        try
        {
            using var request = CreateRequest(hash, key);
            var requested = request.RequestUri!;
            var reply = await SafeHttp.SendAsync(_http, request, _options.Timeout, _options.MaxResponseBytes, cancellationToken).ConfigureAwait(false);

            if (SafeHttp.WasRedirectedElsewhere(requested, reply.FinalUri) || SafeHttp.IsRedirect(reply.Status))
                return Failed($"{ServiceName} answered with a redirect; it was not followed.");
            switch (reply.Status)
            {
                case HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden:
                    return Failed($"{ServiceName}: API key rejected.");
                case HttpStatusCode.TooManyRequests:
                    return Failed($"{ServiceName}: rate limit / quota reached. Try again later.");
                case >= HttpStatusCode.InternalServerError:
                    return Failed($"{ServiceName} is unavailable right now (HTTP {(int)reply.Status}).");
            }

            JsonElement? json = null;
            JsonDocument? doc = null;
            try
            {
                // Not every answer has a JSON body (a 404 may not); Interpret decides whether it needs one.
                if (reply.Body.Length > 0)
                {
                    try
                    {
                        doc = JsonDocument.Parse(reply.Body, SafeText.JsonOptions);
                        json = doc.RootElement;
                    }
                    catch (JsonException)
                    {
                        json = null;
                    }
                }
                return WithoutKey(Interpret(reply.Status, json, hash), key);
            }
            finally
            {
                doc?.Dispose();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (TimeoutException)
        {
            return Failed($"{ServiceName} did not answer within {_options.Timeout.TotalSeconds:0} seconds.");
        }
        catch (ResponseTooLargeException)
        {
            return Failed($"{ServiceName} sent a response larger than {_options.MaxResponseBytes / 1024} KB; it was ignored.");
        }
        catch (HttpRequestException)
        {
            return Failed($"Could not reach {ServiceName}. Check the internet connection.");
        }
        catch (Exception)
        {
            // Malformed or hostile data. The exception text is not passed on: it could quote the response.
            return Failed($"{ServiceName} sent a response Blazma could not read.");
        }
    }

    protected ReputationResult Failed(string error) => Result(ReputationVerdict.Unknown) with { Error = error };

    protected ReputationResult Result(ReputationVerdict verdict) => new()
    {
        ProviderId = Id,
        ProviderName = ServiceName,
        Verdict = verdict,
        CheckedAt = _time.GetUtcNow(),
    };

    /// <summary>A status word from the service, reduced to letters, digits and underscores so it can be shown safely.</summary>
    protected static string StatusWord(string? status)
    {
        var word = new string((status ?? string.Empty).Where(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-').Take(40).ToArray());
        return word.Length == 0 ? "unknown" : word;
    }

    /// <summary>Last line of defence: a service that echoes the key back never gets it into an error message.</summary>
    private static ReputationResult WithoutKey(ReputationResult result, string key) =>
        result.Error?.Contains(key, StringComparison.Ordinal) == true ? result with { Error = result.Error.Replace(key, "[key]", StringComparison.Ordinal) } : result;

    private string? ApiKey()
    {
        var stored = StoredApiKey;
        if (string.IsNullOrWhiteSpace(stored)) return null;
        try
        {
            var key = _secrets.Unprotect(stored)?.Trim();
            return string.IsNullOrEmpty(key) ? null : key;
        }
        catch (Exception)
        {
            return null;
        }
    }
}
