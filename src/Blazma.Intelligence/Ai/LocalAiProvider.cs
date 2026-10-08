using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Settings;
using Blazma.Core.Text;
using Blazma.Intelligence.Net;

namespace Blazma.Intelligence.Ai;

/// <summary>A failure talking to the AI server, with a message fit to show the user in either language.</summary>
public sealed class AiProviderException : Exception
{
    public AiProviderException() : this(LocalizedText.Same("The AI request failed.")) { }

    public AiProviderException(string message) : this(LocalizedText.Same(message)) { }

    public AiProviderException(string message, Exception innerException) : base(message, innerException) => UserMessage = LocalizedText.Same(message);

    public AiProviderException(LocalizedText userMessage) : base(userMessage.En) => UserMessage = userMessage;

    public LocalizedText UserMessage { get; }
}

/// <summary>Result of "Test connection": the models the server offers, or why it could not be reached.</summary>
public sealed record AiConnectionResult(bool Success, IReadOnlyList<string> Models, LocalizedText? Error)
{
    public static AiConnectionResult Failed(LocalizedText error) => new(false, [], error);
}

/// <summary>
/// Ask Blazma with a model the user runs on this computer: Ollama (<c>/api/chat</c>) or any
/// OpenAI-compatible server such as LM Studio or llama.cpp (<c>/v1/chat/completions</c>).
/// The model receives the prompt built from the structured result, never the sample.
/// Only loopback endpoints are used unless <see cref="AiSettings.AllowRemoteEndpoint"/> is on;
/// the address is checked before every request and redirects are never followed.
/// </summary>
public sealed class LocalAiProvider : IAiProvider
{
    public const string ProviderId = "local-ai";

    /// <summary>Longest answer kept, in characters.</summary>
    public const int MaxAnswerChars = 12_000;

    /// <summary>Tokens the model may generate per answer.</summary>
    public const int MaxOutputTokens = 1_500;

    private const int MaxModels = 200;
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(15);

    private readonly HttpClient _http;
    private readonly Func<AiSettings> _settings;
    private readonly AnalysisPromptBuilder _prompts;
    private readonly int _maxResponseBytes;

    /// <param name="httpClient">Use <see cref="IntegrationHttp.CreateClient"/> with <c>useProxy: false</c>.</param>
    /// <param name="settings">Read on every call, so changes in Settings apply without a restart.</param>
    public LocalAiProvider(HttpClient httpClient, Func<AiSettings> settings, AnalysisPromptBuilder? promptBuilder = null, int maxResponseBytes = SafeHttp.DefaultMaxResponseBytes)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(settings);
        _http = httpClient;
        _settings = settings;
        _prompts = promptBuilder ?? new AnalysisPromptBuilder();
        _maxResponseBytes = maxResponseBytes;
    }

    public LocalAiProvider(HttpClient httpClient, AiSettings settings, AnalysisPromptBuilder? promptBuilder = null, int maxResponseBytes = SafeHttp.DefaultMaxResponseBytes)
        : this(httpClient, () => settings, promptBuilder, maxResponseBytes)
    {
    }

    public string Id => ProviderId;

    public bool IsAvailable
    {
        get
        {
            var s = _settings();
            return s.Enabled && !string.IsNullOrWhiteSpace(s.Model) && AiEndpointPolicy.TryValidate(s.LocalEndpoint, s.AllowRemoteEndpoint, out _, out _);
        }
    }

    /// <summary>Asks the model. Throws <see cref="AiProviderException"/> with a user-facing message on failure.</summary>
    public async Task<string> AskAsync(AnalysisResult result, string question, string language, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(result);
        var s = _settings();
        if (!s.Enabled) throw new AiProviderException(new LocalizedText("AI explanations are turned off in Settings.", "شروحات الذكاء الاصطناعي معطّلة في الإعدادات."));
        var baseUri = Validate(s);
        var model = Model(s);

        var prompt = _prompts.Build(result, question ?? string.Empty, language);
        var messages = new JsonArray
        {
            new JsonObject { ["role"] = "system", ["content"] = prompt.System },
            new JsonObject { ["role"] = "user", ["content"] = prompt.User },
        };
        JsonObject body;
        Uri uri;
        if (s.Provider == AiProviderKind.Ollama)
        {
            uri = AiEndpointPolicy.Combine(baseUri, "api/chat");
            body = new JsonObject
            {
                ["model"] = model,
                ["messages"] = messages,
                ["stream"] = false,
                ["options"] = new JsonObject { ["temperature"] = 0.2, ["num_predict"] = MaxOutputTokens },
            };
        }
        else
        {
            uri = OpenAiUri(baseUri, "chat/completions");
            body = new JsonObject
            {
                ["model"] = model,
                ["messages"] = messages,
                ["stream"] = false,
                ["temperature"] = 0.2,
                ["max_tokens"] = MaxOutputTokens,
            };
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        };
        using var doc = await SendAsync(request, Timeout(s), cancellationToken).ConfigureAwait(false);
        var root = doc.RootElement;
        var content = s.Provider == AiProviderKind.Ollama
            ? SafeText.Object(root, "message") is { } m ? SafeText.String(m, "content") : null
            : SafeText.Array(root, "choices") is { } choices && choices.GetArrayLength() > 0 && SafeText.Object(choices[0], "message") is { } cm ? SafeText.String(cm, "content") : null;
        if (content is null) throw Unreadable();

        var answer = CleanAnswer(content);
        if (answer.Length == 0) throw new AiProviderException(new LocalizedText("The model returned an empty answer.", "أعاد النموذج إجابة فارغة."));
        return answer;
    }

    /// <summary>Lists the models the server offers. Works while AI is still turned off, so the user can check the setup first.</summary>
    public async Task<AiConnectionResult> TestConnectionAsync(CancellationToken cancellationToken = default)
    {
        var s = _settings();
        try
        {
            var baseUri = Validate(s);
            var ollama = s.Provider == AiProviderKind.Ollama;
            using var request = new HttpRequestMessage(HttpMethod.Get, ollama ? AiEndpointPolicy.Combine(baseUri, "api/tags") : OpenAiUri(baseUri, "models"));
            var timeout = Timeout(s) < TestTimeout ? Timeout(s) : TestTimeout;
            using var doc = await SendAsync(request, timeout, cancellationToken).ConfigureAwait(false);
            var list = SafeText.Array(doc.RootElement, ollama ? "models" : "data");
            if (list is null) throw Unreadable();

            var models = new List<string>();
            foreach (var item in list.Value.EnumerateArray())
            {
                if (models.Count >= MaxModels) break;
                var name = SafeText.Clean(ollama ? SafeText.String(item, "name") ?? SafeText.String(item, "model") : SafeText.String(item, "id"), 200);
                if (name.Length > 0 && !models.Contains(name, StringComparer.Ordinal)) models.Add(name);
            }
            return new AiConnectionResult(true, models, null);
        }
        catch (AiProviderException ex)
        {
            return AiConnectionResult.Failed(ex.UserMessage);
        }
    }

    private static Uri Validate(AiSettings s) =>
        AiEndpointPolicy.TryValidate(s.LocalEndpoint, s.AllowRemoteEndpoint, out var uri, out var error) ? uri : throw new AiProviderException(error);

    private static string Model(AiSettings s)
    {
        var model = SafeText.Clean(s.Model, 200);
        return model.Length > 0 ? model : throw new AiProviderException(new LocalizedText("No model is set.", "لم يُحدَّد نموذج."));
    }

    private static TimeSpan Timeout(AiSettings s) => TimeSpan.FromSeconds(Math.Clamp(s.TimeoutSeconds, 5, 600));

    /// <summary>OpenAI-compatible paths live under /v1; the user may or may not have typed it.</summary>
    private static Uri OpenAiUri(Uri baseUri, string relative) =>
        AiEndpointPolicy.Combine(baseUri, baseUri.AbsolutePath.TrimEnd('/').EndsWith("/v1", StringComparison.OrdinalIgnoreCase) ? relative : "v1/" + relative);

    private async Task<JsonDocument> SendAsync(HttpRequestMessage request, TimeSpan timeout, CancellationToken cancellationToken)
    {
        // Checked again right before sending: the request URI is what actually goes on the wire.
        var s = _settings();
        if (!s.AllowRemoteEndpoint && !AiEndpointPolicy.IsLoopback(request.RequestUri!)) throw new AiProviderException(LocalizedText.Same("Refused: the AI server is not on this computer."));

        HttpReply reply;
        try
        {
            reply = await SafeHttp.SendAsync(_http, request, timeout, _maxResponseBytes, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (TimeoutException)
        {
            var seconds = timeout.TotalSeconds.ToString("0", System.Globalization.CultureInfo.InvariantCulture);
            throw new AiProviderException(new LocalizedText($"The AI server did not answer within {seconds} seconds.", $"لم يُجب خادم الذكاء الاصطناعي خلال {seconds} ثانية."));
        }
        catch (ResponseTooLargeException)
        {
            throw new AiProviderException(new LocalizedText("The AI server sent a response that is too large; it was ignored.", "أرسل خادم الذكاء الاصطناعي ردًا كبيرًا جدًا، فتم تجاهله."));
        }
        catch (HttpRequestException)
        {
            var at = SafeText.Clean(request.RequestUri!.GetLeftPart(UriPartial.Authority), 200);
            throw new AiProviderException(new LocalizedText(
                $"Could not connect to the AI server at {at}. Is Ollama or LM Studio running?",
                $"تعذّر الاتصال بخادم الذكاء الاصطناعي على {at}. هل Ollama أو LM Studio قيد التشغيل؟"));
        }

        if (SafeHttp.IsRedirect(reply.Status) || SafeHttp.WasRedirectedElsewhere(request.RequestUri!, reply.FinalUri))
            throw new AiProviderException(new LocalizedText("The AI server answered with a redirect; it was not followed.", "أجاب خادم الذكاء الاصطناعي بإعادة توجيه، ولم تُتبَع."));

        JsonDocument? doc = null;
        try
        {
            doc = JsonDocument.Parse(reply.Body, SafeText.JsonOptions);
        }
        catch (JsonException)
        {
            // Not JSON: handled below as an unreadable answer or a plain HTTP error.
        }

        if (reply.Status != HttpStatusCode.OK)
        {
            var detail = doc is null ? null : ServerError(doc.RootElement);
            doc?.Dispose();
            var code = ((int)reply.Status).ToString(System.Globalization.CultureInfo.InvariantCulture);
            var suffix = detail is null ? string.Empty : ": " + detail;
            throw new AiProviderException(new LocalizedText(
                $"The AI server answered with an error (HTTP {code}){suffix}",
                $"أجاب خادم الذكاء الاصطناعي بخطأ (HTTP {code}){suffix}"));
        }
        return doc ?? throw Unreadable();
    }

    /// <summary>Ollama: {"error":"..."}; OpenAI-compatible: {"error":{"message":"..."}}.</summary>
    private static string? ServerError(JsonElement root)
    {
        var text = SafeText.String(root, "error") ?? (SafeText.Object(root, "error") is { } e ? SafeText.String(e, "message") : null);
        var clean = SafeText.Clean(text, 200);
        return clean.Length == 0 ? null : clean;
    }

    private static AiProviderException Unreadable() =>
        new(new LocalizedText("The AI server sent an answer Blazma could not read.", "أرسل خادم الذكاء الاصطناعي ردًا تعذّرت قراءته."));

    /// <summary>Drops reasoning blocks some local models emit, strips control characters and caps the length.</summary>
    internal static string CleanAnswer(string content)
    {
        var text = WithoutThinking(content);
        var clean = SafeText.Clean(text, MaxAnswerChars + 1, multiline: true);
        return clean.Length > MaxAnswerChars ? clean[..MaxAnswerChars] + "…" : clean;
    }

    private static string WithoutThinking(string text)
    {
        var sb = new StringBuilder(text.Length);
        var at = 0;
        while (at < text.Length)
        {
            var open = text.IndexOf("<think>", at, StringComparison.OrdinalIgnoreCase);
            if (open < 0) break;
            sb.Append(text, at, open - at);
            var close = text.IndexOf("</think>", open, StringComparison.OrdinalIgnoreCase);
            at = close < 0 ? text.Length : close + "</think>".Length;
        }
        if (at < text.Length) sb.Append(text, at, text.Length - at);
        return sb.ToString();
    }
}
