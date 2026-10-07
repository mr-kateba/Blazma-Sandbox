namespace Blazma.Core.Text;

/// <summary>
/// A user-facing string in both supported languages. Domain objects that end up in
/// front of the user (findings, rule names, explanations) carry both so reports can be
/// rendered in either language without a second analysis pass.
/// </summary>
public sealed record LocalizedText(string En, string Ar)
{
    public string Get(string language) =>
        language.StartsWith("ar", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(Ar) ? Ar : En;

    public static LocalizedText Same(string text) => new(text, text);

    public override string ToString() => En;
}
