using System.ComponentModel;
using System.Globalization;
using System.Reflection;
using System.Text.Json;
using Avalonia.Data;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Blazma.Core.Settings;

namespace Blazma.App.Localization;

/// <summary>
/// Every user-facing string, in English and Arabic, loaded from embedded JSON. Switching
/// language raises one indexer change so every binding retranslates, and flips
/// <see cref="FlowDirection"/> so the whole window mirrors for Arabic.
/// Technical terms (SHA-256, PID, IP, Registry) stay in Latin script inside the Arabic
/// strings so they remain recognisable.
/// </summary>
public sealed class Loc : INotifyPropertyChanged
{
    public static Loc Instance { get; } = new();

    private readonly Dictionary<string, string> _en;
    private readonly Dictionary<string, string> _ar;
    private Dictionary<string, string> _current;

    private Loc()
    {
        _en = Load("en");
        _ar = Load("ar");
        _current = _en;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? LanguageChanged;

    public AppLanguage Language { get; private set; } = AppLanguage.English;
    public bool IsArabic => Language == AppLanguage.Arabic;
    public string Code => IsArabic ? "ar" : "en";
    public FlowDirection FlowDirection => IsArabic ? FlowDirection.RightToLeft : FlowDirection.LeftToRight;
    public CultureInfo Culture => IsArabic ? CultureInfo.GetCultureInfo("ar") : CultureInfo.GetCultureInfo("en-US");

    public string this[string key] => _current.TryGetValue(key, out var v) ? v : _en.TryGetValue(key, out var e) ? e : key;

    public static string T(string key) => Instance[key];

    public static string F(string key, params object?[] args) => string.Format(CultureInfo.InvariantCulture, Instance[key], args);

    public IReadOnlyCollection<string> Keys(AppLanguage language) => (language == AppLanguage.Arabic ? _ar : _en).Keys;

    public void SetLanguage(AppLanguage language)
    {
        if (language == Language) return;
        Language = language;
        _current = language == AppLanguage.Arabic ? _ar : _en;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item"));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Language)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsArabic)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(FlowDirection)));
        LanguageChanged?.Invoke(this, EventArgs.Empty);
    }

    private static Dictionary<string, string> Load(string code)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var name = assembly.GetManifestResourceNames().Single(n => n.EndsWith($"Localization.{code}.json", StringComparison.Ordinal));
        using var stream = assembly.GetManifestResourceStream(name)!;
        return JsonSerializer.Deserialize<Dictionary<string, string>>(stream) ?? [];
    }
}

/// <summary>XAML: <c>Text="{l:T Dashboard}"</c>. Re-evaluates when the language changes.</summary>
public sealed class TExtension(string key) : MarkupExtension
{
    public string Key { get; } = key;

    public override object ProvideValue(IServiceProvider serviceProvider) =>
        new ReflectionBinding($"[{Key}]") { Source = Loc.Instance, Mode = BindingMode.OneWay };
}
