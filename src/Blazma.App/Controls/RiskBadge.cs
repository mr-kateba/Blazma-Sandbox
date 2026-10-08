using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Indicators;

namespace Blazma.App.Controls;

/// <summary>
/// Severity, verdict or indicator status as a pill: a shape, a word and a colour together,
/// so the meaning never depends on colour alone (accessibility).
/// </summary>
public sealed class RiskBadge : Border
{
    public static readonly StyledProperty<Severity?> SeverityProperty = AvaloniaProperty.Register<RiskBadge, Severity?>(nameof(Severity));
    public static readonly StyledProperty<Verdict?> VerdictProperty = AvaloniaProperty.Register<RiskBadge, Verdict?>(nameof(Verdict));
    public static readonly StyledProperty<IndicatorStatus?> StatusProperty = AvaloniaProperty.Register<RiskBadge, IndicatorStatus?>(nameof(Status));
    public static readonly StyledProperty<bool> LargeProperty = AvaloniaProperty.Register<RiskBadge, bool>(nameof(Large));

    private readonly TextBlock _glyph = new() { FontSize = 9, VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _text = new() { FontSize = 11, FontWeight = FontWeight.SemiBold, VerticalAlignment = VerticalAlignment.Center };

    public RiskBadge()
    {
        CornerRadius = new CornerRadius(999);
        BorderThickness = new Thickness(1);
        Padding = new Thickness(8, 1, 9, 2);
        HorizontalAlignment = HorizontalAlignment.Left;
        VerticalAlignment = VerticalAlignment.Center;
        Child = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 5, Children = { _glyph, _text } };
        Loc.Instance.LanguageChanged += (_, _) => Update();
        ActualThemeVariantChanged += (_, _) => Update();
    }

    public Severity? Severity { get => GetValue(SeverityProperty); set => SetValue(SeverityProperty, value); }
    public Verdict? Verdict { get => GetValue(VerdictProperty); set => SetValue(VerdictProperty, value); }
    public IndicatorStatus? Status { get => GetValue(StatusProperty); set => SetValue(StatusProperty, value); }
    public bool Large { get => GetValue(LargeProperty); set => SetValue(LargeProperty, value); }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == SeverityProperty || change.Property == VerdictProperty || change.Property == StatusProperty || change.Property == LargeProperty) Update();
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        Update();
    }

    private void Update()
    {
        Core.Events.Severity level;
        string label;
        if (Verdict is { } v) { level = Fmt.SeverityOf(v); label = Fmt.Verdict(v); }
        else if (Status is { } s)
        {
            level = s switch
            {
                IndicatorStatus.HighRisk or IndicatorStatus.WatchlistMatch => Core.Events.Severity.High,
                IndicatorStatus.Suspicious => Core.Events.Severity.Medium,
                IndicatorStatus.Observed => Core.Events.Severity.Low,
                _ => Core.Events.Severity.Informational,
            };
            label = Fmt.IndicatorStatus(s);
        }
        else { level = Severity ?? Core.Events.Severity.Informational; label = Fmt.Severity(level); }

        var (fg, bg, glyph) = level switch
        {
            Core.Events.Severity.Critical => ("CriticalBrush", "CriticalSoftBrush", "◆◆"),
            Core.Events.Severity.High => ("DangerBrush", "DangerSoftBrush", "▲"),
            Core.Events.Severity.Medium => ("WarnBrush", "WarnSoftBrush", "◆"),
            Core.Events.Severity.Low => ("OkBrush", "OkSoftBrush", "●"),
            _ => ("InfoBrush", "PanelBrush", "○"),
        };
        var fgBrush = Resource(fg);
        Background = Resource(bg);
        BorderBrush = fgBrush is ISolidColorBrush sc ? new SolidColorBrush(sc.Color, 0.45) : fgBrush;
        _glyph.Foreground = _text.Foreground = fgBrush;
        _glyph.Text = glyph;
        _text.Text = label;
        _text.FontSize = Large ? 14 : 11;
        Padding = Large ? new Thickness(12, 3, 13, 4) : new Thickness(8, 1, 9, 2);
    }

    private IBrush? Resource(string key) =>
        this.TryFindResource(key, ActualThemeVariant, out var value) && value is IBrush b ? b
        : Application.Current?.TryFindResource(key, out var app) == true ? app as IBrush : Brushes.Gray;
}
