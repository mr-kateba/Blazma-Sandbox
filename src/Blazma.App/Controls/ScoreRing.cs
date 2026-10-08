using Avalonia;
using Avalonia.Animation;
using Avalonia.Controls;
using Avalonia.Media;
using Blazma.Core.Findings;

namespace Blazma.App.Controls;

/// <summary>The large risk score ring. The arc length is the score; the colour follows the verdict.</summary>
public sealed class ScoreRing : Control
{
    public static readonly StyledProperty<double> ValueProperty = AvaloniaProperty.Register<ScoreRing, double>(nameof(Value));
    public static readonly StyledProperty<Verdict> VerdictProperty = AvaloniaProperty.Register<ScoreRing, Verdict>(nameof(Verdict));
    public static readonly StyledProperty<double> ThicknessProperty = AvaloniaProperty.Register<ScoreRing, double>(nameof(Thickness), 10);
    public static readonly StyledProperty<bool> AnimateProperty = AvaloniaProperty.Register<ScoreRing, bool>(nameof(Animate), true);

    static ScoreRing() => AffectsRender<ScoreRing>(ValueProperty, VerdictProperty, ThicknessProperty);

    public double Value { get => GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public Verdict Verdict { get => GetValue(VerdictProperty); set => SetValue(VerdictProperty, value); }
    public double Thickness { get => GetValue(ThicknessProperty); set => SetValue(ThicknessProperty, value); }
    public bool Animate { get => GetValue(AnimateProperty); set => SetValue(AnimateProperty, value); }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == AnimateProperty)
            Transitions = Animate ? [new DoubleTransition { Property = ValueProperty, Duration = TimeSpan.FromMilliseconds(600), Easing = new Avalonia.Animation.Easings.CubicEaseOut() }] : null;
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        if (Animate && Transitions is null)
            Transitions = [new DoubleTransition { Property = ValueProperty, Duration = TimeSpan.FromMilliseconds(600), Easing = new Avalonia.Animation.Easings.CubicEaseOut() }];
    }

    public override void Render(DrawingContext context)
    {
        var size = Math.Min(Bounds.Width, Bounds.Height);
        if (size <= 0) return;
        var t = Thickness;
        var center = new Point(Bounds.Width / 2, Bounds.Height / 2);
        var radius = size / 2 - t / 2;

        var track = Brush("RuleBrush");
        context.DrawEllipse(null, new Pen(track, t), center, radius, radius);

        var fraction = Math.Clamp(Value / 100.0, 0, 1);
        if (fraction <= 0) return;
        var key = Verdict switch
        {
            Verdict.CriticalBehavior => "CriticalBrush",
            Verdict.HighRiskBehavior => "DangerBrush",
            Verdict.Suspicious => "WarnBrush",
            _ => "OkBrush",
        };
        var pen = new Pen(Brush(key), t, lineCap: PenLineCap.Round);
        if (fraction >= 0.999)
        {
            context.DrawEllipse(null, pen, center, radius, radius);
            return;
        }
        var start = -Math.PI / 2;
        var end = start + fraction * 2 * Math.PI;
        var geometry = new StreamGeometry();
        using (var g = geometry.Open())
        {
            g.BeginFigure(new Point(center.X + radius * Math.Cos(start), center.Y + radius * Math.Sin(start)), false);
            g.ArcTo(new Point(center.X + radius * Math.Cos(end), center.Y + radius * Math.Sin(end)), new Size(radius, radius), 0, fraction > 0.5, SweepDirection.Clockwise);
            g.EndFigure(false);
        }
        context.DrawGeometry(null, pen, geometry);
    }

    private IBrush Brush(string key) =>
        this.TryFindResource(key, ActualThemeVariant, out var value) && value is IBrush b ? b : Brushes.Gray;
}
