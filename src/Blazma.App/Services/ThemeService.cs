using Avalonia;
using Avalonia.Media;
using Avalonia.Styling;
using Blazma.Core.Settings;
using CoreTheme = Blazma.Core.Settings.ThemeVariant;

namespace Blazma.App.Services;

/// <summary>
/// Applies appearance settings by replacing the token brushes. Dark is the Blazma
/// default; Midnight and Light follow the family's other apps. The accent ramp is
/// derived from one colour. Risk colours are adjusted for contrast on light surfaces.
/// </summary>
public sealed class ThemeService
{
    private sealed record Palette(string Bg, string Sidebar, string Panel, string PanelHover, string Field, string Rule, string RuleStrong,
        string Text, string Muted, string Faint, string Outline, string Hover, string Ok, string OkSoft, string Warn, string WarnSoft,
        string Danger, string DangerSoft, string Critical, string CriticalSoft);

    private static readonly Palette Dark = new("#121216", "#16161B", "#1C1C22", "#26262E", "#0D0D10", "#2A2A33", "#3A3A45",
        "#F2F2F5", "#A0A0AB", "#6E6E7A", "#C8C8CE", "#2E2E38", "#34D399", "#10302A", "#FFB300", "#33270A", "#FF5252", "#3A1A1C", "#FF3B5C", "#3A1420");

    private static readonly Palette Midnight = new("#07070A", "#0B0B0F", "#121217", "#1B1B22", "#040406", "#1F1F27", "#2D2D37",
        "#F2F2F5", "#9A9AA6", "#62626E", "#B8B8C0", "#22222B", "#34D399", "#0C2620", "#FFB300", "#2A2008", "#FF5252", "#301417", "#FF3B5C", "#2E101A");

    private static readonly Palette Light = new("#F5F6F8", "#ECEEF2", "#FFFFFF", "#EEF0F4", "#F9FAFB", "#DFE2E8", "#C5CAD3",
        "#1C1F26", "#5A6070", "#848A99", "#5A6070", "#E4E7EC", "#15803D", "#DCF3E4", "#B45309", "#FFF7E6", "#C53030", "#FDECEC", "#B4123A", "#FDE6EC");

    public static Color AccentOf(AccentColor accent) => Color.Parse(accent switch
    {
        AccentColor.Amber => "#FFB300",
        AccentColor.Ember => "#FF3D00",
        _ => "#FF6D00",
    });

    public void Apply(AppearanceSettings settings)
    {
        var app = Application.Current;
        if (app is null) return;
        var r = app.Resources;
        var p = settings.Theme switch { CoreTheme.Midnight => Midnight, CoreTheme.Light => Light, _ => Dark };
        app.RequestedThemeVariant = settings.Theme == CoreTheme.Light ? Avalonia.Styling.ThemeVariant.Light : Avalonia.Styling.ThemeVariant.Dark;

        void Set(string key, string hex) => r[key] = new SolidColorBrush(Color.Parse(hex));
        Set("BgBrush", p.Bg); Set("SidebarBrush", p.Sidebar); Set("PanelBrush", p.Panel); Set("PanelHoverBrush", p.PanelHover);
        Set("FieldBrush", p.Field); Set("RuleBrush", p.Rule); Set("RuleStrongBrush", p.RuleStrong); Set("TextBrush", p.Text);
        Set("MutedBrush", p.Muted); Set("FaintBrush", p.Faint); Set("OutlineBrush", p.Outline); Set("HoverBrush", p.Hover);
        Set("OkBrush", p.Ok); Set("OkSoftBrush", p.OkSoft); Set("WarnBrush", p.Warn); Set("WarnSoftBrush", p.WarnSoft);
        Set("DangerBrush", p.Danger); Set("DangerSoftBrush", p.DangerSoft); Set("CriticalBrush", p.Critical); Set("CriticalSoftBrush", p.CriticalSoft);

        // Fluent control surfaces that should follow the Blazma palette instead of their defaults.
        foreach (var key in new[] { "ExpanderHeaderBackground", "ExpanderHeaderBackgroundPointerOver", "ExpanderHeaderBackgroundPressed", "ExpanderContentBackground" })
            Set(key, key == "ExpanderHeaderBackgroundPointerOver" ? p.PanelHover : p.Panel);
        foreach (var key in new[] { "ExpanderHeaderBorderBrush", "ExpanderContentBorderBrush", "ExpanderHeaderBorderBrushPointerOver" })
            Set(key, p.Rule);
        Set("ComboBoxDropDownBackground", p.Panel);
        var lightTheme = settings.Theme == CoreTheme.Light;
        Set("DemoBgBrush", lightTheme ? "#FFF1E0" : "#2A1D0D");
        Set("DemoBorderBrush", lightTheme ? "#F2C18C" : "#6B3D0C");
        Set("DemoTextBrush", lightTheme ? "#9A4A00" : "#FFB066");
        Set("FlyoutPresenterBackground", p.Panel);

        var accent = AccentOf(settings.Accent);
        var light = settings.Theme == CoreTheme.Light;
        var accentText = light ? Shade(accent, -0.28) : Shade(accent, 0.12);
        r["AccentBrush"] = new SolidColorBrush(light ? Shade(accent, -0.12) : accent);
        r["AccentTextBrush"] = new SolidColorBrush(accentText);
        r["AccentSoftBrush"] = new SolidColorBrush(Color.FromArgb(light ? (byte)0x1F : (byte)0x24, accent.R, accent.G, accent.B));
        r["AccentRimBrush"] = new SolidColorBrush(Shade(accent, 0.35));
        r["OnAccentBrush"] = new SolidColorBrush(settings.Accent is AccentColor.Amber ? Color.Parse("#111114") : Color.Parse("#F7F7F7"));
        r["SystemAccentColor"] = accent;
        r["SystemAccentColorLight1"] = Shade(accent, 0.12);
        r["SystemAccentColorLight2"] = Shade(accent, 0.25);
        r["SystemAccentColorLight3"] = Shade(accent, 0.35);
        r["SystemAccentColorDark1"] = Shade(accent, -0.1);
        r["SystemAccentColorDark2"] = Shade(accent, -0.22);
        r["SystemAccentColorDark3"] = Shade(accent, -0.34);

        var compact = settings.Density == Density.Compact;
        r["CardPadding"] = compact ? new Thickness(14, 11) : new Thickness(18, 16);
        r["CardRadius"] = new CornerRadius(compact ? 8 : 10);
    }

    private static Color Shade(Color c, double amount)
    {
        byte Mix(byte v) => (byte)Math.Clamp(amount >= 0 ? v + (255 - v) * amount : v * (1 + amount), 0, 255);
        return Color.FromRgb(Mix(c.R), Mix(c.G), Mix(c.B));
    }
}
