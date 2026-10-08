using System.Globalization;
using Avalonia;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace Blazma.App.Controls;

/// <summary>Resource key (e.g. "IconDashboard") → icon geometry.</summary>
public sealed class IconConverter : IValueConverter
{
    public static readonly IconConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is string key && Application.Current?.TryGetResource(key, Application.Current.ActualThemeVariant, out var res) == true ? res as Geometry : null;

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Resource key → brush, for state colours chosen by view models.</summary>
public sealed class BrushKeyConverter : IValueConverter
{
    public static readonly BrushKeyConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is string key && Application.Current?.TryGetResource(key, Application.Current.ActualThemeVariant, out var res) == true ? res as IBrush : Brushes.Gray;

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
