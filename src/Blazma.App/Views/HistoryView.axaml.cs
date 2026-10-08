using Avalonia.Controls;
using Avalonia.Input;
using Blazma.App.ViewModels;

namespace Blazma.App.Views;

public partial class HistoryView : UserControl
{
    public HistoryView() => InitializeComponent();

    private void OnRowDoubleTapped(object? sender, TappedEventArgs e)
    {
        if (sender is Control { DataContext: AnalysisRow row }) (DataContext as HistoryViewModel)?.OpenCommand.Execute(row);
    }
}
