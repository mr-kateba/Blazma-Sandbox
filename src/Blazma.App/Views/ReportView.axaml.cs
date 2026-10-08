using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Threading;
using Blazma.App.ViewModels;

namespace Blazma.App.Views;

public partial class ReportView : UserControl
{
    private ReportViewModel? _vm;

    public ReportView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (_vm is not null) _vm.ScrollTimelineTo -= OnScrollTo;
            _vm = DataContext as ReportViewModel;
            if (_vm is not null)
            {
                _vm.ScrollTimelineTo += OnScrollTo;
                _vm.Chat.CollectionChanged += (_, _) => Dispatcher.UIThread.Post(() => ChatScroll.ScrollToEnd(), DispatcherPriority.Background);
            }
        };
    }

    private void OnScrollTo(object? sender, TimelineRow row) => TimelineList.ScrollIntoView(row);

    private void OnFindingTapped(object? sender, TappedEventArgs e)
    {
        if (sender is Control { DataContext: FindingItem item }) _vm?.SelectFindingCommand.Execute(item);
    }

    private void OnAskKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) { _vm?.AskCommand.Execute(null); e.Handled = true; }
    }
}
