using Avalonia.Controls;
using Avalonia.Threading;
using Blazma.App.ViewModels;

namespace Blazma.App.Views;

public partial class LiveAnalysisView : UserControl
{
    private LiveAnalysisViewModel? _vm;

    public LiveAnalysisView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (_vm is not null) _vm.RowsAdded -= OnRowsAdded;
            _vm = DataContext as LiveAnalysisViewModel;
            if (_vm is not null) _vm.RowsAdded += OnRowsAdded;
        };
    }

    private void OnRowsAdded(object? sender, EventArgs e)
    {
        if (_vm is not { AutoScroll: true } || _vm.Events.Count == 0) return;
        Dispatcher.UIThread.Post(() => EventsList.ScrollIntoView(_vm.Events.Count - 1), DispatcherPriority.Background);
    }
}
