using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Platform.Storage;
using Blazma.App.ViewModels;

namespace Blazma.App.Views;

public partial class DashboardView : UserControl
{
    public DashboardView()
    {
        InitializeComponent();
        DropZone.AddHandler(DragDrop.DragEnterEvent, (_, _) => Vm?.SetDragOver(true));
        DropZone.AddHandler(DragDrop.DragLeaveEvent, (_, _) => Vm?.SetDragOver(false));
        DropZone.AddHandler(DragDrop.DragOverEvent, (_, e) => e.DragEffects = DragDropEffects.Copy);
        DropZone.AddHandler(DragDrop.DropEvent, async (_, e) =>
        {
            Vm?.SetDragOver(false);
            var file = e.DataTransfer.TryGetFiles()?.FirstOrDefault()?.TryGetLocalPath();
            if (file is not null && Vm is { } vm) await vm.Main.PrepareFileAsync(file);
        });
    }

    private DashboardViewModel? Vm => DataContext as DashboardViewModel;

    private void OnRowTapped(object? sender, TappedEventArgs e)
    {
        if (sender is Control { DataContext: AnalysisRow row }) Vm?.OpenCommand.Execute(row);
    }

    private void OnSandboxPressed(object? sender, PointerPressedEventArgs e) => Vm?.Main.Navigate("Sandbox");
}
