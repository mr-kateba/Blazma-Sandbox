using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Blazma.App.ViewModels;
using Blazma.Core.Settings;

namespace Blazma.App.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        TitleBar.PointerPressed += (_, e) =>
        {
            if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed && e.Source is not TextBox) BeginMoveDrag(e);
        };
        TitleBar.DoubleTapped += (_, _) => ToggleMaximize();
        MinimizeButton.Click += (_, _) => WindowState = WindowState.Minimized;
        MaximizeButton.Click += (_, _) => ToggleMaximize();
        CloseButton.Click += (_, _) => Close();
        AddHandler(KeyDownEvent, OnKeyDown, RoutingStrategies.Tunnel);
        DataContextChanged += (_, _) =>
        {
            if (DataContext is not MainViewModel vm) return;
            vm.SearchFocusRequested += (_, _) => SearchBox.Focus();
            vm.PropertyChanged += (_, e) => { if (e.PropertyName == nameof(MainViewModel.Motion)) ApplyMotion(vm); };
            vm.Palette.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(CommandPaletteViewModel.IsOpen) && vm.Palette.IsOpen)
                    Avalonia.Threading.Dispatcher.UIThread.Post(() => PaletteBox.Focus());
            };
            ApplyMotion(vm);
        };
        Root.Classes.Set("rtl", Blazma.App.Localization.Loc.Instance.IsArabic);
        Blazma.App.Localization.Loc.Instance.LanguageChanged += (_, _) => Root.Classes.Set("rtl", Blazma.App.Localization.Loc.Instance.IsArabic);
    }

    private void ApplyMotion(MainViewModel vm) => Root.Classes.Set("motion", vm.Motion);

    private void ToggleMaximize() => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnKeyDown(object? sender, KeyEventArgs e)
    {
        if (DataContext is not MainViewModel vm) return;

        if (vm.Palette.IsOpen)
        {
            switch (e.Key)
            {
                case Key.Down: vm.Palette.Move(1); e.Handled = true; return;
                case Key.Up: vm.Palette.Move(-1); e.Handled = true; return;
                case Key.Enter: _ = vm.Palette.Run(null); e.Handled = true; return;
            }
        }
        if (e.Key == Key.Escape)
        {
            e.Handled = vm.CloseOverlay();
            return;
        }

        // Shortcuts come from settings so users can rebind them.
        var shortcuts = vm.Settings.Current.Shortcuts;
        bool Is(string command)
        {
            try { return KeyGesture.Parse(shortcuts.Get(command)).Matches(e); }
            catch (Exception ex) when (ex is ArgumentException or FormatException) { return false; }
        }

        if (Is("CommandPalette")) { vm.Palette.Open(); e.Handled = true; }
        else if (Is("NewAnalysis")) { _ = vm.PickAndPrepareAsync(); e.Handled = true; }
        else if (Is("Search")) { SearchBox.Focus(); SearchBox.SelectAll(); e.Handled = true; }
        else if (Is("OpenHistory")) { vm.Navigate("History"); e.Handled = true; }
        else if (Is("OpenSettings")) { vm.Navigate("Settings"); e.Handled = true; }
        else if (Is("ExportReport")) { vm.ExportCurrentCommand.Execute(null); e.Handled = true; }
        else if (Is("ToggleSidebar")) { vm.ToggleSidebarCommand.Execute(null); e.Handled = true; }
        else if (Is("SwitchLanguage")) { vm.SwitchLanguageCommand.Execute(null); e.Handled = true; }
    }

    private void OnScrimPressed(object? sender, PointerPressedEventArgs e) => (DataContext as MainViewModel)?.Palette.Close();

    private void OnPaletteItemTapped(object? sender, TappedEventArgs e)
    {
        if (sender is Control { DataContext: PaletteCommand cmd } && DataContext is MainViewModel vm) _ = vm.Palette.Run(cmd);
    }
}
