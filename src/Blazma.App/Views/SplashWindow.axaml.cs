using Avalonia.Controls;

namespace Blazma.App.Views;

public partial class SplashWindow : Window
{
    public SplashWindow() => InitializeComponent();

    public void ShowError(string message)
    {
        Status.Text = "Blazma could not start: " + message;
        Bar.IsVisible = false;
    }
}
