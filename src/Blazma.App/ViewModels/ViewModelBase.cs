using Blazma.App.Localization;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Blazma.App.ViewModels;

public abstract class ViewModelBase : ObservableObject
{
    protected ViewModelBase() => Loc.Instance.LanguageChanged += (_, _) => OnLanguageChanged();

    /// <summary>Recompute any strings built in code. XAML-bound text updates by itself.</summary>
    protected virtual void OnLanguageChanged() { }
}

/// <summary>A page shown in the main content area.</summary>
public abstract class PageViewModel : ViewModelBase
{
    public abstract string NavKey { get; }

    /// <summary>Called each time the page becomes visible.</summary>
    public virtual Task OnShownAsync() => Task.CompletedTask;
}
