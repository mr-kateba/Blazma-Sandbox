using Avalonia.Threading;
using Blazma.Core.Settings;
using Blazma.Storage;

namespace Blazma.App.Services;

/// <summary>Holds the live settings object and saves it shortly after the last change.</summary>
public sealed class SettingsService(SettingsStore store)
{
    private DispatcherTimer? _saveTimer;

    public BlazmaSettings Current { get; private set; } = store.Load();

    public event EventHandler? Changed;

    /// <summary>Call after changing any property of <see cref="Current"/>.</summary>
    public void Touch()
    {
        Changed?.Invoke(this, EventArgs.Empty);
        _saveTimer ??= new DispatcherTimer(TimeSpan.FromMilliseconds(600), DispatcherPriority.Background, async (_, _) =>
        {
            _saveTimer!.Stop();
            await store.SaveAsync(Current);
        });
        _saveTimer.Stop();
        _saveTimer.Start();
    }

    public Task SaveNowAsync() => store.SaveAsync(Current);

    public void Reset()
    {
        var onboarding = Current.General.OnboardingCompleted;
        Current = new BlazmaSettings();
        Current.General.OnboardingCompleted = onboarding;
        Touch();
    }
}
