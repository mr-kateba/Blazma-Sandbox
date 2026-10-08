namespace Blazma.Intelligence.Tests;

/// <summary>A fact that only runs on Windows and is reported as skipped elsewhere.</summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Needs Windows (DPAPI).";
    }
}
