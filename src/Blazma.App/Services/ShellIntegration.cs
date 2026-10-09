using Microsoft.Win32;

namespace Blazma.App.Services;

/// <summary>
/// The "Analyze with Blazma Sandbox" entry in the Explorer right-click menu. Written under
/// HKEY_CURRENT_USER only, so it needs no administrator rights and affects only this user.
/// Choosing it starts Blazma with the file prepared on the New Analysis screen; nothing runs
/// until the user presses Start.
/// </summary>
public static class ShellIntegration
{
    public const string AnalyzeFlag = "--analyze";
    private const string KeyPath = @"Software\Classes\*\shell\BlazmaSandbox";

    /// <summary>The command Explorer runs, with the file path quoted.</summary>
    public static string Command(string exePath) => $"\"{exePath}\" {AnalyzeFlag} \"%1\"";

    /// <summary>The file to prepare at startup: "--analyze &lt;path&gt;" or a single existing file (drag onto the exe).</summary>
    public static string? StartupFile(IReadOnlyList<string> args)
    {
        if (args.Count == 2 && args[0] == AnalyzeFlag) return File.Exists(args[1]) ? Path.GetFullPath(args[1]) : null;
        if (args.Count == 1 && !args[0].StartsWith("--", StringComparison.Ordinal) && File.Exists(args[0])) return Path.GetFullPath(args[0]);
        return null;
    }

    public static bool IsSupported => OperatingSystem.IsWindows();

    /// <summary>Adds, repairs (after the app moved) or removes the menu entry. Returns false when it could not be written.</summary>
    public static bool Apply(bool enabled, string menuText)
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            if (!enabled)
            {
                Registry.CurrentUser.DeleteSubKeyTree(KeyPath, throwOnMissingSubKey: false);
                return true;
            }
            var exe = Environment.ProcessPath;
            if (exe is null || Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) return false;
            using var key = Registry.CurrentUser.CreateSubKey(KeyPath);
            key.SetValue(null, menuText);
            key.SetValue("Icon", $"\"{exe}\",0");
            using var command = key.CreateSubKey("command");
            command.SetValue(null, Command(exe));
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return false;
        }
    }
}
