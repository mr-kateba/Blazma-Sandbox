using System.Xml.Linq;
using Blazma.Core.Analysis;

namespace Blazma.Sandbox.Isolation;

/// <summary>
/// The Windows Sandbox configuration Blazma generates. Every option that would widen the
/// boundary is off: no GPU passthrough, no clipboard, no printers, no audio or video input,
/// protected client on, networking off unless the user explicitly enabled it for this run.
/// Only <c>out</c> is writable; <c>in</c> and the optional startup folder are read-only.
/// <para>
/// The agent is started by <see cref="LauncherName"/>, which runs it once however many times it
/// is started and records its output in <c>out</c>. It is started by the logon command and,
/// because some Windows Sandbox releases (2026, Windows 11 24H2 and later) skip the logon
/// command, also from the sandbox user's Startup folder and, where available, <c>wsb exec</c>.
/// </para>
/// </summary>
public sealed record IsolationPolicy
{
    public const string SandboxRoot = @"C:\Blazma";
    public const string SandboxIn = @"C:\Blazma\in";
    public const string SandboxOut = @"C:\Blazma\out";

    /// <summary>The Startup folder of the sandbox user (WDAGUtilityAccount); programs in it run when the user signs in.</summary>
    public const string SandboxStartup = @"C:\Users\WDAGUtilityAccount\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup";

    /// <summary>The launcher script, in <c>in</c> and in the startup folder.</summary>
    public const string LauncherName = "blazma-agent.cmd";

    public required string HostInFolder { get; init; }
    public required string HostOutFolder { get; init; }
    public NetworkPolicy Network { get; init; } = NetworkPolicy.Disabled;
    public int MemoryMb { get; init; } = 4096;

    /// <summary>Host folder holding only the launcher, mapped read-only onto <see cref="SandboxStartup"/>; null to leave the Startup folder alone.</summary>
    public string? HostStartupFolder { get; init; }

    /// <summary>No spaces and no quotes, so it reads the same however the sandbox splits it.</summary>
    public string LogonCommand => $@"cmd.exe /c {SandboxIn}\{LauncherName} logon";

    /// <summary>For <c>wsb exec</c>: returns at once and leaves the agent running in the signed-in user's session.</summary>
    public static string ExecCommand => $@"cmd.exe /c start /min cmd.exe /c {SandboxIn}\{LauncherName} exec";

    /// <summary>
    /// The launcher. Only the first start runs the agent (creating a folder is atomic). Starts other than
    /// the logon command must also be elevated: the agent needs administrator rights for kernel tracing.
    /// The agent's console output and exit code are appended to <c>out\agent-start.txt</c>.
    /// </summary>
    public static string LauncherScript()
    {
        var log = $@"{SandboxOut}\{Channel.AgentDiagnostics.StartLogFile}";
        string[] lines =
        [
            "@echo off",
            "rem Blazma Sandbox: starts the monitoring agent once. Started by the logon command, the Startup folder or wsb exec.",
            "setlocal",
            "set \"SOURCE=%~1\"",
            "if not defined SOURCE set \"SOURCE=startup\"",
            $"set \"LOG={log}\"",
            "if /i not \"%SOURCE%\"==\"logon\" (",
            "  fltmc >nul 2>&1 || (>>\"%LOG%\" echo [%SOURCE%] %DATE% %TIME% not running as administrator, left to another start& exit /b 5)",
            ")",
            "mkdir \"%ProgramData%\\Blazma.agent-started\" 2>nul || (>>\"%LOG%\" echo [%SOURCE%] %DATE% %TIME% the agent was already started& exit /b 0)",
            ">>\"%LOG%\" echo [%SOURCE%] %DATE% %TIME% starting the agent",
            $"\"{SandboxIn}\\{Contracts.Protocol.AgentFolder}\\{Contracts.Protocol.AgentExecutable}\" \"{SandboxIn}\" \"{SandboxOut}\" >>\"%LOG%\" 2>&1",
            ">>\"%LOG%\" echo [%SOURCE%] %DATE% %TIME% the agent exited with code %ERRORLEVEL%",
        ];
        return string.Join("\r\n", lines) + "\r\n";
    }

    public string ToWsbXml()
    {
        var doc = new XElement("Configuration",
            new XElement("vGPU", "Disable"),
            new XElement("Networking", Network == NetworkPolicy.Enabled ? "Default" : "Disable"),
            new XElement("AudioInput", "Disable"),
            new XElement("VideoInput", "Disable"),
            new XElement("PrinterRedirection", "Disable"),
            new XElement("ClipboardRedirection", "Disable"),
            new XElement("ProtectedClient", "Enable"),
            new XElement("MemoryInMB", Math.Clamp(MemoryMb, 2048, 32768)),
            new XElement("MappedFolders",
                new XElement("MappedFolder",
                    new XElement("HostFolder", HostInFolder),
                    new XElement("SandboxFolder", SandboxIn),
                    new XElement("ReadOnly", "true")),
                new XElement("MappedFolder",
                    new XElement("HostFolder", HostOutFolder),
                    new XElement("SandboxFolder", SandboxOut),
                    new XElement("ReadOnly", "false")),
                HostStartupFolder is null ? null : new XElement("MappedFolder",
                    new XElement("HostFolder", HostStartupFolder),
                    new XElement("SandboxFolder", SandboxStartup),
                    new XElement("ReadOnly", "true"))),
            new XElement("LogonCommand",
                new XElement("Command", LogonCommand)));
        return doc.ToString();
    }
}
