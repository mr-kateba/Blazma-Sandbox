using System.Xml.Linq;
using Blazma.Core.Analysis;

namespace Blazma.Sandbox.Isolation;

/// <summary>
/// The Windows Sandbox configuration Blazma generates. Every option that would widen the
/// boundary is off: no GPU passthrough, no clipboard, no printers, no audio or video input,
/// protected client on, networking off unless the user explicitly enabled it for this run.
/// Only two folders are mapped: <c>in</c> read-only and <c>out</c> writable.
/// </summary>
public sealed record IsolationPolicy
{
    public const string SandboxRoot = @"C:\Blazma";
    public const string SandboxIn = @"C:\Blazma\in";
    public const string SandboxOut = @"C:\Blazma\out";

    public required string HostInFolder { get; init; }
    public required string HostOutFolder { get; init; }
    public NetworkPolicy Network { get; init; } = NetworkPolicy.Disabled;
    public int MemoryMb { get; init; } = 4096;

    public string LogonCommand => $"{SandboxIn}\\agent\\Blazma.Agent.exe \"{SandboxIn}\" \"{SandboxOut}\"";

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
                    new XElement("ReadOnly", "false"))),
            new XElement("LogonCommand",
                new XElement("Command", LogonCommand)));
        return doc.ToString();
    }
}
