namespace Blazma.Core.Events;

public enum EventCategory
{
    Process,
    File,
    Registry,
    Network,
    Dns,
    Persistence,
    System,
}

public enum EventAction
{
    ProcessStart,
    ProcessExit,

    FileCreate,
    FileWrite,
    FileDelete,
    FileRename,

    RegistryKeyCreate,
    RegistryValueSet,
    RegistryValueDelete,
    RegistryKeyDelete,

    NetworkConnect,
    NetworkListen,
    NetworkSend,

    DnsQuery,

    /// <summary>An HTTP request received by the simulated internet.</summary>
    HttpRequest,

    /// <summary>A TLS connection to the simulated internet; carries the requested server name.</summary>
    TlsHandshake,

    ServiceInstall,
    ScheduledTaskCreate,

    MonitoringStarted,
    MonitoringInterrupted,
    SampleExecuted,
    SampleExited,
    AnalysisNote,
}

/// <summary>
/// Five levels, always shown with an icon and a label as well as a colour so the
/// meaning never depends on colour alone.
/// </summary>
public enum Severity
{
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public static class EventActionExtensions
{
    public static EventCategory DefaultCategory(this EventAction action) => action switch
    {
        EventAction.ProcessStart or EventAction.ProcessExit or EventAction.SampleExecuted or EventAction.SampleExited => EventCategory.Process,
        EventAction.FileCreate or EventAction.FileWrite or EventAction.FileDelete or EventAction.FileRename => EventCategory.File,
        EventAction.RegistryKeyCreate or EventAction.RegistryValueSet or EventAction.RegistryValueDelete or EventAction.RegistryKeyDelete => EventCategory.Registry,
        EventAction.NetworkConnect or EventAction.NetworkListen or EventAction.NetworkSend => EventCategory.Network,
        EventAction.DnsQuery => EventCategory.Dns,
        EventAction.HttpRequest or EventAction.TlsHandshake => EventCategory.Network,
        EventAction.ServiceInstall or EventAction.ScheduledTaskCreate => EventCategory.Persistence,
        _ => EventCategory.System,
    };
}
