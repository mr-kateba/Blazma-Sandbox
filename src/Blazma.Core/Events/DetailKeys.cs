namespace Blazma.Core.Events;

/// <summary>Well-known keys of <see cref="AnalysisEvent.Details"/>.</summary>
public static class DetailKeys
{
    public const string ImagePath = "ImagePath";
    public const string CommandLine = "CommandLine";
    public const string User = "User";
    public const string IntegrityLevel = "IntegrityLevel";
    public const string Architecture = "Architecture";
    public const string ExitCode = "ExitCode";
    public const string IsSample = "IsSample";
    public const string Sha256 = "Sha256";
    public const string Size = "Size";
    public const string NewPath = "NewPath";
    public const string ValueName = "ValueName";
    public const string ValueData = "ValueData";
    public const string OldValue = "OldValue";
    public const string ValueType = "ValueType";
    public const string RemoteAddress = "RemoteAddress";
    public const string RemotePort = "RemotePort";
    public const string LocalPort = "LocalPort";
    public const string Protocol = "Protocol";
    public const string BytesSent = "BytesSent";
    public const string BytesReceived = "BytesReceived";
    public const string QueryName = "QueryName";
    public const string QueryResult = "QueryResult";
    public const string ServiceName = "ServiceName";
    public const string TaskName = "TaskName";
    public const string Reason = "Reason";
    public const string Signer = "Signer";
    public const string HttpMethod = "HttpMethod";
    public const string HttpPath = "HttpPath";
    public const string HttpHost = "HttpHost";
    public const string UserAgent = "UserAgent";
    public const string ServerName = "ServerName";
    public const string BodyPreview = "BodyPreview";

    /// <summary>"true" when the event was answered by the simulated internet, not a real server.</summary>
    public const string Simulated = "Simulated";

    /// <summary>
    /// Outcome of a <see cref="EventAction.NetworkConnect"/>: one of <see cref="ConnectStatus"/>. Absent on
    /// events from older agents, which only reported connections that succeeded.
    /// </summary>
    public const string Status = "Status";

    /// <summary>Windows status code of a failed connection attempt or lookup, as hexadecimal (e.g. "0xC000023C").</summary>
    public const string ErrorCode = "ErrorCode";

    /// <summary>How many times the process tried to reach the same address and port (retries are counted, not repeated).</summary>
    public const string Attempts = "Attempts";
}

/// <summary>Values of <see cref="DetailKeys.Status"/> on network connection events.</summary>
public static class ConnectStatus
{
    /// <summary>The connection was established.</summary>
    public const string Connected = "Connected";

    /// <summary>The program asked Windows to connect (or send); whether it worked is not known yet.</summary>
    public const string Attempted = "Attempted";

    /// <summary>Windows reported that the attempt failed (no network, no route, refused, timed out or blocked).</summary>
    public const string Failed = "Failed";
}
