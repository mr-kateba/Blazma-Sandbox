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
}
