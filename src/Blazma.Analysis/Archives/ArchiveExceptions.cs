namespace Blazma.Analysis.Archives;

/// <summary>
/// The archive needs a password, or the one given is wrong. A separate type so the UI can ask
/// for a password instead of reporting a broken file.
/// </summary>
public sealed class ArchivePasswordException : Exception
{
    public ArchivePasswordException() : base("The archive is encrypted and the password is missing or wrong.") { }
    public ArchivePasswordException(string message) : base(message) { }
    public ArchivePasswordException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// An entry broke a safety limit (size, compression ratio, link) while it was being read. The
/// partial output has already been deleted when this is thrown.
/// </summary>
public sealed class ArchiveLimitException : Exception
{
    public ArchiveLimitException() : base("The archive entry exceeds a safety limit.") { }
    public ArchiveLimitException(string message) : base(message) { }
    public ArchiveLimitException(string message, Exception innerException) : base(message, innerException) { }
}
