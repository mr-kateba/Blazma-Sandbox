namespace Blazma.Agent;

/// <summary>
/// Reads a file from the shared folders while allowing the host to replace or rewrite it at the
/// same moment. File.ReadAllBytes refuses delete sharing, which can make the host's rename of
/// control files fail with "the file is being used by another process".
/// </summary>
internal static class SharedRead
{
    public static byte[] AllBytes(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }
}
