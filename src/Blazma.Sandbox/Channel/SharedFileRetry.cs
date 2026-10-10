namespace Blazma.Sandbox.Channel;

/// <summary>
/// Retries file operations that fail only because another process has the file open: an
/// antivirus scan, the search indexer, or Windows Sandbox's shared-folder service holding a
/// handle for a moment after the guest read the file. Other errors are not retried.
/// </summary>
public sealed class SharedFileRetry(TimeSpan total, TimeSpan firstDelay)
{
    /// <summary>About 15 seconds in total, starting with short pauses.</summary>
    public static SharedFileRetry Default { get; } = new(TimeSpan.FromSeconds(15), TimeSpan.FromMilliseconds(100));

    private const int ErrorSharingViolation = 32;
    private const int ErrorLockViolation = 33;

    /// <summary>True for "the process cannot access the file because it is being used by another process" and lock violations.</summary>
    public static bool IsSharingViolation(Exception ex) =>
        ex is IOException io && (io.HResult & 0xFFFF) is ErrorSharingViolation or ErrorLockViolation;

    public void Run(Action action)
    {
        var deadline = DateTime.UtcNow + total;
        var delay = firstDelay;
        while (true)
        {
            try
            {
                action();
                return;
            }
            catch (IOException ex) when (IsSharingViolation(ex) && DateTime.UtcNow + delay < deadline)
            {
                Thread.Sleep(delay);
                delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, 2000));
            }
        }
    }

    /// <summary>Like <see cref="Run"/>, but returns false instead of throwing when the file stays in use.</summary>
    public bool TryRun(Action action)
    {
        try
        {
            Run(action);
            return true;
        }
        catch (IOException ex) when (IsSharingViolation(ex))
        {
            return false;
        }
    }
}
