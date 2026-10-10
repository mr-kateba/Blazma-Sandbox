using Blazma.Sandbox.Channel;

namespace Blazma.Sandbox.Tests;

public class SharedFileRetryTests
{
    private static IOException InUse() => new("The process cannot access the file because it is being used by another process.") { HResult = unchecked((int)0x80070020) };

    private static readonly SharedFileRetry Quick = new(TimeSpan.FromSeconds(2), TimeSpan.FromMilliseconds(5));

    [Fact]
    public void Retries_a_file_in_use_until_it_is_free()
    {
        var attempts = 0;
        Quick.Run(() => { if (++attempts < 4) throw InUse(); });
        Assert.Equal(4, attempts);
    }

    [Fact]
    public void Other_errors_are_not_retried()
    {
        var attempts = 0;
        Assert.Throws<FileNotFoundException>(() => Quick.Run(() => { attempts++; throw new FileNotFoundException("gone"); }));
        Assert.Equal(1, attempts);
    }

    [Fact]
    public void Gives_up_after_the_time_budget()
    {
        var shortRetry = new SharedFileRetry(TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(10));
        Assert.False(shortRetry.TryRun(() => throw InUse()));
        Assert.Throws<IOException>(() => shortRetry.Run(() => throw InUse()));
    }

    [Theory]
    [InlineData(unchecked((int)0x80070020), true)]
    [InlineData(unchecked((int)0x80070021), true)]
    [InlineData(unchecked((int)0x80070005), false)]
    [InlineData(unchecked((int)0x80070002), false)]
    public void Recognizes_sharing_and_lock_violations(int hresult, bool expected) =>
        Assert.Equal(expected, SharedFileRetry.IsSharingViolation(new IOException("x") { HResult = hresult }));

    [Fact]
    public void Write_atomic_replaces_the_file_and_leaves_no_temporary_file()
    {
        var folder = Directory.CreateTempSubdirectory("blazma-retry");
        try
        {
            var path = Path.Combine(folder.FullName, "control.json");
            File.WriteAllText(path, "old");
            ChannelFiles.WriteAtomic(path, "new"u8.ToArray());
            Assert.Equal("new", File.ReadAllText(path));
            Assert.Single(Directory.GetFiles(folder.FullName));
            using var shared = ChannelFiles.OpenShared(path);
            Assert.Equal(3, shared.Length);
        }
        finally { folder.Delete(recursive: true); }
    }
}
