using System.Text;
using Blazma.App.Services;

namespace Blazma.App.Tests;

public class SingleInstanceTests
{
    [Fact]
    public void Open_message_round_trips_for_an_existing_file()
    {
        var file = Path.GetTempFileName();
        try
        {
            var (valid, path) = SingleInstance.Decode(SingleInstance.Encode(file));
            Assert.True(valid);
            Assert.Equal(file, path);
            Assert.Equal((true, (string?)null), SingleInstance.Decode(SingleInstance.Encode(null)));
        }
        finally { File.Delete(file); }
    }

    [Theory]
    [InlineData("")]
    [InlineData("run\nC:/x.exe")]
    [InlineData("open\nrelative.exe")]
    [InlineData("open\n/definitely/missing/file.exe")]
    public void Malformed_or_unsafe_messages_are_ignored(string text) =>
        Assert.False(SingleInstance.Decode(Encoding.UTF8.GetBytes(text)).Valid);

    [Fact]
    public void Oversized_and_invalid_utf8_messages_are_ignored()
    {
        Assert.False(SingleInstance.Decode(new byte[9000]).Valid);
        Assert.False(SingleInstance.Decode([0x6F, 0x70, 0xFF, 0xFE]).Valid);
    }

    [Fact]
    public async Task Second_instance_hands_its_file_to_the_first()
    {
        var scope = Guid.NewGuid().ToString("N");
        var file = Path.GetTempFileName();
        try
        {
            using var first = SingleInstance.Acquire(scope);
            Assert.True(first.IsFirst);
            var received = new TaskCompletionSource<string?>();
            first.Listen(f => received.TrySetResult(f));

            var sent = await Task.Run(() =>
            {
                using var second = SingleInstance.Acquire(scope);
                Assert.False(second.IsFirst);
                return second.TrySendToFirst(file, TimeSpan.FromSeconds(5));
            });

            Assert.True(sent);
            Assert.Equal(file, await received.Task.WaitAsync(TimeSpan.FromSeconds(10)));
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public void Nobody_listening_means_start_normally()
    {
        using var lonely = SingleInstance.Acquire(Guid.NewGuid().ToString("N"));
        Assert.False(lonely.TrySendToFirst(null, TimeSpan.FromMilliseconds(200)));
    }
}
