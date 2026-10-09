using Blazma.App.Services;

namespace Blazma.App.Tests;

public class ShellIntegrationTests
{
    [Fact]
    public void Command_quotes_the_program_and_the_file()
    {
        Assert.Equal("\"C:\\Program Files\\Blazma\\BlazmaSandbox.exe\" --analyze \"%1\"",
            ShellIntegration.Command(@"C:\Program Files\Blazma\BlazmaSandbox.exe"));
    }

    [Fact]
    public void Startup_file_comes_from_analyze_flag_or_a_single_path()
    {
        var file = Path.GetTempFileName();
        try
        {
            Assert.Equal(Path.GetFullPath(file), ShellIntegration.StartupFile(["--analyze", file]));
            Assert.Equal(Path.GetFullPath(file), ShellIntegration.StartupFile([file]));
            Assert.Null(ShellIntegration.StartupFile(["--analyze", file + ".missing"]));
            Assert.Null(ShellIntegration.StartupFile([]));
            Assert.Null(ShellIntegration.StartupFile(["--static-worker", file]));
            Assert.Null(ShellIntegration.StartupFile(["--verbose"]));
        }
        finally { File.Delete(file); }
    }
}
