using Blazma.Analysis.Pipeline;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.App.ViewModels;

namespace Blazma.App.Tests;

public class AnalysisFailureTests
{
    [Fact]
    public void Progress_is_coalesced_and_the_newest_value_is_always_delivered()
    {
        var queue = new Queue<Action>();
        var delivered = new List<string>();
        var progress = new LatestProgress<string>(delivered.Add, queue.Enqueue);

        for (var i = 0; i < 10_000; i++) progress.Report("p" + i);
        Assert.Single(queue);
        queue.Dequeue()();
        Assert.Equal(["p9999"], delivered);

        progress.Report("Failed");
        Assert.Single(queue);
        queue.Dequeue()();
        Assert.Equal(["p9999", "Failed"], delivered);
        Assert.Empty(queue);
    }

    [Fact]
    public void Failure_text_explains_the_cause_in_the_current_language_and_keeps_the_reason()
    {
        var io = LiveAnalysisViewModel.FailureText(new AnalysisFailedException("The analysis failed: disk full", new IOException("disk full")));
        Assert.StartsWith(Loc.T("AnalysisErrorFiles"), io, StringComparison.Ordinal);
        Assert.EndsWith("The analysis failed: disk full", io, StringComparison.Ordinal);

        Assert.StartsWith(Loc.T("AnalysisErrorAccess"), LiveAnalysisViewModel.FailureText(new AnalysisFailedException("x", new UnauthorizedAccessException())), StringComparison.Ordinal);
        Assert.StartsWith(Loc.T("AnalysisErrorData"), LiveAnalysisViewModel.FailureText(new AnalysisFailedException("x", new System.Text.Json.JsonException())), StringComparison.Ordinal);
        Assert.StartsWith(Loc.T("AnalysisErrorTimeout"), LiveAnalysisViewModel.FailureText(new AnalysisFailedException("x", new TaskCanceledException())), StringComparison.Ordinal);
        Assert.StartsWith(Loc.T("AnalysisErrorEnvironment"), LiveAnalysisViewModel.FailureText(new AnalysisFailedException("Windows Sandbox did not start.")), StringComparison.Ordinal);
        Assert.StartsWith(Loc.T("AnalysisErrorUnexpected"), LiveAnalysisViewModel.FailureText(new InvalidOperationException("boom")), StringComparison.Ordinal);
    }

    [Fact]
    public void Crash_file_holds_the_full_exception_with_inner_exceptions_and_stack()
    {
        var folder = Directory.CreateTempSubdirectory("blz-crash").FullName;
        try
        {
            Exception ex;
            try { Throw(); throw new InvalidOperationException(); }
            catch (Exception e) { ex = e; }

            var path = App.WriteCrashFile(ex, "test", terminating: true, folder);
            Assert.NotNull(path);
            Assert.StartsWith("crash-", Path.GetFileName(path), StringComparison.Ordinal);
            var text = File.ReadAllText(path);
            Assert.Contains("outer failure", text, StringComparison.Ordinal);
            Assert.Contains("inner cause", text, StringComparison.Ordinal);
            Assert.Contains(nameof(Throw), text, StringComparison.Ordinal);
            Assert.Contains("process terminating", text, StringComparison.Ordinal);
        }
        finally { Directory.Delete(folder, recursive: true); }

        static void Throw()
        {
            try { throw new IOException("inner cause"); }
            catch (IOException inner) { throw new InvalidOperationException("outer failure", inner); }
        }
    }
}
