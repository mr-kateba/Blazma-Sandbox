using Blazma.Core.Analysis;

namespace Blazma.Analysis.Tests;

public class StateMachineTests
{
    [Fact]
    public void Happy_path_is_strictly_linear()
    {
        var path = AnalysisStateMachine.Path;
        for (var i = 0; i + 1 < path.Count; i++)
            Assert.True(AnalysisStateMachine.CanTransition(path[i], path[i + 1]), $"{path[i]} -> {path[i + 1]}");
        Assert.False(AnalysisStateMachine.CanTransition(AnalysisStage.Preparing, AnalysisStage.Analyzing));
        Assert.False(AnalysisStateMachine.CanTransition(AnalysisStage.Analyzing, AnalysisStage.Booting));
    }

    [Theory]
    [InlineData(AnalysisStage.Preparing)]
    [InlineData(AnalysisStage.Booting)]
    [InlineData(AnalysisStage.Analyzing)]
    [InlineData(AnalysisStage.GeneratingReport)]
    public void Any_active_stage_can_fail_or_be_cancelled(AnalysisStage stage)
    {
        Assert.True(AnalysisStateMachine.CanTransition(stage, AnalysisStage.Failed));
        Assert.True(AnalysisStateMachine.CanTransition(stage, AnalysisStage.Cancelled));
    }

    [Theory]
    [InlineData(AnalysisStage.Completed)]
    [InlineData(AnalysisStage.Failed)]
    [InlineData(AnalysisStage.Cancelled)]
    public void Terminal_stages_never_move(AnalysisStage stage)
    {
        foreach (var to in Enum.GetValues<AnalysisStage>())
            Assert.False(AnalysisStateMachine.CanTransition(stage, to));
    }
}
