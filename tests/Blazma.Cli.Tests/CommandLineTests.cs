using Blazma.Cli;
using Blazma.Core.Findings;

namespace Blazma.Cli.Tests;

public class CommandLineTests
{
    [Fact]
    public void Parses_verb_positionals_values_and_flags()
    {
        var (c, error) = CommandLine.Parse(["analyze", "a b.exe", "--env", "demo", "--duration=60", "--json"]);
        Assert.Null(error);
        Assert.Equal("analyze", c!.Verb);
        Assert.Equal(["a b.exe"], c.Positionals);
        Assert.Equal("demo", c.Option("env"));
        Assert.Equal("60", c.Option("duration"));
        Assert.True(c.Flag("json"));
        Assert.False(c.Flag("lookup"));
    }

    [Fact]
    public void No_arguments_means_help()
    {
        var (c, _) = CommandLine.Parse([]);
        Assert.Equal("help", c!.Verb);
    }

    [Theory]
    [InlineData("--nope")]
    [InlineData("--json=yes")]
    public void Rejects_unknown_options(string arg)
    {
        var (c, error) = CommandLine.Parse(["analyze", "x", arg]);
        Assert.Null(c);
        Assert.NotNull(error);
    }

    [Fact]
    public void A_value_option_needs_a_value()
    {
        var (c, error) = CommandLine.Parse(["analyze", "x", "--env"]);
        Assert.Null(c);
        Assert.Contains("--env", error);
    }

    [Fact]
    public void Double_dash_ends_options()
    {
        var (c, _) = CommandLine.Parse(["static", "--", "--weird-name.exe"]);
        Assert.Equal(["--weird-name.exe"], c!.Positionals);
    }

    [Theory]
    [InlineData(Verdict.LowRisk, ExitCodes.Ok)]
    [InlineData(Verdict.Suspicious, ExitCodes.Suspicious)]
    [InlineData(Verdict.HighRiskBehavior, ExitCodes.HighRisk)]
    [InlineData(Verdict.CriticalBehavior, ExitCodes.Critical)]
    public void Exit_code_follows_the_verdict(Verdict verdict, int expected) => Assert.Equal(expected, ExitCodes.For(verdict));

    [Fact]
    public void Batch_keeps_the_most_severe_code()
    {
        Assert.Equal(ExitCodes.HighRisk, ExitCodes.Combine(ExitCodes.Suspicious, ExitCodes.HighRisk));
        Assert.Equal(ExitCodes.Suspicious, ExitCodes.Combine(ExitCodes.Suspicious, ExitCodes.Error));
        Assert.Equal(ExitCodes.Error, ExitCodes.Combine(ExitCodes.Ok, ExitCodes.Error));
    }

    [Theory]
    [InlineData("plain.exe", "plain.exe")]
    [InlineData("=HYPERLINK(1).exe", "\"'=HYPERLINK(1).exe\"")]
    [InlineData("a,b.exe", "\"a,b.exe\"")]
    [InlineData("say \"hi\",x", "\"say \"\"hi\"\",x\"")]
    public void Csv_quotes_and_neutralizes_formulas(string input, string expected) => Assert.Equal(expected, CliApp.Csv(input));
}
