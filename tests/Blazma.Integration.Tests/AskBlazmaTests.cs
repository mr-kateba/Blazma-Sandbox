using Blazma.Core.Findings;
using Blazma.Intelligence;

namespace Blazma.Integration.Tests;

public class AskBlazmaTests
{
    [Theory]
    [InlineData("Why is the score high?", QuestionIntent.Score)]
    [InlineData("ليش أعطيت الملف High Risk؟", QuestionIntent.Score)]
    [InlineData("Did it create persistence?", QuestionIntent.Persistence)]
    [InlineData("Which process connected to the internet?", QuestionIntent.Network)]
    [InlineData("What did this program change?", QuestionIntent.Changes)]
    [InlineData("ماذا فعل هذا البرنامج؟", QuestionIntent.Summary)]
    public void Classifies_questions_in_both_languages(string question, QuestionIntent intent) =>
        Assert.Equal(intent, AskBlazma.Classify(question));

    [Fact]
    public async Task Score_answers_cite_findings_and_keep_the_disclaimer()
    {
        await using var f = await Fixture.CreateAsync();
        var r = await f.RunDemoAsync();
        var answer = new AskBlazma().Ask(r, "Why is the score high?", "en");
        Assert.Contains("related behaviors", answer.Text, StringComparison.Ordinal);
        Assert.Contains(answer.Parts, p => p.FindingIds.Count > 0 && p.Provenance == Provenance.RuleInference);
        Assert.Contains(RiskAssessment.Disclaimer, answer.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Persistence_answers_are_facts_with_event_references()
    {
        await using var f = await Fixture.CreateAsync();
        var r = await f.RunDemoAsync();
        var answer = new AskBlazma().Ask(r, "هل أنشأ آلية بقاء؟", "ar");
        Assert.All(answer.Parts, p => Assert.Equal(Provenance.ObservedFact, p.Provenance));
        Assert.All(answer.Parts, p => Assert.NotEmpty(p.EventSequences));
        Assert.StartsWith("نعم", answer.Parts[0].Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Says_so_when_nothing_was_observed_instead_of_inventing()
    {
        await using var f = await Fixture.CreateAsync();
        var r = await f.RunDemoAsync("viewer-tool.exe");
        var answer = new AskBlazma().Ask(r, "Did it create persistence?", "en");
        Assert.StartsWith("No persistence attempt", answer.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Answers_about_a_named_process()
    {
        await using var f = await Fixture.CreateAsync();
        var r = await f.RunDemoAsync();
        var answer = new AskBlazma().Ask(r, "schtasks", "en");
        Assert.Equal(QuestionIntent.Specific, answer.Intent);
        Assert.NotEmpty(answer.Parts[0].EventSequences);
    }
}
