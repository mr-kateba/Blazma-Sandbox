using Blazma.Core.Attack;

namespace Blazma.Reporting.Tests;

public class AttackCatalogTests
{
    [Fact]
    public void Known_techniques_resolve_with_tactics_in_matrix_order()
    {
        Assert.True(AttackCatalog.TryGet("T1547.001", out var run));
        Assert.Equal("Registry Run Keys / Startup Folder", run.Name);
        Assert.Equal(["persistence", "privilege-escalation"], run.Tactics);
        Assert.True(run.IsSubTechnique);
        Assert.Equal("https://attack.mitre.org/techniques/T1547/001", run.Url);

        Assert.True(AttackCatalog.TryGet(" t1059 ", out var interp));
        Assert.Equal("Command and Scripting Interpreter", interp.Name);
        Assert.False(interp.IsSubTechnique);
    }

    [Fact]
    public void Revoked_and_unknown_ids_are_not_in_the_catalog()
    {
        Assert.False(AttackCatalog.TryGet("T1562.001", out _)); // revoked in ATT&CK v19
        Assert.True(AttackCatalog.TryGetReplacement("T1562.001", out var replacement));
        Assert.True(AttackCatalog.TryGet(replacement.Id, out _));
        Assert.False(AttackCatalog.TryGet("T9999", out _));
        Assert.False(AttackCatalog.TryGet(null, out _));
        Assert.False(AttackCatalog.TryGetReplacement("T1059", out _));
    }

    [Fact]
    public void Tactics_are_ordered_and_named_in_both_languages()
    {
        Assert.Equal("TA0043", AttackCatalog.Tactics[0].Id);
        Assert.Equal("TA0040", AttackCatalog.Tactics[^1].Id);
        Assert.All(AttackCatalog.Tactics, t =>
        {
            Assert.Matches(@"^TA\d{4}$", t.Id);
            Assert.False(string.IsNullOrWhiteSpace(t.Name));
            Assert.Contains(t.NameAr, c => c is >= '؀' and <= 'ۿ');
        });
        Assert.Equal(AttackCatalog.Tactics.Count, AttackCatalog.Tactics.Select(t => t.ShortName).Distinct().Count());
        Assert.Equal("Persistence", AttackCatalog.Tactic("persistence")?.Name);
        Assert.Equal("persistence", AttackCatalog.Tactic("ta0003")?.ShortName);
    }

    [Fact]
    public void Every_technique_is_well_formed()
    {
        Assert.True(AttackCatalog.Count > 500);
        var shortNames = AttackCatalog.Tactics.Select(t => t.ShortName).ToHashSet();
        Assert.All(AttackCatalog.All, t =>
        {
            Assert.Matches(@"^T\d{4}(\.\d{3})?$", t.Id);
            Assert.NotEmpty(t.Name);
            Assert.NotEmpty(t.Tactics);
            Assert.All(t.Tactics, x => Assert.Contains(x, shortNames));
        });
    }
}
