using Blazma.Core.Text;

namespace Blazma.Core.Findings;

/// <summary>
/// The verdict wording is deliberately about behaviour. Blazma never says a file
/// "is malware"; it says what the observed behaviour amounts to.
/// </summary>
public enum Verdict
{
    LowRisk,
    Suspicious,
    HighRiskBehavior,
    CriticalBehavior,
}

public sealed record RiskThresholds(int Suspicious = 20, int High = 45, int Critical = 75)
{
    public static RiskThresholds Default { get; } = new();

    public bool IsValid => Suspicious is > 0 and < 100 && High > Suspicious && Critical > High && Critical <= 100;

    public Verdict VerdictFor(int score) =>
        score >= Critical ? Verdict.CriticalBehavior :
        score >= High ? Verdict.HighRiskBehavior :
        score >= Suspicious ? Verdict.Suspicious :
        Verdict.LowRisk;
}

public sealed record ScoreContribution(string FindingId, string RuleId, LocalizedText Title, FindingCategory Category, int Points, bool Capped);

public sealed record RiskAssessment(int Score, Verdict Verdict, IReadOnlyList<ScoreContribution> Contributions)
{
    public static RiskAssessment Empty { get; } = new(0, Verdict.LowRisk, []);

    public const string Disclaimer =
        "Blazma evaluates observed behavior. A high score does not by itself prove that a file is malicious.";

    public const string DisclaimerAr =
        "يقيّم Blazma السلوك الذي تمت ملاحظته. النتيجة المرتفعة وحدها لا تثبت أن الملف خبيث.";
}
