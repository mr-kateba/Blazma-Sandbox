using Blazma.Core.Findings;

namespace Blazma.Cli;

/// <summary>Process exit codes. A script can branch on the verdict without parsing output.</summary>
public static class ExitCodes
{
    public const int Ok = 0;
    public const int Error = 1;
    public const int Usage = 2;
    public const int EnvironmentNotReady = 3;
    public const int Cancelled = 4;
    public const int Suspicious = 10;
    public const int HighRisk = 20;
    public const int Critical = 30;

    public static int For(Verdict verdict) => verdict switch
    {
        Verdict.Suspicious => Suspicious,
        Verdict.HighRiskBehavior => HighRisk,
        Verdict.CriticalBehavior => Critical,
        _ => Ok,
    };

    /// <summary>For a batch: the most severe outcome wins, an error only when nothing worse was seen.</summary>
    public static int Combine(int a, int b) => Rank(a) >= Rank(b) ? a : b;

    private static int Rank(int code) => code switch
    {
        Critical => 7,
        HighRisk => 6,
        Suspicious => 5,
        Error => 4,
        EnvironmentNotReady => 3,
        Cancelled => 2,
        Usage => 1,
        _ => 0,
    };
}
