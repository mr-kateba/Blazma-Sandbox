namespace Blazma.Analysis.Yara;

/// <summary>
/// Every bound the YARA engine enforces. Rules come from users and the internet and the data
/// is hostile, so nothing a rule or a sample does may grow without a limit.
/// </summary>
public static class YaraLimits
{
    /// <summary>Matches recorded per string. <c>#a</c> saturates here and the search stops.</summary>
    public const int MaxHitsPerString = 1000;

    /// <summary>Strings listed per reported match, and hits listed per string.</summary>
    public const int MaxReportedStrings = 10;
    public const int MaxReportedHitsPerString = 3;

    /// <summary>Bytes of a match shown in its preview.</summary>
    public const int PreviewBytes = 32;

    /// <summary>Nesting of parentheses, operators, loops, hex alternatives and regex groups.</summary>
    public const int MaxNestingDepth = 64;

    /// <summary>Depth of a compiled condition tree; bounds recursion during evaluation.</summary>
    public const int MaxExpressionDepth = 256;

    /// <summary>Largest hex jump. Unbounded jumps (<c>[n-]</c>, <c>[-]</c>) stop here.</summary>
    public const int MaxHexJump = 65_535;

    /// <summary>Largest regex repetition bound (the same limit YARA uses).</summary>
    public const int MaxRegexRepeat = 32_767;

    /// <summary>Values one <c>for</c> loop may iterate over; a larger range makes the loop undefined.</summary>
    public const int MaxLoopIterations = 1_000_000;

    /// <summary>Evaluation steps for one rule's condition (loop iterations and string checks).</summary>
    public const long MaxEvaluationSteps = 20_000_000;

    /// <summary>Wall-clock time one string may spend searching before it gives up.</summary>
    public static readonly TimeSpan StringSearchBudget = TimeSpan.FromSeconds(5);

    /// <summary>Wall-clock time a whole scan may spend searching strings.</summary>
    public static readonly TimeSpan ScanBudget = TimeSpan.FromSeconds(60);

    /// <summary>Rule files read from a folder, and the largest file read.</summary>
    public const int MaxRuleFiles = 256;
    public const long MaxRuleFileBytes = 2 * 1024 * 1024;
}
