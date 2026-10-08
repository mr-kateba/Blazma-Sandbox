namespace Blazma.Agent.Simulation;

internal enum ButtonAction { None, Accept, Advance }

/// <summary>
/// Which buttons a simulated user presses. Mirrors what a hurried person does with an
/// installer: accept the licence, press Next/Install/OK. Never presses anything that cancels,
/// declines, deletes or goes back.
/// </summary>
internal static class InstallerButtons
{
    private static readonly string[] Advance =
    [
        "next", "install", "install now", "i agree", "agree", "accept", "i accept", "ok", "yes", "run", "continue", "finish",
        "allow", "open", "start", "extract", "unzip", "setup", "launch", "proceed", "update", "enable", "enable content", "enable editing",
        "التالي", "تثبيت", "موافق", "نعم", "أوافق", "اوافق", "قبول", "تشغيل", "متابعة", "إنهاء", "فتح", "بدء", "استخراج", "سماح",
    ];

    private static readonly string[] Never =
    [
        "cancel", "no", "decline", "back", "browse", "uninstall", "remove", "delete", "abort", "exit", "quit", "close", "don't", "do not",
        "not accept", "disagree", "reject", "skip", "إلغاء", "لا", "رجوع", "السابق", "حذف", "إزالة", "رفض", "خروج", "إغلاق", "تخطي",
    ];

    public static string Normalize(string label)
    {
        var s = label.Replace("&", string.Empty, StringComparison.Ordinal).Replace("…", string.Empty, StringComparison.Ordinal)
            .Replace("...", string.Empty, StringComparison.Ordinal).Trim().TrimEnd('>', ' ', '.', ':').Trim().ToLowerInvariant();
        return string.Join(' ', s.Split((char[])[' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries));
    }

    /// <param name="buttonType">The BS_* type from the button's style (push, check box, radio).</param>
    public static ButtonAction Decide(string label, int buttonType)
    {
        var s = Normalize(label);
        if (s.Length is 0 or > 80) return ButtonAction.None;
        if (Never.Any(n => s == n || s.StartsWith(n + " ", StringComparison.Ordinal) || s.Contains(" " + n + " ", StringComparison.Ordinal)
                           || s.Contains("not accept", StringComparison.Ordinal) || s.Contains("لا أوافق", StringComparison.Ordinal)))
            return ButtonAction.None;

        var isChoice = buttonType is 2 or 3 or 4 or 9; // check box or radio button
        if (isChoice)
            return s.Contains("accept", StringComparison.Ordinal) || s.Contains("agree", StringComparison.Ordinal)
                   || s.Contains("أوافق", StringComparison.Ordinal) || s.Contains("قبول", StringComparison.Ordinal) || s.Contains("أقبل", StringComparison.Ordinal)
                ? ButtonAction.Accept : ButtonAction.None;

        return Advance.Contains(s, StringComparer.Ordinal) ? ButtonAction.Advance : ButtonAction.None;
    }
}
