using System.Text;

namespace Blazma.Sandbox.Providers.VirtualMachine;

/// <summary>Builds PowerShell text from untrusted values without letting them become code.</summary>
public static class PowerShellText
{
    /// <summary>PowerShell treats all of these as single quotes inside a single-quoted string.</summary>
    private static readonly char[] SingleQuotes = ['\'', '‘', '’', '‚', '‛'];

    /// <summary>
    /// A single-quoted literal: no variable expansion, no sub-expressions, no escape characters.
    /// Every quote character (including the typographic ones PowerShell also accepts) is doubled,
    /// which is the only escape a single-quoted string has. NUL is removed.
    /// </summary>
    public static string Quote(string value)
    {
        var builder = new StringBuilder(value.Length + 2).Append('\'');
        foreach (var c in value)
        {
            if (c == '\0') continue;
            if (Array.IndexOf(SingleQuotes, c) >= 0) builder.Append(c);
            builder.Append(c);
        }
        return builder.Append('\'').ToString();
    }

    /// <summary>An array literal of single-quoted strings: <c>@('a', 'b')</c>.</summary>
    public static string QuoteArray(IEnumerable<string> values) => "@(" + string.Join(", ", values.Select(Quote)) + ")";

    /// <summary>For <c>-EncodedCommand</c>: base64 of UTF-16LE. Only for scripts without secrets (it is a command-line argument).</summary>
    public static string EncodeCommand(string script) => Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

    /// <summary>
    /// The single line sent to <c>powershell.exe -Command -</c> on standard input. The script itself
    /// travels as base64 of UTF-8, so its encoding and line structure survive the console's stdin
    /// handling (which executes line by line and garbles multi-line blocks and non-ASCII text).
    /// </summary>
    public static string Bootstrap(string script) =>
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8; & ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
        + Convert.ToBase64String(new UTF8Encoding(false).GetBytes(script)) + "'))))\n";

    /// <summary>Reverses <see cref="Bootstrap"/>; used by tests and diagnostics.</summary>
    public static string? DecodeBootstrap(string stdin)
    {
        const string marker = "FromBase64String('";
        var start = stdin.IndexOf(marker, StringComparison.Ordinal);
        if (start < 0) return null;
        start += marker.Length;
        var end = stdin.IndexOf('\'', start);
        return end < 0 ? null : Encoding.UTF8.GetString(Convert.FromBase64String(stdin[start..end]));
    }
}
