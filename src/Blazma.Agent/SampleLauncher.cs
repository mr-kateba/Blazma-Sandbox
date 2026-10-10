using System.Buffers.Binary;
using System.ComponentModel;

namespace Blazma.Agent;

/// <summary>How the sample is started: a program and its arguments, through the Windows shell or directly.</summary>
internal sealed record LaunchPlan(string FileName, string Arguments, bool UseShellExecute)
{
    public string CommandLine => Arguments.Length == 0 ? $"\"{FileName}\"" : $"\"{FileName}\" {Arguments}";
}

internal enum PeKind { None, Program, Library }

/// <summary>
/// Decides how to start a sample the way Windows would when a user opens it. Pure, so the rules
/// can be tested anywhere. Everything goes through the shell (as a double-click would), which also
/// gives console programs and scripts their own visible window instead of sharing the agent's
/// console, except a program whose extension Windows would not run (the shell would only ask
/// which app to open it with).
/// </summary>
internal static class SampleLauncher
{
    private const ushort ImageFileDll = 0x2000;

    /// <summary>Extensions the shell runs as programs.</summary>
    private static readonly string[] ProgramExtensions = [".exe", ".com", ".scr", ".pif"];

    public static LaunchPlan Plan(string path, ReadOnlySpan<byte> head, string systemFolder)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        var kind = Inspect(head);
        return ext switch
        {
            ".msi" => new(Path.Combine(systemFolder, "msiexec.exe"), $"/i \"{path}\" /qn", true),
            ".ps1" => new(Path.Combine(systemFolder, @"WindowsPowerShell\v1.0\powershell.exe"), $"-NoProfile -ExecutionPolicy Bypass -File \"{path}\"", true),
            // cmd strips the outer pair of quotes, so a name with spaces or ( ) & still arrives quoted.
            ".bat" or ".cmd" => new(Path.Combine(systemFolder, "cmd.exe"), $"/c \"\"{path}\"\"", true),
            ".vbs" or ".vbe" or ".js" or ".jse" or ".wsf" => new(Path.Combine(systemFolder, "wscript.exe"), $"\"{path}\"", true),
            ".dll" or ".ocx" => Rundll(path, systemFolder),
            _ when ProgramExtensions.Contains(ext) => new(path, string.Empty, true),
            _ when kind == PeKind.Program => new(path, string.Empty, false),
            _ when kind == PeKind.Library && ext != ".cpl" => Rundll(path, systemFolder),
            // Documents, shortcuts, .hta, .cpl, .url and the rest: whatever the file association says.
            _ => new(path, string.Empty, true),
        };
    }

    /// <summary>Whether the first bytes of a file are a Windows program, a DLL, or neither.</summary>
    public static PeKind Inspect(ReadOnlySpan<byte> head)
    {
        if (head.Length < 0x40 || head[0] != (byte)'M' || head[1] != (byte)'Z') return PeKind.None;
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(head[0x3C..]);
        // Headers beyond what was read: an MZ file is most likely a program.
        if (peOffset < 0x40 || peOffset > head.Length - 24) return PeKind.Program;
        if (!head.Slice(peOffset, 4).SequenceEqual("PE\0\0"u8)) return PeKind.Program;
        var characteristics = BinaryPrimitives.ReadUInt16LittleEndian(head[(peOffset + 22)..]);
        return (characteristics & ImageFileDll) != 0 ? PeKind.Library : PeKind.Program;
    }

    /// <summary>A message for the analyst when the sample could not be copied or started.</summary>
    public static string DescribeFailure(Exception ex)
    {
        for (var e = ex; e is not null; e = e.InnerException)
        {
            // ERROR_VIRUS_INFECTED / ERROR_VIRUS_DELETED
            if (e is Win32Exception { NativeErrorCode: 225 or 226 } || e.HResult is unchecked((int)0x800700E1) or unchecked((int)0x800700E2))
                return "The sample could not be started: Microsoft Defender in the sandbox blocked it as malware or potentially unwanted software.";
        }
        var hint = ex is FileNotFoundException ? " The file may have been removed by Microsoft Defender in the sandbox." : string.Empty;
        return $"The sample could not be started: {ex.Message}{hint}";
    }

    private static LaunchPlan Rundll(string path, string systemFolder) =>
        new(Path.Combine(systemFolder, "rundll32.exe"), $"\"{path}\",#1", true);
}
