using System.Text;
using System.Text.RegularExpressions;
using Blazma.Sandbox.Processes;

namespace Blazma.Sandbox.Providers.VirtualMachine.VirtualBox;

/// <summary>A VM as listed by <c>VBoxManage list vms</c>.</summary>
internal sealed record VBoxMachine(string Name, string Id);

/// <summary>
/// Runs VBoxManage and parses its output. Every value is a separate argument. After the VM and
/// snapshot names are resolved once, only their UUIDs are passed, so a name that looks like an
/// option (<c>--help</c>) or contains quotes can never change the meaning of a command.
/// </summary>
internal sealed partial class VBoxManage(IProcessRunner runner, string executable, TimeSpan timeout)
{
    public const string GuestAdditionsVersionProperty = "/VirtualBox/GuestAdd/Version";

    /// <summary>VM states in which the VM is not running and a snapshot can be restored.</summary>
    private static readonly HashSet<string> StoppedStates = new(StringComparer.OrdinalIgnoreCase) { "poweroff", "saved", "aborted", "aborted-saved", "teleported" };

    public string Executable => executable;

    public Task<ProcessResult> RunAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken, TimeSpan? timeoutOverride = null) =>
        runner.RunAsync(new ProcessRequest(executable, arguments)
        {
            Timeout = timeoutOverride ?? timeout,
            MaxOutputChars = 4 * 1024 * 1024,
            OutputEncoding = Encoding.UTF8,
        }, cancellationToken);

    /// <summary>Runs and throws a readable error when VBoxManage fails.</summary>
    public async Task<ProcessResult> RequireAsync(IReadOnlyList<string> arguments, string what, CancellationToken cancellationToken, TimeSpan? timeoutOverride = null)
    {
        var result = await RunAsync(arguments, cancellationToken, timeoutOverride).ConfigureAwait(false);
        if (!result.Succeeded) throw new InvalidOperationException($"VirtualBox could not {what} ({result.Describe()}).");
        return result;
    }

    /// <summary>Parses <c>"name" {uuid}</c> lines. The name is everything between the first and the last quote.</summary>
    public static IReadOnlyList<VBoxMachine> ParseVmList(string output) =>
        output.Split('\n')
            .Select(l => VmLineRegex().Match(l.TrimEnd('\r')))
            .Where(m => m.Success)
            .Select(m => new VBoxMachine(m.Groups["name"].Value, m.Groups["id"].Value))
            .ToList();

    /// <summary>
    /// Parses <c>--machinereadable</c> output: <c>key="value"</c>, <c>"key"="value"</c> or <c>key=value</c>.
    /// Quoted values are unescaped (<c>\"</c>, <c>\\</c>, <c>\n</c>). The first occurrence of a key wins.
    /// </summary>
    public static Dictionary<string, string> ParseMachineReadable(string output)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var position = 0;
            var key = ReadToken(line, ref position, untilEquals: true);
            if (key is null || position >= line.Length || line[position] != '=') continue;
            position++;
            var value = ReadToken(line, ref position, untilEquals: false) ?? string.Empty;
            values.TryAdd(key, value);
        }
        return values;
    }

    private static string? ReadToken(string line, ref int position, bool untilEquals)
    {
        if (position >= line.Length) return null;
        if (line[position] != '"')
        {
            var end = untilEquals ? line.IndexOf('=', position) : line.Length;
            if (end < 0) return null;
            var token = line[position..end];
            position = end;
            return token;
        }
        var builder = new StringBuilder();
        for (position++; position < line.Length; position++)
        {
            var c = line[position];
            if (c == '\\' && position + 1 < line.Length)
            {
                var next = line[++position];
                builder.Append(next == 'n' ? '\n' : next);
                continue;
            }
            if (c == '"') { position++; return builder.ToString(); }
            builder.Append(c);
        }
        return builder.ToString();
    }

    /// <summary>UUIDs of every snapshot with this exact name (snapshot names need not be unique).</summary>
    public static IReadOnlyList<string> FindSnapshots(Dictionary<string, string> snapshotList, string name) =>
        snapshotList
            .Where(kv => kv.Key.StartsWith("SnapshotName", StringComparison.Ordinal) && kv.Value == name)
            .Select(kv => snapshotList.GetValueOrDefault("SnapshotUUID" + kv.Key["SnapshotName".Length..]))
            .OfType<string>()
            .Where(id => Guid.TryParse(id, out _))
            .ToList();

    /// <summary>Adapters that are enabled and attached to anything ("none" is disabled, "null" is "Not attached").</summary>
    public static IReadOnlyList<string> ConnectedAdapters(Dictionary<string, string> vmInfo) =>
        vmInfo
            .Select(kv => (Match: NicRegex().Match(kv.Key), kv.Value))
            .Where(x => x.Match.Success && !x.Value.Equals("none", StringComparison.OrdinalIgnoreCase) && !x.Value.Equals("null", StringComparison.OrdinalIgnoreCase))
            .OrderBy(x => int.Parse(x.Match.Groups[1].ValueSpan, System.Globalization.CultureInfo.InvariantCulture))
            .Select(x => $"adapter {x.Match.Groups[1].Value}: {Clean(x.Value)}")
            .ToList();

    public static string State(Dictionary<string, string> vmInfo) => vmInfo.GetValueOrDefault("VMState") ?? "unknown";

    public static bool IsRunning(Dictionary<string, string> vmInfo) => !StoppedStates.Contains(State(vmInfo));

    /// <summary>Parses the guest listing printed by <see cref="VirtualBoxSession"/> (<c>length|name</c> per line).</summary>
    public static IReadOnlyList<Channel.GuestFile> ParseListing(string output) =>
        output.Split('\n')
            .Select(l => ListingRegex().Match(l.TrimEnd('\r')))
            .Where(m => m.Success && long.TryParse(m.Groups[1].ValueSpan, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out _))
            .Select(m => new Channel.GuestFile(m.Groups[2].Value, long.Parse(m.Groups[1].ValueSpan, System.Globalization.CultureInfo.InvariantCulture)))
            .ToList();

    private static string Clean(string s) => s.Length > 40 ? s[..40] : new string(s.Where(c => !char.IsControl(c)).ToArray());

    [GeneratedRegex(@"^""(?<name>.*)"" \{(?<id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}$", RegexOptions.CultureInvariant)]
    private static partial Regex VmLineRegex();

    [GeneratedRegex(@"^nic(\d{1,2})$", RegexOptions.CultureInvariant)]
    private static partial Regex NicRegex();

    [GeneratedRegex(@"^(\d{1,19})\|([^|]+)$", RegexOptions.CultureInvariant)]
    private static partial Regex ListingRegex();
}
