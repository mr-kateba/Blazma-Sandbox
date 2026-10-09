namespace Blazma.Cli;

/// <summary>A parsed command: verb, positional arguments and --options.</summary>
public sealed class CommandLine
{
    public required string Verb { get; init; }
    public IReadOnlyList<string> Positionals { get; init; } = [];
    public IReadOnlyDictionary<string, string> Options { get; init; } = new Dictionary<string, string>();
    public IReadOnlySet<string> Flags { get; init; } = new HashSet<string>();

    public string? Option(string name) => Options.TryGetValue(name, out var v) ? v : null;
    public bool Flag(string name) => Flags.Contains(name);

    /// <summary>Options that take a value; anything else starting with "--" is a flag.</summary>
    private static readonly HashSet<string> ValueOptions = new(StringComparer.Ordinal)
    {
        "env", "profile", "network", "duration", "report", "format", "out", "limit", "lang", "data", "summary", "password", "entry",
    };

    private static readonly HashSet<string> KnownFlags = new(StringComparer.Ordinal)
    {
        "json", "allow-internet", "lookup", "recursive", "interactive", "pcap", "no-screenshots", "help", "verbose",
    };

    /// <summary>Parses arguments; returns an error message instead of throwing on bad input.</summary>
    public static (CommandLine? Command, string? Error) Parse(IReadOnlyList<string> args)
    {
        if (args.Count == 0) return (new CommandLine { Verb = "help" }, null);
        var verb = args[0].ToLowerInvariant();
        if (verb is "-h" or "--help" or "/?") verb = "help";
        if (verb is "-v" or "--version") verb = "version";

        var positionals = new List<string>();
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        var flags = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 1; i < args.Count; i++)
        {
            var arg = args[i];
            if (arg == "--")
            {
                positionals.AddRange(args.Skip(i + 1));
                break;
            }
            if (!arg.StartsWith("--", StringComparison.Ordinal) || arg.Length == 2)
            {
                positionals.Add(arg);
                continue;
            }
            var name = arg[2..];
            string? inline = null;
            var eq = name.IndexOf('=');
            if (eq > 0) { inline = name[(eq + 1)..]; name = name[..eq]; }
            name = name.ToLowerInvariant();

            if (ValueOptions.Contains(name))
            {
                var value = inline ?? (i + 1 < args.Count ? args[++i] : null);
                if (string.IsNullOrEmpty(value)) return (null, $"--{name} needs a value.");
                options[name] = value;
            }
            else if (KnownFlags.Contains(name) && inline is null) flags.Add(name);
            else return (null, $"Unknown option --{name}.");
        }
        return (new CommandLine { Verb = verb, Positionals = positionals, Options = options, Flags = flags }, null);
    }
}
