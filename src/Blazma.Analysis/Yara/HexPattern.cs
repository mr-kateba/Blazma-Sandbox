using System.Buffers;
using System.Globalization;

namespace Blazma.Analysis.Yara;

/// <summary>
/// A YARA hex string with jumps or alternatives, compiled to a tiny program and matched by a
/// depth-first search that remembers every (instruction, position) it has tried. That keeps
/// the work per candidate bounded by pattern size times window size, so jumps cannot cause
/// exponential backtracking. Jumps are lazy (shortest first) and alternatives are tried in
/// order, as in YARA. Hex strings without jumps or alternatives never get here: they are a
/// plain <see cref="BytePattern"/>.
/// </summary>
internal sealed class HexProgram
{
    private enum Op { Block, Jump, Split, Goto, Match }

    private sealed record Inst(Op Op, BytePattern? Block = null, int Min = 0, int Max = 0, int[]? Targets = null);

    private readonly Inst[] _program;
    private readonly BytePattern? _required;
    private readonly SearchValues<byte>? _firstBytes;
    private readonly bool _anyFirstByte;

    private HexProgram(Inst[] program, BytePattern? required)
    {
        _program = program;
        _required = required;
        var first = new bool[256];
        FirstBytes(0, first, new HashSet<int>());
        var values = Enumerable.Range(0, 256).Where(b => first[b]).Select(b => (byte)b).ToArray();
        _anyFirstByte = values.Length == 256;
        _firstBytes = _anyFirstByte ? null : SearchValues.Create(values);
    }

    /// <summary>
    /// Parses a hex string body. Returns a <see cref="BytePattern"/> when the string is fixed
    /// (bytes, wildcards and short fixed jumps only), otherwise a <see cref="HexProgram"/>.
    /// Throws <see cref="FormatException"/> with a message naming the line offset.
    /// </summary>
    public static object Parse(string body)
    {
        var parser = new HexParser(body);
        var nodes = parser.ParseTop();
        var builder = new Builder();
        builder.EmitSequence(nodes, topLevel: true);
        builder.Add(new Inst(Op.Match));
        var program = builder.Program;
        if (program.Count == 2 && program[0].Op == Op.Block) return program[0].Block!;
        return new HexProgram([.. program], builder.Required);
    }

    /// <summary>Finds match starts in ascending order and adds them (with lengths) until the cap.</summary>
    public SearchOutcome Find(ReadOnlySpan<byte> data, List<YaraHit> hits, long deadline)
    {
        if (_required is not null && _required.FindNext(data, 0, deadline) == -1) return SearchOutcome.Complete;

        var stack = new Stack<Frame>();
        var visited = new HashSet<long>();
        var pos = 0;
        var checks = 0;
        while (pos < data.Length && hits.Count < YaraLimits.MaxHitsPerString)
        {
            int candidate;
            if (_program[0].Op == Op.Block)
            {
                candidate = _program[0].Block!.FindNext(data, pos, deadline);
                if (candidate == -2) return SearchOutcome.TimedOut;
            }
            else if (_anyFirstByte) candidate = pos;
            else
            {
                var idx = data[pos..].IndexOfAny(_firstBytes!);
                candidate = idx < 0 ? -1 : pos + idx;
            }
            if (candidate < 0) break;

            // A pathological candidate can grow the set; start fresh rather than clear it every time.
            if (visited.Count > 4096) visited = new HashSet<long>();
            var end = Run(data, candidate, stack, visited, deadline);
            if (end == -2) return SearchOutcome.TimedOut;
            if (end >= 0) hits.Add(new YaraHit(candidate, end - candidate));
            pos = candidate + 1;
            if (++checks % 1024 == 0 && YaraClock.Now > deadline) return SearchOutcome.TimedOut;
        }
        return hits.Count >= YaraLimits.MaxHitsPerString ? SearchOutcome.Capped : SearchOutcome.Complete;
    }

    private readonly record struct Frame(int Pc, int Pos, int IterEnd, bool Iterating);

    /// <summary>The end of the first match starting at <paramref name="start"/>, -1 for none, -2 on timeout.</summary>
    private int Run(ReadOnlySpan<byte> data, int start, Stack<Frame> stack, HashSet<long> visited, long deadline)
    {
        stack.Clear();
        visited.Clear();
        stack.Push(new Frame(0, start, 0, false));
        var steps = 0;

        while (stack.Count > 0)
        {
            if (++steps % 4096 == 0 && YaraClock.Now > deadline) return -2;
            var f = stack.Pop();

            if (f.Iterating)
            {
                // Lazily walk the positions a jump may land on, nearest first.
                if (f.Pos > f.IterEnd) continue;
                var next = _program[f.Pc + 1];
                int landing;
                if (next.Op == Op.Block)
                {
                    var limit = (int)Math.Min(data.Length, (long)f.IterEnd + next.Block!.Length);
                    landing = next.Block.FindNext(data[..limit], f.Pos, deadline);
                    if (landing == -2) return -2;
                    if (landing < 0) continue;
                }
                else landing = f.Pos;
                stack.Push(f with { Pos = landing + 1 });
                stack.Push(new Frame(f.Pc + 1, landing, 0, false));
                continue;
            }

            if (!visited.Add(((long)f.Pc << 32) | (uint)f.Pos)) continue;
            var inst = _program[f.Pc];
            switch (inst.Op)
            {
                case Op.Block:
                    if (inst.Block!.MatchesAt(data, f.Pos)) stack.Push(new Frame(f.Pc + 1, f.Pos + inst.Block.Length, 0, false));
                    break;
                case Op.Jump:
                    var from = (long)f.Pos + inst.Min;
                    if (from > data.Length) break;
                    var to = (int)Math.Min(data.Length, (long)f.Pos + inst.Max);
                    stack.Push(new Frame(f.Pc, (int)from, to, true));
                    break;
                case Op.Split:
                    for (var i = inst.Targets!.Length - 1; i >= 0; i--) stack.Push(new Frame(inst.Targets[i], f.Pos, 0, false));
                    break;
                case Op.Goto:
                    stack.Push(new Frame(inst.Min, f.Pos, 0, false));
                    break;
                case Op.Match:
                    return f.Pos;
            }
        }
        return -1;
    }

    private void FirstBytes(int pc, bool[] first, HashSet<int> seen)
    {
        if (!seen.Add(pc)) return;
        var inst = _program[pc];
        switch (inst.Op)
        {
            case Op.Block:
                foreach (var b in inst.Block!.FirstByteValues()) first[b] = true;
                break;
            case Op.Split:
                foreach (var t in inst.Targets!) FirstBytes(t, first, seen);
                break;
            case Op.Goto:
                FirstBytes(inst.Min, first, seen);
                break;
            default:
                Array.Fill(first, true);
                break;
        }
    }

    // ---- building ---------------------------------------------------------------------

    private abstract record HexNode;
    private sealed record ByteNode(byte Value, byte Mask, bool Negated) : HexNode;
    private sealed record JumpNode(int Min, int Max) : HexNode;
    private sealed record AltNode(List<List<HexNode>> Branches) : HexNode;

    /// <summary>Fixed jumps up to this size become wildcard bytes inside a block.</summary>
    private const int InlineJump = 16;

    private sealed class Builder
    {
        private readonly List<byte> _values = [], _masks = [];
        private readonly List<bool> _negated = [];
        private int _bestRequired;

        public List<Inst> Program { get; } = [];
        public BytePattern? Required { get; private set; }

        public void Add(Inst inst) => Program.Add(inst);

        public void EmitSequence(List<HexNode> nodes, bool topLevel)
        {
            foreach (var node in nodes)
            {
                switch (node)
                {
                    case ByteNode b:
                        _values.Add(b.Value);
                        _masks.Add(b.Mask);
                        _negated.Add(b.Negated);
                        break;
                    case JumpNode j when j.Min == j.Max && j.Min <= InlineJump:
                        for (var i = 0; i < j.Min; i++) { _values.Add(0); _masks.Add(0); _negated.Add(false); }
                        break;
                    case JumpNode j:
                        Flush(topLevel);
                        if (Program.Count > 0 && Program[^1].Op == Op.Jump)
                        {
                            var prev = Program[^1];
                            Program[^1] = prev with { Min = Math.Min(prev.Min + j.Min, YaraLimits.MaxHexJump), Max = Math.Min(prev.Max + j.Max, YaraLimits.MaxHexJump) };
                        }
                        else Program.Add(new Inst(Op.Jump, Min: j.Min, Max: j.Max));
                        break;
                    case AltNode alt:
                        Flush(topLevel);
                        var splitPc = Program.Count;
                        Program.Add(new Inst(Op.Split));
                        var targets = new int[alt.Branches.Count];
                        var gotos = new List<int>();
                        for (var i = 0; i < alt.Branches.Count; i++)
                        {
                            targets[i] = Program.Count;
                            EmitSequence(alt.Branches[i], topLevel: false);
                            Flush(topLevel: false);
                            gotos.Add(Program.Count);
                            Program.Add(new Inst(Op.Goto));
                        }
                        Program[splitPc] = new Inst(Op.Split, Targets: targets);
                        foreach (var g in gotos) Program[g] = new Inst(Op.Goto, Min: Program.Count);
                        break;
                }
            }
            Flush(topLevel);
        }

        private void Flush(bool topLevel)
        {
            if (_values.Count == 0) return;
            var block = BytePattern.Masked([.. _values], [.. _masks], [.. _negated]);
            if (topLevel)
            {
                // The longest exact run outside alternatives must occur for any match at all.
                var run = 0;
                for (var i = 0; i <= _values.Count; i++)
                {
                    if (i < _values.Count && _masks[i] == 0xFF && !_negated[i]) { run++; continue; }
                    if (run > _bestRequired && run >= 2)
                    {
                        _bestRequired = run;
                        Required = BytePattern.Exact(_values.Skip(i - run).Take(run).ToArray());
                    }
                    run = 0;
                }
            }
            Program.Add(new Inst(Op.Block, Block: block));
            _values.Clear();
            _masks.Clear();
            _negated.Clear();
        }
    }

    private sealed class HexParser(string src)
    {
        private int _pos;
        private int _depth;

        private int LineOffset => src.AsSpan(0, Math.Min(_pos, src.Length)).Count('\n');

        private FormatException Error(string message) =>
            new(LineOffset > 0 ? $"{message} (hex string line +{LineOffset.ToString(CultureInfo.InvariantCulture)})" : message);

        public List<HexNode> ParseTop()
        {
            var nodes = ParseSequence();
            SkipSpace();
            if (_pos < src.Length) throw Error($"unexpected '{src[_pos]}' in hex string");
            if (nodes.Count == 0) throw Error("empty hex string");
            if (nodes[0] is JumpNode) throw Error("a hex string cannot start with a jump");
            if (nodes[^1] is JumpNode) throw Error("a hex string cannot end with a jump");
            return nodes;
        }

        private void SkipSpace()
        {
            while (_pos < src.Length && char.IsWhiteSpace(src[_pos])) _pos++;
        }

        private List<HexNode> ParseSequence()
        {
            var nodes = new List<HexNode>();
            while (true)
            {
                SkipSpace();
                if (_pos >= src.Length) return nodes;
                var c = src[_pos];
                if (c is '|' or ')') return nodes;
                if (c == '[') nodes.Add(ParseJump());
                else if (c == '(') nodes.Add(ParseAlternation());
                else if (c == '~')
                {
                    _pos++;
                    var b = ParseByte();
                    if (b.Mask == 0) throw Error("'~??' would match nothing");
                    nodes.Add(b with { Negated = true });
                }
                else nodes.Add(ParseByte());
            }
        }

        private ByteNode ParseByte()
        {
            if (_pos + 1 >= src.Length) throw Error("incomplete hex byte");
            int hi = Nibble(src[_pos]), lo = Nibble(src[_pos + 1]);
            if (hi == -2 || lo == -2) throw Error($"invalid hex byte '{src.Substring(_pos, 2)}'");
            _pos += 2;
            var value = (byte)(((hi < 0 ? 0 : hi) << 4) | (lo < 0 ? 0 : lo));
            var mask = (byte)((hi < 0 ? 0 : 0xF0) | (lo < 0 ? 0 : 0x0F));
            return new ByteNode(value, mask, false);
        }

        /// <summary>0-15 for a hex digit, -1 for '?', -2 for anything else.</summary>
        private static int Nibble(char c) => c == '?' ? -1 : char.IsAsciiHexDigit(c) ? Convert.ToInt32(c.ToString(), 16) : -2;

        private JumpNode ParseJump()
        {
            var close = src.IndexOf(']', _pos);
            if (close < 0) throw Error("unterminated jump '['");
            var body = src[(_pos + 1)..close].Replace(" ", string.Empty, StringComparison.Ordinal).Replace("\t", string.Empty, StringComparison.Ordinal);
            _pos = close + 1;
            int min, max;
            if (body == "-") { min = 0; max = YaraLimits.MaxHexJump; }
            else if (body.EndsWith('-') && TryNumber(body[..^1], out min)) max = YaraLimits.MaxHexJump;
            else if (body.Contains('-', StringComparison.Ordinal))
            {
                var parts = body.Split('-');
                if (parts.Length != 2 || !TryNumber(parts[0], out min) || !TryNumber(parts[1], out max)) throw Error($"invalid jump '[{body}]'");
                if (min > max) throw Error($"invalid jump '[{body}]': lower bound above upper bound");
                if (max > YaraLimits.MaxHexJump) throw Error($"jump '[{body}]' is larger than the limit of {YaraLimits.MaxHexJump} bytes");
            }
            else if (TryNumber(body, out min))
            {
                max = min;
                if (max > YaraLimits.MaxHexJump) throw Error($"jump '[{body}]' is larger than the limit of {YaraLimits.MaxHexJump} bytes");
            }
            else throw Error($"invalid jump '[{body}]'");
            if (min > YaraLimits.MaxHexJump) throw Error($"jump '[{body}]' is larger than the limit of {YaraLimits.MaxHexJump} bytes");
            return new JumpNode(min, max);
        }

        private static bool TryNumber(string s, out int value) =>
            int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out value);

        private AltNode ParseAlternation()
        {
            if (++_depth > YaraLimits.MaxNestingDepth) throw Error($"hex alternatives nested more than {YaraLimits.MaxNestingDepth} levels");
            _pos++; // (
            var branches = new List<List<HexNode>>();
            while (true)
            {
                var branch = ParseSequence();
                if (branch.Count == 0) throw Error("empty alternative in hex string");
                branches.Add(branch);
                if (_pos >= src.Length) throw Error("unterminated alternative '('");
                if (src[_pos++] == ')') break;
            }
            if (branches.Count < 2) throw Error("an alternative needs at least two options separated by '|'");
            _depth--;
            return new AltNode(branches);
        }
    }
}

/// <summary>How a string search ended; anything but Complete is reported as a scan warning or saturation.</summary>
internal enum SearchOutcome { Complete, Capped, TimedOut }

/// <summary>One match of one string: where it starts and how many bytes it covers.</summary>
internal readonly record struct YaraHit(int Offset, int Length);
