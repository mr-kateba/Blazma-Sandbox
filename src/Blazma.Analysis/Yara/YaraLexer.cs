using System.Globalization;
using System.Text;

namespace Blazma.Analysis.Yara;

internal enum TokenKind
{
    End,
    Identifier,
    Number,
    Text,
    Hex,
    Regex,
    Punct,

    /// <summary><c>$a</c>, or <c>$</c> alone inside a <c>for ... of</c> loop.</summary>
    StringId,

    /// <summary><c>$a*</c> or <c>$*</c>.</summary>
    StringWildcard,
    StringCount,
    StringOffset,
    StringLength,
}

/// <summary>One token. For strings Text holds the raw source between the delimiters; for regexes Flags holds the trailing flags.</summary>
internal readonly record struct Token(TokenKind Kind, string Text, long Number, int Line, string Flags = "")
{
    public bool Is(TokenKind kind, string text) => Kind == kind && Text == text;
    public bool IsPunct(string text) => Kind == TokenKind.Punct && Text == text;
    public bool IsWord(string text) => Kind == TokenKind.Identifier && Text == text;

    public string Describe() => Kind switch
    {
        TokenKind.End => "end of file",
        TokenKind.Text => "a text string",
        TokenKind.Hex => "a hex string",
        TokenKind.Regex => "a regular expression",
        TokenKind.Number => Number.ToString(CultureInfo.InvariantCulture),
        _ => $"'{Text}'",
    };
}

/// <summary>A syntax error: the whole file is rejected with <c>file:line: message</c>.</summary>
internal sealed class YaraSyntaxException(int line, string message) : Exception(message)
{
    public int Line { get; } = line;
}

/// <summary>
/// Hand-written lexer. Regexes and hex strings are only valid right after <c>=</c> in the
/// strings section (and after <c>matches</c>), so the parser asks for them explicitly
/// instead of the lexer guessing whether <c>/</c> starts a regex.
/// </summary>
internal sealed class YaraLexer(string source)
{
    private readonly List<Token> _buffer = [];
    private int _pos;
    private int _line = 1;

    public static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "all", "and", "any", "ascii", "at", "base64", "base64wide", "condition", "contains", "defined",
        "endswith", "entrypoint", "false", "filesize", "for", "fullword", "global", "icontains",
        "iendswith", "iequals", "import", "in", "include", "int16", "int16be", "int32", "int32be",
        "int8", "int8be", "istartswith", "matches", "meta", "nocase", "none", "not", "of", "or",
        "private", "rule", "startswith", "strings", "them", "true", "uint16", "uint16be", "uint32",
        "uint32be", "uint8", "uint8be", "wide", "xor",
    };

    public int Line => _buffer.Count > 0 ? _buffer[0].Line : _line;

    public Token Peek(int ahead = 0)
    {
        while (_buffer.Count <= ahead) _buffer.Add(Read());
        return _buffer[ahead];
    }

    public Token Next()
    {
        var t = Peek();
        _buffer.RemoveAt(0);
        return t;
    }

    /// <summary>Reads the value of a string definition: a text string, a hex string or a regex.</summary>
    public Token ReadStringValue()
    {
        EnsureNoLookahead();
        SkipTrivia();
        if (_pos >= source.Length) throw new YaraSyntaxException(_line, "expected a string value, found end of file");
        return source[_pos] switch
        {
            '"' => ReadText(),
            '{' => ReadHex(),
            '/' => ReadRegex(),
            _ => throw new YaraSyntaxException(_line, "expected a text string, hex string or regular expression after '='"),
        };
    }

    /// <summary>Reads the regex operand of <c>matches</c>.</summary>
    public Token ReadRegexOperand()
    {
        EnsureNoLookahead();
        SkipTrivia();
        if (_pos >= source.Length || source[_pos] != '/') throw new YaraSyntaxException(_line, "expected a regular expression after 'matches'");
        return ReadRegex();
    }

    /// <summary>Whether the next non-blank source character is <paramref name="c"/> (only with no lookahead buffered).</summary>
    public bool RawNextIs(char c)
    {
        if (_buffer.Count > 0) return false;
        SkipTrivia();
        return _pos < source.Length && source[_pos] == c;
    }

    private void EnsureNoLookahead()
    {
        if (_buffer.Count > 0) throw new InvalidOperationException("lexer lookahead is not empty");
    }

    private void SkipTrivia()
    {
        while (_pos < source.Length)
        {
            var c = source[_pos];
            if (c == '\n') { _line++; _pos++; }
            else if (char.IsWhiteSpace(c)) _pos++;
            else if (c == '/' && At(1) == '/')
            {
                while (_pos < source.Length && source[_pos] != '\n') _pos++;
            }
            else if (c == '/' && At(1) == '*')
            {
                var startLine = _line;
                _pos += 2;
                while (_pos < source.Length && !(source[_pos] == '*' && At(1) == '/'))
                {
                    if (source[_pos] == '\n') _line++;
                    _pos++;
                }
                if (_pos >= source.Length) throw new YaraSyntaxException(startLine, "unterminated comment");
                _pos += 2;
            }
            else break;
        }
    }

    private char At(int offset) => _pos + offset < source.Length ? source[_pos + offset] : '\0';

    private static bool IsIdentChar(char c) => char.IsAsciiLetterOrDigit(c) || c == '_';

    private Token Read()
    {
        SkipTrivia();
        if (_pos >= source.Length) return new Token(TokenKind.End, string.Empty, 0, _line);
        var c = source[_pos];

        if (char.IsAsciiLetter(c) || c == '_')
        {
            var start = _pos;
            while (_pos < source.Length && IsIdentChar(source[_pos])) _pos++;
            if (_pos - start > 128) throw new YaraSyntaxException(_line, "identifier longer than 128 characters");
            return new Token(TokenKind.Identifier, source[start.._pos], 0, _line);
        }
        if (char.IsAsciiDigit(c)) return ReadNumber();
        if (c == '"') return ReadText();

        if (c is '$' or '#' or '@' or '!')
        {
            if (c == '!' && At(1) == '=') { _pos += 2; return new Token(TokenKind.Punct, "!=", 0, _line); }
            var start = _pos++;
            while (_pos < source.Length && IsIdentChar(source[_pos])) _pos++;
            var name = source[start.._pos];
            if (c == '$' && At(0) == '*')
            {
                _pos++;
                return new Token(TokenKind.StringWildcard, name, 0, _line);
            }
            var kind = c switch { '$' => TokenKind.StringId, '#' => TokenKind.StringCount, '@' => TokenKind.StringOffset, _ => TokenKind.StringLength };
            return new Token(kind, name, 0, _line);
        }

        foreach (var two in TwoCharPunct)
        {
            if (c == two[0] && At(1) == two[1])
            {
                _pos += 2;
                return new Token(TokenKind.Punct, two, 0, _line);
            }
        }
        if ("{}()[]:=,.+-*\\%&|^~<>".Contains(c, StringComparison.Ordinal))
        {
            _pos++;
            return new Token(TokenKind.Punct, c.ToString(), 0, _line);
        }
        if (c == '/')
            throw new YaraSyntaxException(_line, "unexpected '/': YARA divides with '\\', and regular expressions are only allowed as string definitions");
        throw new YaraSyntaxException(_line, $"unexpected character '{c}'");
    }

    private static readonly string[] TwoCharPunct = ["..", "<<", ">>", "<=", ">=", "=="];

    private Token ReadNumber()
    {
        var start = _pos;
        long value;
        if (source[_pos] == '0' && (At(1) is 'x' or 'X'))
        {
            _pos += 2;
            var digits = _pos;
            while (_pos < source.Length && char.IsAsciiHexDigit(source[_pos])) _pos++;
            if (!long.TryParse(source.AsSpan(digits, _pos - digits), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value) || _pos == digits || _pos - digits > 16)
                throw new YaraSyntaxException(_line, $"invalid hexadecimal number '{source[start.._pos]}'");
        }
        else if (source[_pos] == '0' && At(1) == 'o')
        {
            _pos += 2;
            var digits = _pos;
            value = 0;
            while (_pos < source.Length && source[_pos] is >= '0' and <= '7')
            {
                if (value > (long.MaxValue >> 3)) throw new YaraSyntaxException(_line, "octal number too large");
                value = (value << 3) | (long)(source[_pos++] - '0');
            }
            if (_pos == digits) throw new YaraSyntaxException(_line, "invalid octal number");
        }
        else
        {
            while (_pos < source.Length && char.IsAsciiDigit(source[_pos])) _pos++;
            if (!long.TryParse(source.AsSpan(start, _pos - start), NumberStyles.None, CultureInfo.InvariantCulture, out value))
                throw new YaraSyntaxException(_line, $"number '{source[start.._pos]}' is too large");
            if (At(0) == '.' && char.IsAsciiDigit(At(1)))
                throw new YaraSyntaxException(_line, "floating-point numbers are not supported");
            if ((At(0) is 'K' or 'M') && At(1) == 'B' && !IsIdentChar(At(2)))
            {
                var factor = At(0) == 'K' ? 1024L : 1024L * 1024;
                _pos += 2;
                if (value > long.MaxValue / factor) throw new YaraSyntaxException(_line, "size is too large");
                value *= factor;
            }
        }
        if (IsIdentChar(At(0))) throw new YaraSyntaxException(_line, $"invalid number '{source[start..(_pos + 1)]}'");
        return new Token(TokenKind.Number, source[start.._pos], value, _line);
    }

    private Token ReadText()
    {
        var line = _line;
        _pos++; // opening quote
        var start = _pos;
        while (true)
        {
            if (_pos >= source.Length || source[_pos] == '\n') throw new YaraSyntaxException(line, "unterminated text string");
            var c = source[_pos];
            if (c == '\\') { _pos += 2; continue; }
            if (c == '"') break;
            _pos++;
        }
        var raw = source[start.._pos];
        _pos++;
        return new Token(TokenKind.Text, raw, 0, line);
    }

    private Token ReadHex()
    {
        var line = _line;
        _pos++; // {
        var sb = new StringBuilder();
        while (true)
        {
            if (_pos >= source.Length) throw new YaraSyntaxException(line, "unterminated hex string");
            var c = source[_pos];
            if (c == '}') { _pos++; break; }
            if (c == '/' && At(1) == '/')
            {
                while (_pos < source.Length && source[_pos] != '\n') _pos++;
                continue;
            }
            if (c == '/' && At(1) == '*')
            {
                _pos += 2;
                while (_pos < source.Length && !(source[_pos] == '*' && At(1) == '/'))
                {
                    if (source[_pos] == '\n') { _line++; sb.Append('\n'); }
                    _pos++;
                }
                if (_pos >= source.Length) throw new YaraSyntaxException(line, "unterminated comment in hex string");
                _pos += 2;
                sb.Append(' ');
                continue;
            }
            if (c == '\n') _line++;
            sb.Append(c);
            _pos++;
        }
        return new Token(TokenKind.Hex, sb.ToString(), 0, line);
    }

    private Token ReadRegex()
    {
        var line = _line;
        _pos++; // opening slash
        var sb = new StringBuilder();
        while (true)
        {
            if (_pos >= source.Length || source[_pos] == '\n') throw new YaraSyntaxException(line, "unterminated regular expression");
            var c = source[_pos];
            if (c == '\\')
            {
                if (_pos + 1 >= source.Length || source[_pos + 1] == '\n') throw new YaraSyntaxException(line, "unterminated regular expression");
                if (source[_pos + 1] == '/') sb.Append('/');
                else sb.Append(c).Append(source[_pos + 1]);
                _pos += 2;
                continue;
            }
            if (c == '/') break;
            sb.Append(c);
            _pos++;
        }
        _pos++;
        var flagsStart = _pos;
        while (_pos < source.Length && source[_pos] is 'i' or 's') _pos++;
        if (IsIdentChar(At(0))) throw new YaraSyntaxException(line, $"unknown regular expression flag '{At(0)}' (only 'i' and 's' exist)");
        if (sb.Length == 0) throw new YaraSyntaxException(line, "empty regular expression");
        return new Token(TokenKind.Regex, sb.ToString(), 0, line, source[flagsStart.._pos]);
    }
}

/// <summary>Escape sequences of YARA text strings: \" \\ \n \t \r \xHH.</summary>
internal static class YaraEscapes
{
    /// <summary>Text strings are bytes: characters become UTF-8 (as YARA reads the file), \xHH a raw byte.</summary>
    public static byte[] ToBytes(string raw, out string? error)
    {
        error = null;
        var bytes = new List<byte>(raw.Length);
        Span<byte> utf8 = stackalloc byte[4];
        for (var i = 0; i < raw.Length; i++)
        {
            var c = raw[i];
            if (c == '\\')
            {
                var b = Escape(raw, ref i, out error);
                if (error is not null) return [];
                bytes.Add(b);
            }
            else if (c < 0x80) bytes.Add((byte)c);
            else
            {
                var len = char.IsHighSurrogate(c) && i + 1 < raw.Length
                    ? Encoding.UTF8.GetBytes(raw.AsSpan(i++, 2), utf8)
                    : Encoding.UTF8.GetBytes(raw.AsSpan(i, 1), utf8);
                for (var k = 0; k < len; k++) bytes.Add(utf8[k]);
            }
        }
        return [.. bytes];
    }

    /// <summary>Metadata values are shown to people, so they stay text; \xHH becomes that code point.</summary>
    public static string ToText(string raw, out string? error)
    {
        error = null;
        if (!raw.Contains('\\', StringComparison.Ordinal)) return raw;
        var sb = new StringBuilder(raw.Length);
        for (var i = 0; i < raw.Length; i++)
        {
            if (raw[i] != '\\') { sb.Append(raw[i]); continue; }
            var b = Escape(raw, ref i, out error);
            if (error is not null) return string.Empty;
            sb.Append((char)b);
        }
        return sb.ToString();
    }

    private static byte Escape(string raw, ref int i, out string? error)
    {
        error = null;
        if (i + 1 >= raw.Length) { error = "text string ends with a lone '\\'"; return 0; }
        var e = raw[++i];
        switch (e)
        {
            case '"': return (byte)'"';
            case '\\': return (byte)'\\';
            case 'n': return (byte)'\n';
            case 't': return (byte)'\t';
            case 'r': return (byte)'\r';
            case 'x':
                if (i + 2 < raw.Length && byte.TryParse(raw.AsSpan(i + 1, 2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var v))
                {
                    i += 2;
                    return v;
                }
                error = "'\\x' must be followed by two hex digits";
                return 0;
            default:
                error = $"unknown escape sequence '\\{e}'";
                return 0;
        }
    }
}
