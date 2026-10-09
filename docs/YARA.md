# YARA rules

Blazma Sandbox scans samples, dropped files and memory with YARA rules using its own
managed engine (`src/Blazma.Analysis/Yara/`). There is no native libyara: rule files come
from users and the internet, and the scanned bytes are hostile, so the engine is written in
safe C#, bounds every search, and rejects what it cannot do exactly.

The rule language follows the [YARA documentation](https://yara.readthedocs.io/en/stable/writingrules.html).
This page lists exactly what is supported. **Anything not listed here is reported as an
error; the engine never silently evaluates a rule it does not fully understand.**

## How rules are loaded

`YaraRuleSet.LoadFolder(folder)` reads every `*.yar` and `*.yara` file under the folder,
recursively (symbolic links and junctions are not followed, at most 16 levels deep).

| Limit | Value |
|---|---|
| Files read | the first 256, in ordinal path order |
| File size | 2 MB per file (larger files are skipped and reported) |

Errors never stop loading; they are listed in `LoadErrors`:

- **Syntax error**: the whole file is rejected, as `file:line: message`.
- **Unsupported feature or semantic error in one rule** (a module, an undefined string, a bad
  modifier combination): only that rule is skipped, as `file:line: rule name: message`. The
  rest of the file loads. A rule that references a skipped rule is skipped too.

**Each file is its own namespace.** Rule references and `global` rules apply within the file
they are written in, so one downloaded file's global rule cannot silence your other rules,
and two files may both define a rule called `generic`. (libyara puts files given on one
command line into a single namespace; this is the one deliberate difference.)

## Rules

| Feature | Support |
|---|---|
| `rule name { ... }`, `meta:`, `strings:`, `condition:` | ✅ |
| `private rule` | ✅ evaluated and referenceable, never reported |
| `global rule` | ✅ if any global rule in the file is false, no rule in that file matches |
| Tags (`rule name : tag1 tag2`) | ✅ |
| Metadata: text (with escapes), integers (also negative, hex), `true`/`false` | ✅ first value wins on duplicate keys |
| `//` and `/* */` comments, also inside hex strings | ✅ |
| `import "module"` | ✅ accepted, but a rule that **uses** a module is skipped with an error |
| `include "file"` | ❌ error (put every file in the folder instead) |
| Duplicate rule names in one file | ❌ error |
| Strings never used in the condition | ❌ error, as in YARA (names starting with `$_` are exempt) |

The family shown in reports comes from the metadata keys `family`, `malware_family` or
`malware`, in that order.

## Text strings

`$a = "text"`. Escapes: `\"` `\\` `\n` `\t` `\r` `\xHH`; other escapes are an error. Other
characters are matched as their UTF-8 bytes.

| Modifier | Support |
|---|---|
| `ascii`, `wide` (UTF-16LE: each byte followed by `00`), both together | ✅ |
| `nocase` | ✅ ASCII letters only, as in YARA |
| `fullword` | ✅ the bytes before and after (wide characters for `wide`) are not `[A-Za-z0-9]` |
| `private` | ✅ used by the condition, never reported |
| `xor`, `xor(n)`, `xor(a-b)` | ✅ single-byte keys; plain `xor` is keys 0-255; with `wide`, the zero bytes are xored too |
| `base64`, `base64wide`, with optional custom 64-byte alphabet | ✅ the three offset forms YARA documents; the string must be at least 3 bytes |

Rejected combinations (error): `xor` with `nocase` (YARA rejects it); `xor` with `fullword`
(not supported); `base64`/`base64wide` with `xor`, `nocase` or `fullword` (YARA rejects them);
`base64`/`base64wide` with `ascii` or `wide` (not supported); an empty string.

## Hex strings

| Syntax | Support |
|---|---|
| `4D 5A`, wildcards `??`, nibble wildcards `4?` `?A` | ✅ |
| Negation `~4D`, `~4?` | ✅ |
| Jumps `[n]`, `[n-m]` | ✅ up to 65 535 bytes |
| Unbounded jumps `[n-]`, `[-]` | ✅ **capped at 65 535 bytes** past the previous token |
| Alternatives `( 41 \| 42 43 \| 4? [2] 44 )`, nested | ✅ up to 64 levels |

Jumps are lazy (the shortest match is reported) and alternatives are tried in order, as in
YARA. A hex string cannot start or end with a jump. Only `private` may follow a hex string.

## Regular expressions

`$a = /pattern/is` — `i` is nocase, `s` makes `.` match a newline. Modifiers: `nocase`,
`ascii`, `wide`, `fullword`, `private`.

Supported syntax: literals, `.`, `[...]` and `[^...]` classes with ranges, `\w \W \s \S \d \D`
(ASCII definitions, also inside classes), `\b \B`, `^` and `$` (start and end of the data),
groups `( )`, alternation `|`, quantifiers `* + ? {n} {n,} {,m} {n,m}` and their lazy forms
(`*?` …), escapes `\n \t \r \f \a \xHH` and escaped punctuation.

Errors: backreferences (`\1`), anything starting with `(?` (lookarounds, non-capturing or
named groups, inline options), POSIX classes, unknown escapes, non-ASCII characters (write
`\xHH`), repetition bounds above 32 767, nesting deeper than 64.

Regexes run on the .NET non-backtracking engine, which takes linear time, so no pattern can
hang a scan. Like YARA, **a regex match is at most 4096 bytes long**: each match is what the
regex finds in the 4 KB after its start. (Regexes that use `^` or `$` are matched over the
whole data instead, because those anchors refer to its ends.) Matches may overlap: a match is
reported at every offset where one starts.

## Conditions

| Feature | Support |
|---|---|
| `true`, `false`, `and`, `or`, `not`, parentheses | ✅ |
| Integers: decimal, `0x` hex, `0o` octal, `KB` and `MB` suffixes | ✅ floats are an error |
| `+ - * \ %`, `& \| ^ ~ << >>`, unary `-` | ✅ 64-bit, wrapping; `\` and `%` by zero are undefined |
| `== != < <= > >=` | ✅ |
| `filesize` | ✅ the length of the scanned data |
| `$a`, `$a at x`, `$a in (a..b)` | ✅ |
| `#a`, `#a in (a..b)` | ✅ |
| `@a`, `@a[i]`, `!a`, `!a[i]` | ✅ 1-based; undefined outside 1..`#a` |
| `uint8/16/32`, `int8/16/32`, and their `be` forms | ✅ undefined past the end of the data |
| `any/all/none of them`, `N of (...)`, `N% of (...)` | ✅ with `$a*` and `$*` wildcards |
| `... of (...) at x`, `... of (...) in (a..b)` | ✅ |
| `N of (rule1, rule_prefix*)` | ✅ earlier rules of the same file |
| `for any/all/none/N/N% of (...) : ( ... $ # @ ! ... )` | ✅ |
| `for any/all/none/N i in (a..b) : (...)`, `... in (x, y, z)` | ✅ nested loops too |
| `defined expr` | ✅ |
| References to earlier rules | ✅ a rule cannot reference a later one, as in YARA |
| Anonymous strings `$ = "..."` | ✅ through `them`, `$*` and `for ... of` |
| `entrypoint` | ❌ error (deprecated in YARA; needs the `pe` module) |
| Modules: `pe.`, `elf.`, `math.`, `hash.`, `dotnet.`, `cuckoo.`, `magic.`, `time.`, `console.`, … | ❌ the rule is skipped with an error naming the module |
| External variables | ❌ error (`undefined identifier`) |
| String operators `contains`, `icontains`, `startswith`, `endswith`, `iequals`, `matches`, … | ❌ error (they need module or external string values) |
| `for ... in` with several variables (dictionary iteration) | ❌ error |

**Undefined values** (reading past the end, `@a[5]` with two matches, division by zero)
propagate through arithmetic and comparisons; `not undefined` is undefined; `and`/`or` and the
final result treat undefined as false. This is YARA 4's behaviour.

**Quantifiers:** `N of` and `for N` mean *at least* N. `none` and `0 of` mean *exactly zero*.
`N%` rounds up (`50% of` three strings needs two). A loop over an empty range (`(5..1)`, or
`(1..#a)` when `#a` is 0) has no iterations: `any` is false, `all` is true, `none` is true. A
loop whose bounds are undefined is undefined.

## Safety limits

| Limit | Value | What happens |
|---|---|---|
| Matches recorded per string | 1 000 | the search stops; `#a` saturates at 1 000, and `@a[i]`, `$a at`/`in` only see the first 1 000 matches |
| Regex match length | 4 096 bytes | as in YARA |
| Hex jump | 65 535 bytes | unbounded jumps stop there; larger explicit jumps are an error |
| Nesting (parentheses, `not`, unary operators, loops, hex alternatives, regex groups) | 64 levels | compile error; only that rule is skipped |
| Condition tree height | 256 | compile error (e.g. 300 additions in a row); `and`/`or` chains are flat and unlimited |
| Values per `for` loop | 1 000 000 | the loop is undefined, with a scan warning |
| Evaluation steps per rule | 20 000 000 | the rule counts as not matching, with a scan warning |
| Search time per string | 5 s | the search stops, with a scan warning |
| Search time per scan | 60 s | later strings count as not found, with a scan warning |
| Reported per match | 10 strings × 3 matches | the match itself is unaffected |
| Match preview | 32 bytes | text if mostly printable (wide text without its zero bytes), otherwise hex |

`YaraRuleSet.ScanDetailed` returns the matches together with these warnings; `Scan` (the
`IYaraScanner` method) returns only the matches.

## How matching works

- Strings are searched lazily, the first time a condition needs them, and each at most once
  per scan. Put cheap checks first (`uint16(0) == 0x5A4D and ...`) and most data is never
  searched.
- Text and hex strings without jumps become masked byte patterns. The engine picks the most
  selective part (a run of exact bytes, or the byte with the fewest allowed values) and finds
  candidates with vectorised `IndexOf`/`IndexOfAny`, then verifies each candidate.
- `xor` with a wide key range scans once using the fact that XOR of two neighbouring bytes does
  not depend on the key.
- Hex strings with jumps or alternatives run on a small matcher that remembers every
  (position, pattern step) it has tried, so jumps cannot cause exponential backtracking.
- Regexes skip the data entirely when a literal every match must contain is absent. They run
  over a view of the bytes as text in which bytes `0x80`-`0xFF` become symbols, so `\b` and
  `\w` keep YARA's ASCII meaning. `wide` regexes run over a view with one character per UTF-16
  unit (at both byte alignments), so `\b`, `^` and `$` keep their meaning in wide text.
- A compiled rule set is immutable and can scan from several threads at once.
