#!/usr/bin/env python3
"""Generates src/Blazma.Core/Attack/AttackCatalog.cs from MITRE's enterprise ATT&CK STIX bundle.

Usage:
    python3 tools/attack/generate_attack_catalog.py [--input enterprise-attack.json] [--output path]

Without --input the bundle is downloaded from the mitre/cti repository. The output is
deterministic: the same bundle always produces the same file. Revoked and deprecated
techniques are left out of the catalog; revoked IDs are kept only as a pointer to their
replacement so older rule IDs can still be resolved.

ATT&CK data: (c) The MITRE Corporation. Reproduced and distributed with the permission of
The MITRE Corporation (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import urllib.request

SOURCE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = REPO_ROOT / "src" / "Blazma.Core" / "Attack" / "AttackCatalog.cs"

# Modern Standard Arabic names for the enterprise tactics, keyed by tactic ID. Written by
# hand: MITRE publishes English only. The script fails if a tactic is missing here.
ARABIC_TACTIC_NAMES = {
    "TA0043": "الاستطلاع",
    "TA0042": "تطوير الموارد",
    "TA0001": "الوصول الأولي",
    "TA0002": "التنفيذ",
    "TA0003": "الاستمرارية",
    "TA0004": "تصعيد الصلاحيات",
    "TA0005": "التخفي",
    "TA0112": "إضعاف الدفاعات",
    "TA0006": "الوصول إلى بيانات الاعتماد",
    "TA0007": "الاستكشاف",
    "TA0008": "الحركة الجانبية",
    "TA0009": "جمع البيانات",
    "TA0011": "القيادة والسيطرة",
    "TA0010": "تسريب البيانات",
    "TA0040": "التأثير",
    # Pre-v19 tactic, kept so an older bundle still generates.
    "TA0005-legacy": "التهرب من الدفاعات",
}


def mitre_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def active(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def cs_string(value: str) -> str:
    out = []
    for ch in value:
        if ch in "\\\"":
            out.append("\\" + ch)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def load(path: str | None) -> bytes:
    if path:
        return pathlib.Path(path).read_bytes()
    with urllib.request.urlopen(SOURCE_URL, timeout=120) as response:  # noqa: S310 - fixed https URL
        return response.read()


def generate(raw: bytes) -> str:
    bundle = json.loads(raw)
    objects = bundle["objects"]
    by_ref = {o["id"]: o for o in objects}

    matrices = [o for o in objects if o["type"] == "x-mitre-matrix" and active(o)]
    if len(matrices) != 1:
        sys.exit(f"expected one active matrix, found {len(matrices)}")
    tactics = [by_ref[ref] for ref in matrices[0]["tactic_refs"]]
    order = {t["x_mitre_shortname"]: i for i, t in enumerate(tactics)}

    tactic_rows = []
    for t in tactics:
        tid = mitre_id(t)
        arabic = ARABIC_TACTIC_NAMES.get(tid)
        if t["name"] == "Defense Evasion":
            arabic = ARABIC_TACTIC_NAMES["TA0005-legacy"]
        if not arabic:
            sys.exit(f"no Arabic name for tactic {tid} {t['name']}: add it to ARABIC_TACTIC_NAMES")
        tactic_rows.append(f"        new(\"{tid}\", \"{t['x_mitre_shortname']}\", {cs_string(t['name'])}, {cs_string(arabic)}),")

    techniques = {}
    for o in objects:
        if o["type"] != "attack-pattern" or not active(o):
            continue
        tid = mitre_id(o)
        if not tid or "|" in o["name"]:
            sys.exit(f"unexpected technique {o['id']}")
        if tid in techniques:
            sys.exit(f"duplicate technique {tid}")
        phases = sorted(
            {p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"},
            key=lambda p: order.get(p, len(order)),
        )
        unknown = [p for p in phases if p not in order]
        if unknown:
            sys.exit(f"{tid} uses unknown tactics {unknown}")
        techniques[tid] = (o["name"], phases)

    revoked_by = {}
    for o in objects:
        if o["type"] != "relationship" or o.get("relationship_type") != "revoked-by":
            continue
        src, dst = by_ref.get(o["source_ref"]), by_ref.get(o["target_ref"])
        if src and dst and src["type"] == "attack-pattern" and dst["type"] == "attack-pattern":
            revoked_by[mitre_id(src)] = mitre_id(dst)

    replacements = {}
    for old, new in revoked_by.items():
        # Follow chains of revocations to a technique that is still active.
        seen = {old}
        while new is not None and new not in techniques and new not in seen:
            seen.add(new)
            new = revoked_by.get(new)
        if old and old not in techniques and new in techniques:
            replacements[old] = new

    newest = max(o.get("modified", "") for o in objects)
    digest = hashlib.sha256(raw).hexdigest()

    technique_rows = ["        " + cs_string(f"{tid}|{name}|{' '.join(phases)}") + "," for tid, (name, phases) in sorted(techniques.items())]
    replacement_rows = [f"        [\"{old}\"] = \"{new}\"," for old, new in sorted(replacements.items())]

    return f"""// Generated by tools/attack/generate_attack_catalog.py from {SOURCE_URL}
// Data last modified {newest}; bundle SHA-256 {digest}.
// {len(techniques)} techniques, {len(tactics)} tactics, {len(replacements)} revoked IDs. Regenerate; do not edit by hand.
using System.Diagnostics.CodeAnalysis;

namespace Blazma.Core.Attack;

/// <summary>An ATT&amp;CK tactic: the adversary's goal (the "why" of a technique).</summary>
/// <param name="ShortName">MITRE's phase name, used as <c>kill_chain_phases.phase_name</c> in STIX.</param>
/// <param name="NameAr">Modern Standard Arabic name, written for Blazma (MITRE publishes English only).</param>
public sealed record AttackTactic(string Id, string ShortName, string Name, string NameAr);

/// <summary>An ATT&amp;CK technique or sub-technique with the tactics it serves, in matrix order.</summary>
public sealed record AttackTechnique(string Id, string Name, IReadOnlyList<string> Tactics)
{{
    public bool IsSubTechnique => Id.Contains('.', StringComparison.Ordinal);

    public string Url => "https://attack.mitre.org/techniques/" + Id.Replace('.', '/');
}}

/// <summary>
/// Offline MITRE ATT&amp;CK Enterprise lookup, so exports can name the techniques rules cite
/// without a network call. Revoked and deprecated techniques are excluded; a revoked ID can
/// still be mapped to its replacement with <see cref="TryGetReplacement"/>.
/// <para>
/// {cs_xml(bundle_copyright(objects))}
/// This work is reproduced and distributed with the permission of
/// The MITRE Corporation. See https://attack.mitre.org/resources/legal-and-branding/terms-of-use/.
/// </para>
/// </summary>
public static class AttackCatalog
{{
    /// <summary>Last modification time of the ATT&amp;CK data this catalog was generated from.</summary>
    public const string DataModified = "{newest}";

    /// <summary>The enterprise tactics in matrix order.</summary>
    public static IReadOnlyList<AttackTactic> Tactics {{ get; }} =
    [
{chr(10).join(tactic_rows)}
    ];

    private static readonly Dictionary<string, AttackTactic> TacticsByShortName = Tactics.ToDictionary(t => t.ShortName, StringComparer.Ordinal);

    private static readonly Lazy<Dictionary<string, AttackTechnique>> Techniques = new(Parse);

    public static int Count => Techniques.Value.Count;

    public static IEnumerable<AttackTechnique> All => Techniques.Value.Values.OrderBy(t => t.Id, StringComparer.Ordinal);

    /// <summary>Looks up an active technique ("T1059" or "T1059.001"; case-insensitive).</summary>
    public static bool TryGet(string? id, [NotNullWhen(true)] out AttackTechnique? entry)
    {{
        entry = null;
        return !string.IsNullOrWhiteSpace(id) && Techniques.Value.TryGetValue(id.Trim(), out entry);
    }}

    /// <summary>For a technique MITRE has revoked: the active technique that replaced it.</summary>
    public static bool TryGetReplacement(string? revokedId, [NotNullWhen(true)] out AttackTechnique? replacement)
    {{
        replacement = null;
        return !string.IsNullOrWhiteSpace(revokedId) && Revoked.TryGetValue(revokedId.Trim(), out var id) && TryGet(id, out replacement);
    }}

    /// <summary>The tactic with this phase name ("persistence") or ID ("TA0003").</summary>
    public static AttackTactic? Tactic(string? shortNameOrId) =>
        shortNameOrId is null ? null
        : TacticsByShortName.TryGetValue(shortNameOrId, out var t) ? t
        : Tactics.FirstOrDefault(x => x.Id.Equals(shortNameOrId, StringComparison.OrdinalIgnoreCase));

    private static Dictionary<string, AttackTechnique> Parse()
    {{
        var map = new Dictionary<string, AttackTechnique>(Rows.Length, StringComparer.OrdinalIgnoreCase);
        foreach (var row in Rows)
        {{
            var parts = row.Split('|');
            map[parts[0]] = new AttackTechnique(parts[0], parts[1], parts[2].Split(' ', StringSplitOptions.RemoveEmptyEntries));
        }}
        return map;
    }}

    private static readonly Dictionary<string, string> Revoked = new(StringComparer.OrdinalIgnoreCase)
    {{
{chr(10).join(replacement_rows)}
    }};

    // ID|English name|tactic phase names in matrix order
    private static readonly string[] Rows =
    [
{chr(10).join(technique_rows)}
    ];
}}
"""


def bundle_copyright(objects: list) -> str:
    for o in objects:
        if o["type"] == "marking-definition":
            statement = o.get("definition", {}).get("statement")
            if statement:
                return statement
    return "Copyright The MITRE Corporation."


def cs_xml(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", help="local enterprise-attack.json (downloaded when omitted)")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()
    text = generate(load(args.input))
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(text.encode("utf-8"))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
