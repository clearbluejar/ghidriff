"""
Align per-build names in two decompiled functions, for the emitted C diff (--align-names).

Ghidra names some things per build: locals (uVar1.., local_28, extraout_x8), code labels
(LAB_.., switchD_..), and references to unnamed functions and data by address (FUN_..,
func_0x.., DAT_..). A change in one build renumbers or re-addresses the rest, so a diff of
two builds fills with renames. Each new-side name is mapped to its old-side counterpart in
three tiers of certainty:

- locals and code labels: alpha-renaming, found by aligning the two sides with those names
  masked and voting on which pairs share aligned lines. A bijection that never merges two
  names, so it is lossless: a real change in which variable or label is used still shows.
- functions: through ghidriff's match table (old name <-> new name). Exact.
- unresolved addresses (func_0x.., DAT_.., PTR_.., s_..): optional (--align-unresolved).
  Inferred like locals, but a one-use changed target is indistinguishable from a
  relocation, so it is off by default.

Only the emitted diff text is affected: ghidriff's ratios and its `code` gate are computed
before renaming. Every rename is recorded and reverses exactly (undo).
"""

import difflib
import re
from collections import Counter
from typing import Dict, Iterable, List, Optional, Tuple

# Ghidra's default local names. The variable base is printNameBase: 'p' per
# pointer level, 'a' per array, then the first character of the type name
# (any case, '_' included), or nothing: uVar1 pcVar2 pFVar4 p_Var4 AVar3 _Var8 Var32.
LOCAL = re.compile(
    r"\b(?:[pa]*[A-Za-z_]?Var\d+"
    r"|(?:local|[a-z]{1,4}[A-Z]?[a-zA-Z]{0,4}Stack)_[0-9a-f]+(?:_[0-9a-f]+)?"
    r"|(?:extraout|in|unaff)_[A-Za-z0-9]+"
    r"|this_\d+"
    r"|LAB_[0-9a-f]+|switchD_[0-9a-f]+|caseD_[0-9a-f]+"
    r"|joined_r0x[0-9a-f]+|code_r0x[0-9a-f]+)\b")

# References by address to things the program has no name for.
UNRESOLVED = re.compile(
    r"\b(?:func_0x[0-9a-f]+|_?DAT_[0-9a-f]+|PTR_\w+?_[0-9a-f]{6,}|PTR_[0-9a-f]{6,}"
    r"|s_\w*?_[0-9a-f]{6,})\b")

# Identifiers as the decompiler prints symbol names, including C++ scopes.
IDENT = re.compile(r"(?<![\w$])[A-Za-z_][\w$]*(?:::~?[A-Za-z_][\w$]*)*")


def _fresh(name: str, avoid: set) -> str:
    """A name of the same shape (so the same pattern still matches it) not in `avoid`."""
    m = re.match(r"^(.*?)(\d+)$", name)
    stem, n = (m.group(1), int(m.group(2))) if m else (name, 1)
    while True:
        n += 1
        cand = f"{stem}{n}"
        if cand not in avoid:
            return cand


def _bijection(votes: Counter, new_tokens: Iterable[str], old_tokens: Iterable[str]) -> Dict[str, str]:
    """new -> old, greedy by votes. An unpaired new name keeps its own name
    unless a pair already took it; then it gets a fresh name that appears on
    neither side, so it cannot pass for an unrelated old name."""
    new_tokens, old_tokens = set(new_tokens), set(old_tokens)
    mp: Dict[str, str] = {}
    used = set()
    for (y, x), _ in sorted(votes.items(), key=lambda kv: (-kv[1], kv[0])):
        if y not in mp and x not in used:
            mp[y] = x
            used.add(x)
    avoid = new_tokens | old_tokens | used
    for y in sorted(new_tokens - set(mp)):
        name = y if y not in used else _fresh(y, avoid)
        mp[y] = name
        used.add(name)
        avoid.add(name)
    return mp


def _align(old: List[str], new: List[str], tok: re.Pattern, also_mask: Optional[re.Pattern] = None) -> Dict[str, str]:
    """Vote for (new, old) token pairs on lines that align once tokens are masked."""
    def mask(line: str) -> str:
        line = tok.sub("\x00", line)
        return also_mask.sub("\x01", line) if also_mask else line
    mo, mn = [mask(line) for line in old], [mask(line) for line in new]
    votes: Counter = Counter()
    for tag, a1, a2, b1, b2 in difflib.SequenceMatcher(None, mo, mn, autojunk=False).get_opcodes():
        # Equal lines are strong evidence; a same-length replaced block is weak
        # (lines changed for other reasons, but often still line up).
        w = 1.0 if tag == "equal" else 0.25 if tag == "replace" and a2 - a1 == b2 - b1 else 0.0
        if not w:
            continue
        for i, j in zip(range(a1, a2), range(b1, b2)):
            to, tn = tok.findall(old[i]), tok.findall(new[j])
            if len(to) == len(tn):
                for x, y in zip(to, tn):
                    votes[y, x] += w
    return _bijection(votes, {t for line in new for t in tok.findall(line)}, {t for line in old for t in tok.findall(line)})


def _apply(lines: List[str], tok: re.Pattern, mp: Dict[str, str]) -> List[str]:
    return [tok.sub(lambda m: mp.get(m.group(0), m.group(0)), line) for line in lines]


def function_map(new_to_old: Dict[str, str], old: List[str], new: List[str]) -> Dict[str, str]:
    """The match-table renames that apply to these two bodies, made collision-free."""
    new_ids = {t for line in new for t in IDENT.findall(line)}
    # Only names the C text can hold: ObjC "+[Cls sel].cold.1" is a match-table
    # name, never an identifier in the decompiled body.
    mp = {n: o for n, o in new_to_old.items()
          if n != o and n in new_ids and IDENT.fullmatch(o)}
    targets = set(mp.values())
    # A new-side name equal to some target, but not itself renamed, would merge
    # with it: keep it distinct.
    old_ids = {t for line in old for t in IDENT.findall(line)}
    for n in sorted(new_ids - set(mp)):
        if n in targets:
            name = _fresh(n, targets | new_ids | old_ids)
            mp[n] = name
            targets.add(name)
    return mp


def rename_new_side(old: List[str], new: List[str],
                    functions: Optional[Dict[str, str]] = None,
                    infer_unresolved: bool = False) -> Tuple[List[str], Dict[str, Dict[str, str]]]:
    """New-side lines renamed to the old side's names, and the renames by tier.

    `functions` is new name -> old name from the differ's match table.
    """
    maps: Dict[str, Dict[str, str]] = {}
    if functions:
        fm = function_map(functions, old, new)
        if fm:
            new = [IDENT.sub(lambda m: fm.get(m.group(0), m.group(0)), line) for line in new]
            maps["functions"] = fm
    lm = _align(old, new, LOCAL, also_mask=UNRESOLVED)
    new = _apply(new, LOCAL, lm)
    maps["locals"] = {k: v for k, v in lm.items() if k != v}
    if infer_unresolved:
        um = _align(old, new, UNRESOLVED)
        new = _apply(new, UNRESOLVED, um)
        maps["unresolved"] = {k: v for k, v in um.items() if k != v}
    return new, maps


def undo(renamed: List[str], maps: Dict[str, Dict[str, str]]) -> List[str]:
    """Inverse of rename_new_side, tier by tier in reverse order."""
    lines = renamed
    for tier, tok in (("unresolved", UNRESOLVED), ("locals", LOCAL)):
        inv = {v: k for k, v in maps.get(tier, {}).items()}
        if inv:
            lines = _apply(lines, tok, inv)
    inv = {v: k for k, v in maps.get("functions", {}).items()}
    if inv:
        lines = [IDENT.sub(lambda m: inv.get(m.group(0), m.group(0)), line) for line in lines]
    return lines


def match_table_names(diff_json: Dict) -> Dict[str, str]:
    """new name -> old name from a ghidriff JSON's matches.name_matches (1:1 only)."""
    out: Dict[str, str] = {}
    for old, news in ((diff_json.get("matches") or {}).get("name_matches") or {}).items():
        if len(news) == 1:
            out.setdefault(news[0][0], old)
    return out


def _clean(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def _alignable(lines: List[str]) -> List[str]:
    """Lines used to compute the maps: whitespace-normalized, no blank or comment lines."""
    out = []
    for line in lines:
        c = _clean(line)
        if c and not c.startswith(("/*", "//")):
            out.append(c)
    return out


def apply_maps(lines: List[str], maps: Dict[str, Dict[str, str]]) -> List[str]:
    """Apply rename maps (as returned by rename_new_side) to lines, tier by tier in order."""
    fm = maps.get("functions", {})
    if fm:
        lines = [IDENT.sub(lambda m: fm.get(m.group(0), m.group(0)), line) for line in lines]
    for tier, tok in (("locals", LOCAL), ("unresolved", UNRESOLVED)):
        if maps.get(tier):
            lines = _apply(lines, tok, maps[tier])
    return lines


def align_lines(old: List[str], new: List[str], functions: Optional[Dict[str, str]] = None,
                infer_unresolved: bool = False) -> Tuple[List[str], Dict[str, Dict[str, str]]]:
    """
    New-side lines renamed to the old side's names, keeping the original lines (indentation,
    blank lines, comments), and the non-identity renames by tier. undo(result, maps) == new.
    """
    _, maps = rename_new_side(_alignable(old), _alignable(new), functions=functions,
                              infer_unresolved=infer_unresolved)
    # identity entries carry no information; keep only real renames
    maps = {tier: {k: v for k, v in m.items() if k != v} for tier, m in maps.items()}
    maps = {tier: m for tier, m in maps.items() if m}
    return apply_maps(new, maps), maps


def name_matches_to_functions(name_matches: Dict) -> Dict[str, str]:
    """new name -> old name from ghidriff's pdiff['matches']['name_matches'] (1:1 only)."""
    return match_table_names({"matches": {"name_matches": name_matches}})
