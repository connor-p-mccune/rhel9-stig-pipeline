#!/usr/bin/env python3
"""
scripts/compare.py

WHAT THIS DOES (plain language)
Puts the scans side by side: the baseline (before any fixes) and the hardened
scan (after remediate.sh and a reboot). It prints a before/after table and
saves the same table as Markdown in reports/comparison.md, ready to paste into
the README.

It reads the summary.json files that scripts/scan.sh writes, so it needs no
extra packages and works on the server or on your laptop.

USAGE:  python3 scripts/compare.py      (from anywhere inside the repo)
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REPORTS = REPO / "reports"
OUT_FILE = REPORTS / "comparison.md"

# The two scans being compared: (folder under reports/, column title).
BEFORE = ("baseline", "Baseline")
AFTER = ("hardened", "Hardened")

# The rows of the table: (row title, how to pull the number out of summary.json).
ROWS = [
    ("Score (out of 100)", lambda s: s["score"]),
    ("CAT I fails", lambda s: s["counts"]["CAT I"]["fail"]),
    ("CAT II fails", lambda s: s["counts"]["CAT II"]["fail"]),
    ("CAT III fails", lambda s: s["counts"]["CAT III"]["fail"]),
    ("All fails", lambda s: s["totals"]["fail"]),
]


def load(label):
    path = REPORTS / label / "summary.json"
    if not path.is_file():
        print(f"ERROR: {path.relative_to(REPO)} not found.", file=sys.stderr)
        print(f"Run ./scripts/scan.sh {label} on the server first.", file=sys.stderr)
        sys.exit(1)
    return json.loads(path.read_text(encoding="utf-8"))


def show(value):
    """Scores get two decimals; counts are whole numbers."""
    return f"{value:.2f}" if isinstance(value, float) else str(value)


def change(before, after):
    """The difference with a + or - sign. For fails, negative is good."""
    diff = after - before
    return f"{diff:+.2f}" if isinstance(diff, float) else f"{diff:+d}"


def main():
    before, after = load(BEFORE[0]), load(AFTER[0])

    header = ["", BEFORE[1], AFTER[1], "Change"]
    table = [
        [title, show(get(before)), show(get(after)), change(get(before), get(after))]
        for title, get in ROWS
    ]

    # ---- print it in the terminal -------------------------------------------
    widths = [max(len(row[i]) for row in [header] + table) for i in range(len(header))]
    line = "  ".join(header[i].ljust(widths[i]) if i == 0 else header[i].rjust(widths[i])
                     for i in range(len(header)))
    print(line)
    print("-" * len(line))
    for row in table:
        print("  ".join(row[i].ljust(widths[i]) if i == 0 else row[i].rjust(widths[i])
                        for i in range(len(row))))

    # Scores are only comparable if both scans used the same STIG content.
    versions = {before.get("content_version"), after.get("content_version")}
    if len(versions) > 1:
        print("\nWARNING: the two scans used different scap-security-guide versions "
              f"({', '.join(sorted(str(v) for v in versions))}). The rules changed "
              "between them, so the numbers aren't a fair comparison.")

    # ---- save it as Markdown -------------------------------------------------
    md = [
        "| " + " | ".join(header) + " |",
        "|---|" + "---:|" * (len(header) - 1),
    ]
    md += ["| " + " | ".join(row) + " |" for row in table]
    md += [
        "",
        f"Scan content: scap-security-guide {after.get('content_version') or 'unknown'}, "
        f"DISA STIG profile. Baseline scanned {(before.get('start_time') or '')[:10]}, "
        f"hardened scanned {(after.get('start_time') or '')[:10]}. "
        "Fewer fails is better; \"notchecked\" rules are not counted as passes.",
    ]
    OUT_FILE.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"\nMarkdown table saved to {OUT_FILE.relative_to(REPO)}")


if __name__ == "__main__":
    main()
