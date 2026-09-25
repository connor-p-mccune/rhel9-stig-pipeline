#!/usr/bin/env python3
"""
scripts/parse_results.py

WHAT THIS DOES (plain language)
Reads the results.xml file OpenSCAP writes and turns it into a short summary:
the overall score, a table of how many rules passed or failed at each severity
(CAT I, II, III), and the list of CAT I (most serious) failures. It prints the
summary and also saves it as summary.json next to the results file, so later
scripts (compare.py) can put different scans side by side.

USAGE:        python3 scripts/parse_results.py reports/baseline/results.xml
WHERE IT RUNS: on the server (scan.sh runs it for you). It also works on any
               machine with Python 3 and lxml.
"""
import json
import sys
from pathlib import Path

from lxml import etree

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"
NS = {"x": XCCDF_NS}
RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"

# DISA calls severity levels "categories". CAT I is the most serious.
SEVERITY_TO_CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}
CATEGORIES = ["CAT I", "CAT II", "CAT III"]
OUTCOMES = ["pass", "fail", "notapplicable", "notchecked", "error"]
NOTCHECKED_NOTE = "notchecked means no automated test exists — these are NOT passes."

# Yellow text in a real terminal, plain text when output goes to a file.
USE_COLOR = sys.stdout.isatty()


def yellow(text):
    return f"\033[1;33m{text}\033[0m" if USE_COLOR else text


def short_id(rule_id):
    """xccdf_org.ssgproject.content_rule_sshd_disable_root_login -> sshd_disable_root_login"""
    return rule_id[len(RULE_PREFIX):] if rule_id.startswith(RULE_PREFIX) else rule_id


def pick_score(test_result):
    """Return (score, maximum). Prefers the default XCCDF scoring model."""
    scores = test_result.findall("x:score", NS)
    if not scores:
        return None, None
    chosen = next(
        (s for s in scores if s.get("system") == "urn:xccdf:scoring:default"),
        scores[0],
    )
    return float(chosen.text.strip()), float(chosen.get("maximum", "100"))


def content_version(root):
    """The SCAP Security Guide version the scan used (the Benchmark's <version>)."""
    benchmark = root if root.tag == f"{{{XCCDF_NS}}}Benchmark" else root.find(".//x:Benchmark", NS)
    if benchmark is None:
        return None
    return benchmark.findtext("x:version", namespaces=NS)


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/parse_results.py <path/to/results.xml>", file=sys.stderr)
        sys.exit(1)

    results_path = Path(sys.argv[1])
    if not results_path.is_file():
        print(f"ERROR: file not found: {results_path}", file=sys.stderr)
        sys.exit(1)

    # Results files are large; lxml refuses very large ones unless told it's OK.
    parser = etree.XMLParser(huge_tree=True)
    root = etree.parse(str(results_path), parser).getroot()

    test_results = root.findall(".//x:TestResult", NS)
    if not test_results:
        print("ERROR: no <TestResult> found. Is this a results file from `oscap xccdf eval --results`?",
              file=sys.stderr)
        sys.exit(1)
    if len(test_results) > 1:
        print(f"NOTE: {len(test_results)} test results in this file; summarizing the first one.")
    tr = test_results[0]

    categories = list(CATEGORIES)
    counts = {cat: {o: 0 for o in OUTCOMES + ["other"]} for cat in categories}
    failures = {cat: [] for cat in categories}
    notselected = 0

    for rr in tr.findall("x:rule-result", NS):
        result_el = rr.find("x:result", NS)
        outcome = result_el.text.strip() if result_el is not None and result_el.text else "unknown"

        # "notselected" = the rule exists in the content but isn't part of this
        # profile. It was never evaluated, so it doesn't belong in any count.
        if outcome == "notselected":
            notselected += 1
            continue

        cat = SEVERITY_TO_CAT.get(rr.get("severity", ""), "Unrated")
        if cat not in counts:
            categories.append(cat)
            counts[cat] = {o: 0 for o in OUTCOMES + ["other"]}
            failures[cat] = []

        counts[cat][outcome if outcome in OUTCOMES else "other"] += 1
        if outcome == "fail":
            failures[cat].append(short_id(rr.get("idref", "")))

    totals = {o: sum(counts[c][o] for c in categories) for o in OUTCOMES + ["other"]}
    score, score_max = pick_score(tr)
    profile_el = tr.find("x:profile", NS)
    label = results_path.resolve().parent.name

    # ---- print the summary --------------------------------------------------
    columns = OUTCOMES + ["other", "total"]
    header_names = {"notchecked": "notchecked(!)"}
    # Narrow columns for short words, wider ones for long words, so the table
    # fits in an 80-character terminal window.
    widths = {"notapplicable": 15, "notchecked": 15}

    def w(col):
        return widths.get(col, 8)

    line_width = 10 + sum(w(c) for c in columns)
    print("=" * line_width)
    print(f" STIG scan summary: {label}")
    print("=" * line_width)
    print(f"Content version: scap-security-guide {content_version(root) or 'unknown'}")
    print(f"Profile:         {profile_el.get('idref') if profile_el is not None else 'unknown'}")
    if score is not None:
        print(f"Score:           {score:.2f} out of {score_max:.2f}")
    else:
        print("Score:           not found in results file")
    print()

    header = "".ljust(10) + "".join(header_names.get(c, c).rjust(w(c)) for c in columns)
    print(header)
    print("-" * len(header))
    for row_name, row in [(c, counts[c]) for c in categories] + [("Total", totals)]:
        cells = []
        for col in columns:
            value = sum(row.values()) if col == "total" else row[col]
            cell = str(value).rjust(w(col))
            cells.append(yellow(cell) if col == "notchecked" else cell)
        print(row_name.ljust(10) + "".join(cells))
    print()
    print(yellow(f"(!) {NOTCHECKED_NOTE}"))
    print(f"    ({notselected} rule(s) outside this profile were skipped and are not counted.)")
    print()

    cat1 = failures["CAT I"]
    print(f"CAT I failures ({len(cat1)}):")
    for rule in cat1:
        print(f"  - {rule}")
    if not cat1:
        print("  (none)")

    # ---- save the same summary as JSON --------------------------------------
    summary = {
        "label": label,
        "results_file": str(results_path),
        "content_version": content_version(root),
        "profile": profile_el.get("idref") if profile_el is not None else None,
        "start_time": tr.get("start-time"),
        "end_time": tr.get("end-time"),
        "score": score,
        "score_max": score_max,
        "counts": counts,
        "totals": totals,
        "cat1_failures": cat1,
        "failures_by_category": failures,
        "notselected_skipped": notselected,
        "note": NOTCHECKED_NOTE,
    }
    out_path = results_path.parent / "summary.json"
    out_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print()
    print(f"Summary saved to {out_path}")


if __name__ == "__main__":
    main()
