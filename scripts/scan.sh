#!/usr/bin/env bash
# =============================================================================
# scripts/scan.sh
#
# WHAT THIS DOES (plain language)
# Measures this server against the DISA STIG and saves the results in
# reports/<label>/. Then it runs parse_results.py to print a summary table.
# It only LOOKS at the server. It never changes a setting.
#
# USAGE (as ec2-user, from the repo folder):
#   ./scripts/scan.sh baseline                          # full STIG
#   ./scripts/scan.sh tailored ansible/tailoring.xml    # STIG minus your documented exclusions
#
# OUTPUT
#   reports/<label>/results.xml    machine-readable result for every rule
#   reports/<label>/report.html    human-readable report; open it in a browser
#   reports/<label>/summary.json   score and counts, written by parse_results.py
#
# ABOUT EXIT CODES
# oscap finishes with one of these codes:
#   0  scan ran, every rule passed      (you will basically never see this)
#   2  scan ran, some rules failed      <- NORMAL. Finding failures is the point.
#   1  the scan itself broke            <- a real error
# "set -e" below would treat 2 as a crash and stop the script, so we catch the
# code ourselves with "|| rc=$?" and only stop on 1 (or anything unexpected).
#
# EXPECTED WARNING
# oscap may warn that a component "points out to the remote resource" and
# suggest --fetch-remote-resources. That's the rule checking for missing
# security patches, which needs to download Red Hat's live patch feed. We
# leave it off so results don't depend on the day you scanned. That one rule
# comes back as "notchecked".
# =============================================================================
set -euo pipefail

DATASTREAM=/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
PROFILE=xccdf_org.ssgproject.content_profile_stig
TAILORED_PROFILE=xccdf_org.ssgproject.content_profile_stig_customized

usage() {
  echo "Usage: ./scripts/scan.sh <label> [tailoring-file]"
  echo "  label:          a folder name under reports/, like baseline, hardened, tailored"
  echo "  tailoring-file: optional; e.g. ansible/tailoring.xml"
}

LABEL="${1:-}"
TAILORING="${2:-}"

if [ -z "$LABEL" ]; then
  usage
  exit 1
fi

# Keep labels to simple folder names so nothing odd ends up in reports/.
if [[ ! "$LABEL" =~ ^[a-z0-9_-]+$ ]]; then
  echo "ERROR: label must be lowercase letters, numbers, - or _ (got: $LABEL)" >&2
  exit 1
fi

# Turn the tailoring path into a full path BEFORE changing folders below.
if [ -n "$TAILORING" ]; then
  if [ ! -f "$TAILORING" ]; then
    echo "ERROR: tailoring file not found: $TAILORING" >&2
    exit 1
  fi
  TAILORING="$(realpath "$TAILORING")"
fi

# Work from the repo's top folder no matter where this was started from,
# so results always land in the same reports/ folder.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ ! -f "$DATASTREAM" ]; then
  echo "ERROR: STIG content not found at $DATASTREAM" >&2
  echo "Run ./scripts/bootstrap.sh first." >&2
  exit 1
fi

OUT_DIR="reports/$LABEL"
mkdir -p "$OUT_DIR"

if [ -n "$TAILORING" ]; then
  OSCAP_ARGS=(xccdf eval --tailoring-file "$TAILORING" --profile "$TAILORED_PROFILE")
  PROFILE_USED="$TAILORED_PROFILE (tailoring: $TAILORING)"
else
  OSCAP_ARGS=(xccdf eval --profile "$PROFILE")
  PROFILE_USED="$PROFILE"
fi
OSCAP_ARGS+=(--results "$OUT_DIR/results.xml" --report "$OUT_DIR/report.html" "$DATASTREAM")

echo "==> Scanning this server"
echo "    label:   $LABEL"
echo "    profile: $PROFILE_USED"
echo "    This takes a few minutes. Each rule prints as it's checked."
echo

rc=0
sudo oscap "${OSCAP_ARGS[@]}" || rc=$?

echo
case "$rc" in
  0) echo "==> Scan finished: every rule passed (exit code 0)." ;;
  2) echo "==> Scan finished: some rules failed (exit code 2). This is normal." ;;
  1) echo "ERROR: oscap exited with code 1. The scan itself failed; read the messages above." >&2
     exit 1 ;;
  *) echo "ERROR: oscap exited with unexpected code $rc." >&2
     exit "$rc" ;;
esac

# oscap ran as root, so root owns the files it wrote. Hand them back to
# ec2-user so git can commit them, even after the STIG tightens default
# file permissions in Prompt 6.
sudo chown "$(id -u):$(id -g)" "$OUT_DIR/results.xml" "$OUT_DIR/report.html"

echo
python3 scripts/parse_results.py "$OUT_DIR/results.xml"
