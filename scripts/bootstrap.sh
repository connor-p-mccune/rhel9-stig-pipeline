#!/usr/bin/env bash
# =============================================================================
# scripts/bootstrap.sh
#
# WHAT THIS DOES (plain language)
# Installs every tool this server needs for the project, then prints the exact
# versions it installed. Run it once on a fresh server.
#
#   openscap-scanner     the scanner itself (the `oscap` command)
#   scap-security-guide  the STIG rules, in a format the scanner can read
#   openscap-utils       extra tools, including `autotailor` (used in Prompt 7)
#   ansible-core         the tool that applies fixes (used in Prompt 6)
#   git                  so the server can pull code from GitHub and push results
#   python3-lxml         the XML library that scripts/parse_results.py uses
#
# WHERE IT RUNS: on the RHEL 9 server, over SSH, as ec2-user (NOT with sudo).
# =============================================================================
set -euo pipefail

DATASTREAM=/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
STIG_PROFILE=xccdf_org.ssgproject.content_profile_stig

# Ansible collections get installed into the home folder of whoever runs this.
# If this ran as root, they'd land in /root, and later playbooks run as
# ec2-user would fail with "couldn't resolve module".
if [ "$(id -u)" -eq 0 ]; then
  echo "ERROR: run this as ec2-user, without sudo:  ./scripts/bootstrap.sh" >&2
  exit 1
fi

echo "==> [1/3] Installing packages with dnf (takes 1-3 minutes)..."
sudo dnf install -y openscap-scanner scap-security-guide openscap-utils ansible-core git python3-lxml

echo
echo "==> [2/3] Installing Ansible collections for $(id -un)..."
# The playbooks OpenSCAP generates use modules from these two collections.
# The versions are capped on purpose: RHEL 9 ships an older ansible-core, and
# the newest releases of these collections dropped support for it. Without the
# cap you'd get the latest versions, which can fail in confusing ways halfway
# through a long playbook run.
ansible-galaxy collection install 'ansible.posix:>=1.5.0,<2.0.0' 'community.general:>=8.0.0,<10.0.0'

echo
echo "==> [3/3] Installed versions"
echo "oscap:               $(oscap --version | head -n 1)"
echo "scap-security-guide: $(rpm -q scap-security-guide)"
echo "ansible-core:        $(ansible --version | head -n 1)"
# The STIG profile's description names the DISA STIG release it matches (like V2R5).
STIG_RELEASE="$(oscap info --profile "$STIG_PROFILE" "$DATASTREAM" 2>/dev/null | grep -o 'V[0-9]\+R[0-9]\+' | head -n 1 || true)"
echo "DISA STIG release:   ${STIG_RELEASE:-not found in profile description}"
echo
echo "Ansible collections:"
# `collection list` only accepts one name at a time, so check each separately.
for collection in ansible.posix community.general; do
  ansible-galaxy collection list "$collection" 2>/dev/null | grep "^$collection " \
    || echo "$collection: NOT FOUND (re-run this script)"
done

cat << 'NOTE'

====================================================================
 WRITE DOWN the scap-security-guide version and DISA STIG release
 printed above, and add them to docs/decisions.md.

 Why: DISA updates the STIG every quarter, and Red Hat ships new rule
 content to match. The same server can score differently next month
 just because the rules changed. Your numbers are only reproducible
 against this exact content version.
====================================================================
NOTE
