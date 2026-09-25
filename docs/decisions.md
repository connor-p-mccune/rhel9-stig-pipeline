# Decisions Log

Deliberate design decisions made on this project, and the reasoning behind them.

## Target OS: RHEL 9

Reason: DISA's RHEL 9 STIG is mature and RHEL 9 is what most defense environments run. RHEL 10 exists but its STIG is newer and less commonly deployed.

<!-- Add new entries below this line, most recent last -->

## Pinned scan content and tool versions

Recorded 2026-09-25 from `scripts/bootstrap.sh` on the test server.

- Base image: `RHEL-9.8.0_HVM-20260908-x86_64-0-Hourly2-GP3` (`ami-0fec1400d2a5313ec`), from Red Hat's official AWS account (309956199498)
- scap-security-guide: 0.1.82-2.el9_8
- DISA STIG release (from the SSG `stig` profile description): V2R9
- OpenSCAP: 1.3.14
- ansible-core: 2.14.18

Reason: DISA updates the STIG every quarter, and Red Hat ships new scap-security-guide content to match. The same server can score differently against different content, so every score in `reports/` is only meaningful next to the versions that produced it. If any of these change (for example after a `dnf update`), re-run the baseline scan and record the new versions here.
