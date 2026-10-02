# scripts/

Helper scripts for the pipeline. The shell and Python scripts here run **on the RHEL 9 server** over SSH, as `ec2-user`, from the repo folder. `compare.py` also works on the Windows laptop.

| Script | What it does | Where it runs |
|---|---|---|
| `bootstrap.sh` | Installs the scanner, the STIG content, Ansible, git, and lxml, then prints the exact versions installed. Run once per fresh server. | Server |
| `scan.sh <label> [tailoring-file]` | Scans the server against the DISA STIG. Saves `results.xml`, `report.html`, and `summary.json` to `reports/<label>/`. Read-only; changes nothing. | Server |
| `parse_results.py <results.xml>` | Turns a results file into a score, a pass/fail table by CAT I/II/III, and a list of CAT I failures. Writes `summary.json`. Called by `scan.sh`. | Server (works anywhere with Python 3 + lxml) |
| `remediate.sh [--verify]` | Generates Ansible fix playbooks from the baseline scan, dry-runs them, applies them (skipping the rules listed at the top of the script), then checks you can still log in before you reboot. `--verify` runs only the final login checks. | Server |
| `compare.py` | Prints a before/after table (score and fails per CAT) from the baseline and hardened scans, and saves it as Markdown in `reports/comparison.md`. | Server or laptop |
