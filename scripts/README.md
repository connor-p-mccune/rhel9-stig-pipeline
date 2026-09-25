# scripts/

Helper scripts for the pipeline. Everything here runs **on the RHEL 9 server** over SSH, as `ec2-user`, from the repo folder. None of it runs on the Windows laptop.

| Script | What it does | Where it runs |
|---|---|---|
| `bootstrap.sh` | Installs the scanner, the STIG content, Ansible, git, and lxml, then prints the exact versions installed. Run once per fresh server. | Server |
| `scan.sh <label> [tailoring-file]` | Scans the server against the DISA STIG. Saves `results.xml`, `report.html`, and `summary.json` to `reports/<label>/`. Read-only; changes nothing. | Server |
| `parse_results.py <results.xml>` | Turns a results file into a score, a pass/fail table by CAT I/II/III, and a list of CAT I failures. Writes `summary.json`. Called by `scan.sh`. | Server (works anywhere with Python 3 + lxml) |
