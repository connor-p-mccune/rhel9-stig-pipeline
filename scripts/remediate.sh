#!/usr/bin/env bash
# =============================================================================
# scripts/remediate.sh
#
# WHAT THIS DOES (plain language)
# Fixes the STIG rules that failed in the baseline scan, carefully:
#   STEP 0  Safety net: make sure ec2-user has a password.
#   STEP 1  Turn the baseline scan results into an Ansible playbook
#           (a long list of fixes, one group of tasks per failed rule).
#   STEP 2  Dry run: show what WOULD change, without changing anything.
#   STEP 3  Apply the fixes for real (asks first). Takes about 20-45 minutes.
#   STEP 4  Check you can still log in, then tell you to reboot.
#
# USAGE (on the server, as ec2-user, from the repo folder):
#   ./scripts/remediate.sh            # all steps
#   ./scripts/remediate.sh --verify   # STEP 4 only. Use this if your SSH
#                                     # connection dropped during STEP 3.
#
# WHERE IT RUNS: on the RHEL 9 server, over SSH. Never on your laptop.
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------------
# RULES WE DELIBERATELY DO NOT APPLY HERE
# The generated playbook tags every task with the id of the rule it fixes.
# That's what makes --skip-tags work: listing a rule id here makes Ansible skip
# every task belonging to that rule.
#
#   sudo_remove_nopasswd         Removes ec2-user's passwordless sudo. On a
#                                cloud image ec2-user logs in with a key and
#                                has no password, so after this rule runs,
#                                sudo asks for a password that doesn't exist
#                                and you can never become root again.
#   sudo_remove_no_authenticate  Same family, same lockout. It passed the
#                                baseline scan, so it isn't in this playbook,
#                                but it IS in the full playbook the image build
#                                uses later, so it stays on the list.
#   sudo_require_authentication  Same family. Not part of this STIG version
#                                (SSG 0.1.82 / DISA V2R9), so skipping it does
#                                nothing today. Kept so this list matches the
#                                exclusions register.
#   enable_fips_mode             Also not part of this STIG version. The FIPS
#                                rule that did fail, sysctl_crypto_fips_enabled,
#                                has no automatic fix at all: RHEL 9 only
#                                supports FIPS mode if it's turned on when the
#                                OS is installed. Handled in the exclusions
#                                register, not here.
#   service_fapolicyd_enabled    fapolicyd only lets the server run code that
#   fapolicy_default_deny        came from an installed RPM package. Its rules
#                                stop Python from opening any other .py file,
#                                which includes Ansible's add-on collections
#                                (in ~/.ansible) and this project's own
#                                parse_results.py and compare.py. Turning it on
#                                mid-run would break the rest of this playbook
#                                and every scan after it. Turning it on safely
#                                needs an allow list built first. Handled in
#                                the exclusions register.
# -----------------------------------------------------------------------------
SKIP_TAGS="sudo_remove_nopasswd,sudo_remove_no_authenticate,sudo_require_authentication,enable_fips_mode,service_fapolicyd_enabled,fapolicy_default_deny"

DATASTREAM=/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
PROFILE=xccdf_org.ssgproject.content_profile_stig
BASELINE_RESULTS=reports/baseline/results.xml
FROM_RESULTS_PLAYBOOK=ansible/remediate-from-results.yml
FULL_PLAYBOOK=ansible/remediate-full.yml
RUN_LOG=reports/hardened/ansible-run.log
FAILED_TASKS=reports/hardened/failed-tasks.txt

# Options used for every ansible-playbook run below:
#   -i "localhost,"   the list of servers to work on: just this one. The comma
#                     tells Ansible it's a list, not a file name.
#   -c local          run directly on this machine instead of connecting over SSH
#   --become          run each task as root (through sudo)
#   -e ansible_python_interpreter=...   use the system Python; silences a warning
ANSIBLE_ARGS=(-i "localhost," -c local --become
              -e ansible_python_interpreter=/usr/bin/python3
              --skip-tags "$SKIP_TAGS")
export ANSIBLE_LOCALHOST_WARNING=False
# Pipelining sends each task's code straight to Python instead of writing it
# to a temporary file first. Same result, noticeably faster over 3,000+ tasks.
export ANSIBLE_PIPELINING=True

header() {
  echo
  echo "=================================================================="
  echo " $1"
  echo "=================================================================="
}

# Work from the repo's top folder no matter where this was started from.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ "$(id -u)" -eq 0 ]; then
  echo "ERROR: run this as ec2-user, without sudo:  ./scripts/remediate.sh" >&2
  exit 1
fi

# The server's public IP, so the instructions at the end can show the exact
# SSH command. Asks AWS's built-in metadata service; prints nothing if it can't.
public_ip() {
  local token
  token="$(curl -s --max-time 2 -X PUT "http://169.254.169.254/latest/api/token" \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 60" || true)"
  curl -s --max-time 2 -H "X-aws-ec2-metadata-token: $token" \
       "http://169.254.169.254/latest/meta-data/public-ipv4" || true
}

# -----------------------------------------------------------------------------
# STEP 4 lives in a function so --verify can run it on its own.
# -----------------------------------------------------------------------------
verify_and_reboot_instructions() {
  header "STEP 4 - Make sure you can still get in, then reboot"

  # 1. Can ec2-user still become root without a password?
  if sudo -n true 2>/dev/null; then
    echo "[OK]   sudo still works for ec2-user."
  else
    echo "[WARN] sudo now asks for a password. Use the ec2-user password from STEP 0."
  fi

  # 2. Is the SSH server's configuration still valid? If it isn't, SSH would
  #    refuse to start after a reboot and nobody could log in.
  if sudo sshd -t; then
    echo "[OK]   SSH configuration is valid."
  else
    echo
    echo "[STOP] The SSH configuration has an error (shown above)."
    echo "       Do NOT reboot and do NOT close this window."
    echo "       Send Claude a screenshot of this error."
    exit 1
  fi

  # 3. The STIG switches the server to the FIPS:STIG encryption policy, which
  #    limits the kinds of login keys SSH accepts. Your key is Ed25519.
  #    "sshd -T" prints the settings SSH will actually use; we look for
  #    ssh-ed25519 as an exact entry in its comma-separated list of key types.
  local key_types
  key_types="$(sudo sshd -T | awk '/^pubkeyacceptedalgorithms /{print $2}')"
  if [[ ",$key_types," == *",ssh-ed25519,"* ]]; then
    echo "[OK]   SSH still accepts your Ed25519 key."
  else
    echo
    echo "[STOP] The new encryption policy no longer accepts Ed25519 keys,"
    echo "       which is the type of key you log in with."
    echo "       Do NOT reboot and do NOT close this window."
    echo "       Send Claude a screenshot of this message."
    exit 1
  fi

  # 4. Restart SSH so the new settings take effect now, while this window is
  #    still open. On RHEL, restarting SSH does not close sessions that are
  #    already open, so this window stays connected either way.
  sudo systemctl restart sshd
  echo "[OK]   SSH restarted with the new settings. This window stays connected."

  local ip
  ip="$(public_ip)"
  cat << EOF

------------------------------------------------------------------
 LAST CHECK BEFORE REBOOTING
------------------------------------------------------------------
 Keep THIS window open. On your laptop, open a SECOND PowerShell
 window and log in the same way:

   ssh -o ServerAliveInterval=60 -i \$env:USERPROFILE\\.ssh\\stig-lab ec2-user@${ip:-<server IP>}

 You'll see a long U.S. Government warning banner first. That's one
 of the fixes. If it asks you to confirm the fingerprint, type yes.

   - If you get in: type exit in the SECOND window, then come back
     to this window and reboot.
   - If you can't get in: do NOT close this window. Send Claude the
     error from the second window.
------------------------------------------------------------------

Reboot now with: sudo reboot. Wait 60 seconds, SSH back in, then run: ./scripts/scan.sh hardened
EOF
}

if [ "${1:-}" = "--verify" ]; then
  verify_and_reboot_instructions
  exit 0
fi

# =============================================================================
header "STEP 0 - Safety net"
# =============================================================================
cat << 'EOF'
The STIG removes passwordless sudo. Before continuing, ec2-user needs a
password so you can still become root if that rule runs.

(This script skips that rule, but the password is your backup if anything
else changes how sudo behaves.)
EOF

# "passwd -S" reports an account's password status: PS = a password is set,
# LK = locked, NP = no password. Cloud images ship ec2-user without one.
status="$(sudo passwd -S ec2-user | awk '{print $2}')"
if [ "$status" = "PS" ]; then
  echo
  echo "[OK] ec2-user already has a password."
else
  cat << 'EOF'

ec2-user has no password yet. Set one now (sudo passwd ec2-user).
  - Use 15 or more characters with upper case, lower case, a number,
    and a symbol. The STIG requires that for every password from now on.
  - Nothing appears on screen while you type. That's normal.
  - Save it in a password manager, not in any file in this project.
  - After hardening, 3 wrong password attempts lock the account's
    password and it does NOT unlock on its own. Type carefully.

EOF
  sudo passwd ec2-user
fi
echo
read -rp "Press Enter to continue (or Ctrl+C to stop)... "

# =============================================================================
header "STEP 1 - Generate the fix playbooks"
# =============================================================================
if [ ! -f "$BASELINE_RESULTS" ]; then
  echo "ERROR: $BASELINE_RESULTS not found. Run ./scripts/scan.sh baseline first." >&2
  exit 1
fi
mkdir -p ansible

# Playbook 1: fixes ONLY for rules that failed in the baseline scan.
# --result-id "" means "use the first scan result in the file". A results file
# can hold more than one scan; ours holds exactly one, so the first is the one.
echo "Generating fixes for the rules that failed in the baseline scan..."
oscap xccdf generate fix --fix-type ansible --result-id "" \
  --output "$FROM_RESULTS_PLAYBOOK" "$BASELINE_RESULTS"

# Playbook 2: fixes for EVERY rule in the STIG profile, whatever this server's
# current state. Not run here; the image build (Packer) will use it later,
# because a fresh image has no scan results to work from.
echo "Generating fixes for the whole STIG profile (used later by the image build)..."
oscap xccdf generate fix --fix-type ansible --profile "$PROFILE" \
  --output "$FULL_PLAYBOOK" "$DATASTREAM"

# By default Ansible stops at the first task that fails. With over a thousand
# tasks, one fix that can't apply on this server would stop all the others.
# This adds one line to the play: "ignore_errors: true". Failed tasks are still
# shown as failed in the output and the log (followed by "...ignoring"), and
# counted in the summary at the end. They just don't stop the run.
if ! grep -q '^  ignore_errors: true$' "$FROM_RESULTS_PLAYBOOK"; then
  sed -i '0,/^- hosts: all$/s//- hosts: all\n  # Added by scripts\/remediate.sh: keep going past individual task failures.\n  ignore_errors: true/' "$FROM_RESULTS_PLAYBOOK"
fi
if grep -q '^  ignore_errors: true$' "$FROM_RESULTS_PLAYBOOK"; then
  echo "[OK] Playbook set to keep going past individual task failures."
else
  echo "[WARN] Couldn't add ignore_errors; the run will stop at the first failed task."
fi

echo
echo "Line counts:"
wc -l "$FROM_RESULTS_PLAYBOOK" "$FULL_PLAYBOOK"

# Make sure the playbook is valid and every module it uses can be found
# (this is where missing collections would show up).
echo
echo "Checking the playbook can be read..."
ansible-playbook "${ANSIBLE_ARGS[@]}" --syntax-check "$FROM_RESULTS_PLAYBOOK" > /dev/null
echo "[OK] Playbook syntax is valid."

# =============================================================================
header "STEP 2 - Dry run (check mode): nothing on the server changes"
# =============================================================================
cat << 'EOF'
Ansible now walks through every fix and reports what it WOULD change.
This takes a few minutes and prints a lot.

Red "failed" lines followed by "...ignoring" are EXPECTED here. Some fixes
can't be simulated without really making the change (for example, a step
that reads a file an earlier step would have created). Keep going.
EOF
echo
check_rc=0
ansible-playbook "${ANSIBLE_ARGS[@]}" --check "$FROM_RESULTS_PLAYBOOK" || check_rc=$?
echo
echo "Dry run finished (exit code $check_rc)."
echo "In the PLAY RECAP line above, changed=N is roughly how many changes the real run will make."

# =============================================================================
header "STEP 3 - Apply the fixes for real"
# =============================================================================
read -rp "Apply for real? (yes/no) " answer
if [ "$answer" != "yes" ]; then
  echo "Stopped before applying any fixes. Run this script again when you're ready."
  exit 0
fi

mkdir -p "$(dirname "$RUN_LOG")"
cat << EOF

Applying fixes. This takes about 20-45 minutes (it's over 3,000 small tasks).
Everything shown here is also saved to $RUN_LOG

  - Keep your laptop awake and plugged in.
  - Pressing Ctrl+C only stops you WATCHING. The run keeps going.
  - If your SSH connection drops, the run keeps going on the server.
    Reconnect, then watch it with:
        tail -f ~/rhel9-stig-pipeline/$RUN_LOG
    When it shows "PLAY RECAP", press Ctrl+C and run:
        ./scripts/remediate.sh --verify

EOF
sleep 3

# The guide's version pipes the output through "tee" (show it AND save it).
# This does the same thing in a way that survives a dropped connection:
# "nohup ... &" runs Ansible in the background, immune to the SSH session
# ending, writing everything to the log. "tail -f" shows the log live and
# stops by itself when Ansible finishes.
nohup ansible-playbook "${ANSIBLE_ARGS[@]}" "$FROM_RESULTS_PLAYBOOK" > "$RUN_LOG" 2>&1 &
ansible_pid=$!
tail --pid="$ansible_pid" -n +1 -f "$RUN_LOG" || true
run_rc=0
wait "$ansible_pid" || run_rc=$?

echo
if [ "$run_rc" -eq 0 ]; then
  echo "[OK] Ansible finished."
else
  echo "[WARN] Ansible stopped early with exit code $run_rc. The last lines of $RUN_LOG show where."
fi

# List every task that failed (and was skipped over), for the write-up.
awk '/^TASK \[/{task=$0; sub(/^TASK \[/, "", task); sub(/\] \**$/, "", task)}
     /^fatal:/{print task}' "$RUN_LOG" | sort -u > "$FAILED_TASKS" || true
echo "Tasks that failed and were skipped over: $(wc -l < "$FAILED_TASKS")  (list saved to $FAILED_TASKS)"
grep -A2 "^PLAY RECAP" "$RUN_LOG" || true

verify_and_reboot_instructions
