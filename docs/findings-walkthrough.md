# Findings Walkthrough: 10 Baseline Failures

Scan: `reports/baseline/` · 2026-09-25 · scap-security-guide 0.1.82 · DISA STIG V2R9 · score 46.46 · 256 failed rules (10 CAT I)

**Where this information comes from.** Titles, severities, STIG IDs, and the automatic fixes are taken from `reports/baseline/results.xml`. The exact test logic for each rule (the OVAL check) lives in the SSG content on the server (`/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml`) and is **not** copied into results.xml. So the "How the scanner checked it" lines are based on each rule's own description and fix in results.xml, not on the raw OVAL test.

---

## Read this first: three facts everything below rests on

1. **Every rule is one setting plus a test that reads it.** The scanner only looks. It never changes anything.
2. **A fix is a separate script that changes the setting.** Some rules have **no** automatic fix at all, because the setting can only be made when the operating system is installed, or would require hard-coding a password.
3. **Severity (CAT I/II/III) measures how bad the gap is, not how safe the fix is.** A CAT II fix can be more dangerous to apply than a CAT I fix.

## The one idea that sorts all ten

The only way into this server is a single path: **your SSH key → the `ec2-user` account → `sudo` to become root.** There's no keyboard or monitor attached, because it's a cloud machine.

So for every fix, ask one question: **does it touch that path, or does it need something that only exists at install time?**
- If it touches the path (SSH, keys, sudo, crypto), it's **careful** or **no**.
- If it needs install time (disk layout, FIPS), there's no automatic fix. It's **no**.
- Everything else, like adding logging, installing a package, or tightening an unused setting, is usually **yes**.

| # | Rule | CAT | Safe to auto-fix? |
|---|---|---|---|
| 1 | `sysctl_crypto_fips_enabled` | I | No (no automatic fix exists) |
| 2 | `configure_crypto_policy` | I | Careful |
| 3 | `grub2_password` | I | No (no automatic fix exists) |
| 4 | `sshd_disable_empty_passwords` | I | Yes |
| 5 | `sudo_remove_nopasswd` | II | No, not as-is |
| 6 | `sshd_disable_root_login` | II | Yes |
| 7 | `audit_rules_sudoers` | II | Yes |
| 8 | `package_aide_installed` | II | Yes |
| 9 | `accounts_tmout` | II | Yes, with a side effect |
| 10 | `partition_for_var_log_audit` | III | No (no automatic fix exists) |

---

## 1. `sysctl_crypto_fips_enabled`: Set kernel parameter 'crypto.fips_enabled' to 1
CAT I · RHEL-09-671010

**What it wants:** the server running in FIPS mode, meaning it only uses encryption code that the U.S. government has tested and certified.

**Why DISA cares:** encryption is only as good as the code doing it. Untested or weak algorithms can protect data in name only.

**How the scanner checked it:** it read the kernel setting `crypto.fips_enabled`. It's `1` in FIPS mode and `0` otherwise. On this server it's `0`.

**What the automatic fix will do:** nothing. There is no automatic fix. RHEL 9 only supports FIPS mode if the server was **installed** with `fips=1`. Red Hat says turning it on afterward is not supported, and that a failure here is "a permanent finding until the system is reinstalled."

**Note:** your guide mentions a rule called `enable_fips_mode`. In this STIG version that rule is `notselected` (it isn't part of the profile), so the FIPS gap shows up here instead.

**Safe to auto-fix on a cloud server?** No. There's nothing to run. The real fix is building the image with `fips=1` from the start (at install time).

---

## 2. `configure_crypto_policy`: Configure System Cryptography Policy
CAT I · RHEL-09-215105

**What it wants:** the server's system-wide encryption policy set to `FIPS:STIG`, which allows only the strictest, government-approved algorithms.

**Why DISA cares:** RHEL has one central switch that controls which algorithms every program (SSH, web servers, and so on) is allowed to use. If that switch is left on a permissive setting, weak algorithms stay available.

**How the scanner checked it:** it compared the active policy (`/etc/crypto-policies/config` and the generated files in `/etc/crypto-policies/back-ends/`) with `FIPS:STIG`.

**What the automatic fix will do:** run `update-crypto-policies --set FIPS:STIG`. The rule itself warns that the server needs a reboot for this to fully take effect.

**Safe to auto-fix on a cloud server?** Careful. This changes which login keys SSH accepts, and your lab key is **Ed25519**. Red Hat does not allow Ed25519 keys in FIPS mode. I couldn't confirm whether the `FIPS:STIG` policy alone (without full FIPS mode) rejects them. So after this fix runs and **before rebooting**, run `sudo sshd -T | grep -i pubkeyacceptedalgorithms` and confirm `ssh-ed25519` is still listed.

---

## 3. `grub2_password`: Set Boot Loader Password in grub2
CAT I · RHEL-09-212010

**What it wants:** a password on the boot menu (GRUB), the screen that appears before Linux starts.

**Why DISA cares:** someone at the console could edit boot options, for example to boot into single-user mode and get a root shell without a password.

**How the scanner checked it:** it looked for the password hash that `grub2-setpassword` writes, a `user.cfg` file in the GRUB folder under `/boot`.

**What the automatic fix will do:** nothing. There is no automatic fix. The rule explains why: a fix would have to hard-code the password inside the script, which is its own security problem.

**Safe to auto-fix on a cloud server?** No. There's nothing to run. The risk is also much smaller here, because nobody can walk up to an EC2 instance's keyboard. If required, set it during image build with a password from a secrets store.

---

## 4. `sshd_disable_empty_passwords`: Disable SSH Access via Empty Passwords
CAT I · RHEL-09-255040

**What it wants:** SSH to refuse any account whose password is blank.

**Why DISA cares:** an account with an empty password is an open door. Anyone who knows the username gets in.

**How the scanner checked it:** it read the SSH server config (`/etc/ssh/sshd_config` and the files in `/etc/ssh/sshd_config.d/`) looking for `PermitEmptyPasswords no`.

**Interesting:** SSH already refuses empty passwords by default. The rule failed because the STIG wants the setting **written down explicitly**, not just assumed. A scanner can only give credit for what it can read.

**What the automatic fix will do:** write `PermitEmptyPasswords no` into `/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf`.

**Safe to auto-fix on a cloud server?** Yes. You log in with a key, not a password, so this can't affect you.

---

## 5. `sudo_remove_nopasswd`: Ensure Users Re-Authenticate for Privilege Escalation - sudo NOPASSWD
CAT II · RHEL-09-611085

**What it wants:** every `sudo` command to require typing a password.

**Why DISA cares:** if someone steals a session or an SSH key, `NOPASSWD` hands them root instantly. Asking for a password adds a second lock.

**How the scanner checked it:** it read `/etc/sudoers` and every file in `/etc/sudoers.d/` looking for the word `NOPASSWD`. On AWS, cloud-init gives `ec2-user` a `NOPASSWD` line, usually in `/etc/sudoers.d/90-cloud-init-users`.

**What the automatic fix will do:** turn every line containing `NOPASSWD` into a comment (it adds `# ` in front) and check the file with `visudo` so it can't break the file's syntax.

**Safe to auto-fix on a cloud server?** No, not as-is. `ec2-user` has **no password**, because you log in with a key. After this fix, `sudo` asks for a password that doesn't exist. You can still log in over SSH, but you can never become root again. Prompt 6 handles this by setting a password for `ec2-user` first **and** skipping this rule.

---

## 6. `sshd_disable_root_login`: Disable SSH Root Login
CAT II · RHEL-09-255045

**What it wants:** SSH to refuse direct logins as `root`.

**Why DISA cares:** `root` exists on every Linux machine, so attackers always know half the login. Making people log in as themselves first also records **who** did something, not just "root did it."

**How the scanner checked it:** it read the SSH server config for `PermitRootLogin no`.

**What the automatic fix will do:** write `PermitRootLogin no` into `/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf`.

**Safe to auto-fix on a cloud server?** Yes. You never log in as root. Your path is `ec2-user` plus `sudo`, which this rule doesn't touch.

---

## 7. `audit_rules_sudoers`: Ensure auditd Collects System Administrator Actions - /etc/sudoers
CAT II · RHEL-09-654215

**What it wants:** the audit system to record every time someone changes `/etc/sudoers`, the file that decides who can become root.

**Why DISA cares:** adding yourself to sudoers is a classic way for an attacker to keep access. If it isn't logged, nobody can prove it happened.

**How the scanner checked it:** it read the audit rule files in `/etc/audit/rules.d/` looking for a rule that watches `/etc/sudoers` for writes and attribute changes (`perm=wa`).

**What the automatic fix will do:** add two watch lines (32-bit and 64-bit) to `/etc/audit/rules.d/actions.rules`. The rules become active when the audit rules are reloaded, which the reboot in Prompt 6 does.

**Safe to auto-fix on a cloud server?** Yes. It only adds logging. This is 1 of **69** `audit_rules_*` failures in your baseline, and nearly all are this same safe kind of fix.

---

## 8. `package_aide_installed`: Install AIDE
CAT II · RHEL-09-651010

**What it wants:** AIDE installed. AIDE is a tool that takes a "fingerprint" of important files and later tells you if any of them changed.

**Why DISA cares:** if an attacker swaps out a system program (say, `ssh` or `sudo`) for a tampered one, AIDE is how you'd find out.

**How the scanner checked it:** it asked the package database whether the `aide` package is installed.

**What the automatic fix will do:** run the equivalent of `dnf install aide`.

**Safe to auto-fix on a cloud server?** Yes. It's just installing a package. A related rule (`aide_build_database`) then builds the first fingerprint, which takes several minutes on a small server. Expect it to be one of the slow steps in Prompt 6.

---

## 9. `accounts_tmout`: Set Interactive Session Timeout
CAT II · RHEL-09-412035

**What it wants:** a login shell to log itself out after 10 minutes (600 seconds) with no typing.

**Why DISA cares:** a terminal someone walked away from is a logged-in session anyone nearby can use.

**How the scanner checked it:** it read `/etc/profile` and the files in `/etc/profile.d/` looking for `TMOUT` set to 600 or less, exported and read-only.

**What the automatic fix will do:** create `/etc/profile.d/tmout.sh` that sets `TMOUT=600` and locks it so users can't turn it off.

**Safe to auto-fix on a cloud server?** Yes, with a side effect. After hardening, if you leave the server sitting at its prompt for 10 minutes, it logs you out. It does **not** interrupt a command that's running (like a long scan). It only fires while the shell is waiting for you to type.

---

## 10. `partition_for_var_log_audit`: Ensure /var/log/audit Located On Separate Partition
CAT III · RHEL-09-231030

**What it wants:** audit logs stored on their own separate disk area (a partition), not sharing space with everything else.

**Why DISA cares:** if some other program fills the disk, auditing can't stop just because logs have nowhere to go. And if audit logs fill their own space, they can't crash the rest of the system.

**How the scanner checked it:** it checked whether `/var/log/audit` is its own mount point in the list of mounted filesystems. On this server everything is on one disk.

**What the automatic fix will do:** nothing on a running server. The only fixes that exist are install-time ones (Kickstart, the installer, Image Builder).

**Safe to auto-fix on a cloud server?** No. You can't repartition the disk the system is running from. In AWS you *could* attach a second disk and move the logs onto it by hand, but the right fix is building the image with the partition from the start. This is 1 of **6** `partition_for_*` failures, all with the same story.

---

## Notes for Prompt 6

- **`enable_fips_mode` isn't in this STIG version**, and the FIPS rule that did fail (`sysctl_crypto_fips_enabled`) has no automatic fix. Skipping FIPS in the playbook changes nothing. Record it in the exclusions register instead.
- **`sudo_remove_nopasswd` passed its sibling check:** `sudo_remove_no_authenticate` passed, and `sudo_require_authentication` isn't in this profile. Of the three sudo rules the guide skips, only `sudo_remove_nopasswd` actually matters here.
- **`configure_crypto_policy` isn't on the guide's skip list,** but it can change which SSH keys are accepted after reboot. Check `sshd -T` before rebooting (see #2).

---

## Quiz (answer in your next message)

1. `sudo_remove_nopasswd` is CAT II and `sshd_disable_empty_passwords` is CAT I. Which one is more dangerous to auto-fix on this server, and why doesn't the CAT level tell you that?
2. SSH already refuses empty passwords by default, yet `sshd_disable_empty_passwords` failed. Why would the scanner fail a rule when the server is already behaving safely?
3. Walk through what happens, step by step, if the `sudo_remove_nopasswd` fix runs and `ec2-user` has no password. After that, what can you still do on the server, and what can't you do?
4. `partition_for_var_log_audit` and `sysctl_crypto_fips_enabled` both come back with no automatic fix. What do they have in common, and what's the correct fix for each in a real deployment?
5. An interviewer says: "Your baseline shows CAT I failures. After you run the automatic remediation, which of the four CAT I findings in this file will be fixed, which will remain, and what do you say about the ones that remain?"
