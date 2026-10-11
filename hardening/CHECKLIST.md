# Linux hardening checklist

Scope: Debian/Ubuntu-style hosts (`/etc/ssh/sshd_config`, `/etc/login.defs`,
`/etc/sysctl.d/`, `/etc/passwd`, `/etc/shadow`).

Items with an ID are checked and, with `--apply`, fixed by `hardening/harden.sh`.
Items under "Manual-only" need a human decision and are not automated.

## How to run

```bash
sudo hardening/harden.sh --check            # report only (default), exit 0 / 1 / 2
sudo hardening/harden.sh --apply            # fix the FAILs, back up changed files
sudo hardening/harden.sh --apply --reload   # also run sysctl -p and reload sshd
sudo hardening/harden.sh --check --only SSH-01
```

Output: one line per check, `PASS|FAIL|FIXED <ID> <description>`, then a
`SUMMARY` line. Exit codes: `0` no FAIL remains, `1` a FAIL remains, `2` usage error.

The script reads config files only. It does not query the live kernel or sshd,
so confirm live values with the verify commands below.

## Automated checks

| ID | Check | Rationale | CIS-style reference | Manual verify command |
|---|---|---|---|---|
| SSH-01 | `PermitRootLogin no` in `sshd_config` | Direct root logins remove per-user accountability, and root is the first account attackers guess. | CIS Linux Benchmark, section 5.2 (SSH Server Configuration): "Ensure SSH root login is disabled" | `sudo sshd -T \| grep -i '^permitrootlogin'` (expect `permitrootlogin no`) |
| SSH-02 | `PasswordAuthentication no` | Blocks password guessing and credential stuffing. Key-based login only. | CIS 5.2: "Ensure SSH PasswordAuthentication is disabled" | `sudo sshd -T \| grep -i '^passwordauthentication'` |
| SSH-03 | `X11Forwarding no` | X11 forwarding gives a compromised client a path to the local X server. Servers do not need it. | CIS 5.2: "Ensure SSH X11 forwarding is disabled" | `sudo sshd -T \| grep -i '^x11forwarding'` |
| SSH-04 | `MaxAuthTries` is 4 or less | Limits guesses per connection. | CIS 5.2: "Ensure SSH MaxAuthTries is set to 4 or less" | `sudo sshd -T \| grep -i '^maxauthtries'` |
| SYS-01 | `net.ipv4.ip_forward = 0` in `/etc/sysctl.d/99-sentinel.conf` | A host that is not a router should not forward packets between networks. | CIS Linux Benchmark, section 3 (Network Configuration): "Ensure IP forwarding is disabled" | `sysctl net.ipv4.ip_forward` (expect `0`) |
| SYS-02 | `net.ipv4.conf.all.accept_redirects = 0` | ICMP redirects can change the routing table and enable man-in-the-middle traffic capture. | CIS section 3: "Ensure ICMP redirects are not accepted" | `sysctl net.ipv4.conf.all.accept_redirects` |
| SYS-03 | `kernel.randomize_va_space = 2` | Full address space layout randomization makes memory-corruption exploits less reliable. | CIS Linux Benchmark, section 1 (Initial Setup): "Ensure address space layout randomization (ASLR) is enabled" | `sysctl kernel.randomize_va_space` (expect `2`) |
| SYS-04 | `net.ipv4.tcp_syncookies = 1` | SYN cookies stop a SYN flood from exhausting the connection backlog. | CIS section 3: "Ensure TCP SYN Cookies is enabled" | `sysctl net.ipv4.tcp_syncookies` (expect `1`) |
| AUTH-01 | `PASS_MAX_DAYS` is 90 or less in `/etc/login.defs` | Limits how long one password stays valid. | CIS section 5.4 (User Accounts and Environment): "Ensure password expiration is 365 days or less". The 90-day limit here is stricter than that CIS value, on purpose. | `grep '^PASS_MAX_DAYS' /etc/login.defs` and `sudo chage -l <user>` |
| PERM-01 | `/etc/shadow` mode 640 or stricter (no bits outside 640) | Shadow holds password hashes. Only root and the shadow group may read it. | CIS section 6.1 (System File Permissions): "Ensure permissions on /etc/shadow are configured" | `stat -c '%a %U:%G %n' /etc/shadow` |
| PERM-02 | `/etc/passwd` mode exactly 644 | World-readable is normal for passwd. Other users must not be able to write it. | CIS section 6.1: "Ensure permissions on /etc/passwd are configured" | `stat -c '%a %U:%G %n' /etc/passwd` |

Notes on the automated checks:

- Each SSH and login.defs check passes only when every active (non-comment)
  setting for that key is compliant. A missing setting is a FAIL.
- sshd settings inside `Match` blocks are also checked, so a block that
  re-enables a bad value fails the check.
- `--apply` replaces every active setting of the key with the compliant value.
  If there is none, it inserts one: `PermitRootLogin`, `PasswordAuthentication`,
  `X11Forwarding` and `MaxAuthTries` go at the top of `sshd_config`, so they win
  over later lines. The sysctl and login.defs lines are appended.
- sysctl values go in `/etc/sysctl.d/99-sentinel.conf`. `--apply` creates that
  file if it is missing.
- PERM-01 and PERM-02 change the mode with `chmod`. `--apply` sets exactly 640
  (shadow) or 644 (passwd).

## Manual-only items

These are not automated because each one depends on the host's role, and some
of them install packages.

| Item | Rationale | CIS-style reference | Manual verify command |
|---|---|---|---|
| auditd installed, enabled and watching identity and privilege files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`) | Gives an audit trail of account and privilege changes. Needed to investigate incidents. | CIS Linux Benchmark, section 4.1 (Configure System Accounting, auditd) | `systemctl is-enabled auditd` and `sudo auditctl -l` (expect watch rules for the files above) |
| Unattended security upgrades | Known vulnerabilities get patched without waiting for a person. | CIS section 1 (Initial Setup), patch management | Debian/Ubuntu: `systemctl is-enabled unattended-upgrades` and `apt-config dump \| grep -i unattended` |
| Firewall default deny for inbound traffic (`ufw default deny incoming`, or an nftables/iptables input policy of drop) | Only the ports that are needed are reachable. | CIS section 3 (Network Configuration), firewall configuration | `sudo ufw status verbose` (expect `Default: deny (incoming)`) or `sudo nft list ruleset \| grep -i policy` |

## Known limits

- Run the script only on hosts you own and have authority to change. Start
  with `--check`, which changes nothing.
- `--apply` backs up each changed file to `<file>.sentinel.bak` (mode 600), once.
  Backing up `/etc/shadow` writes a second copy of the password hashes to disk.
  Delete `/etc/shadow.sentinel.bak` after you have checked the result.
- The temp file used for a rewrite is created in the same directory and then
  moved into place. The new file keeps the original mode. Owner and group come
  from the user running the script, which is root for a real host.
- `--reload` runs `sysctl -p` and reloads sshd only when the script runs on a
  real host (SENTINEL_ROOT empty) and something changed. It is ignored when
  SENTINEL_ROOT is set.
- The checks cover Debian/Ubuntu paths. On other distributions, the sshd, sysctl
  and login.defs paths may differ.
- CIS section numbers differ between benchmark versions. Check the titles
  against the benchmark version you use.
