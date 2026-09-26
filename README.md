# CCDC tryouts 2026: defense scripts

Scripts for a small CCDC-style environment: a VyOS router, Ubuntu 18.04, Windows Server 2016 (AD/DNS) and Rocky 9 with Splunk.
Scored services: HTTP, SSH, FTP, AD/DNS, POP3.

Every script has three ways to run:

| Mode | What it does |
|---|---|
| audit (default) | Read-only report. Changes nothing. |
| harden | Asks before every step. |
| harden --yes / -Yes | Runs the safe steps without asking. Still prompts once for the new password. |

Before changing anything they back up. Afterward they check that the services which were running are still running, and restart any that stopped.

## Safety rules the scripts follow

- Never delete accounts. Unknown accounts are locked or disabled, and the packet's users are never touched except for the password change.
- Never block by source IP. Firewalls allow scored ports from anywhere.
- Outbound traffic stays open, so the Splunk forwarders keep reaching both indexers. Forwarder config is never edited.
- Never change how scored services authenticate: no forced TLS, no FTP chroot, no disabling plaintext POP3.
- Every firewall change has an undo command, and the VyOS changes roll back on their own unless confirmed.

## Get the scripts onto each box

Linux (iron, redstone):
```bash
curl -fsSLO https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/linux/harden.sh
curl -fsSLO https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/linux/backup.sh
curl -fsSLO https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/linux/watchdog.sh
curl -fsSLO https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/linux/hunt.sh
chmod +x *.sh
```

Windows (lapis), in an elevated PowerShell:
```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
Invoke-WebRequest https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/windows/ccdc.ps1 -OutFile C:\ccdc.ps1
Set-ExecutionPolicy -Scope Process Bypass -Force
cd C:\
```

VyOS (bedrock), as `vyos`:
```bash
curl -fsSLO https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/vyos/ccdc-vyos.sh
chmod +x ccdc-vyos.sh
```

Laptop (for checking from outside):
```bash
curl -fsSLO https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/tools/scorecheck.sh && chmod +x scorecheck.sh
```

## Run order for the day

1. **10:00 - baseline from outside.** On the laptop: `./scorecheck.sh <team#> steve 'iyearn4theMines!'`.
   This records which services exist and saves each web page's MD5 hash. Keep it running in a second terminal:
   `WATCH=60 ./scorecheck.sh <team#> steve '<current password>'`
2. **Linux boxes:** `sudo ./hunt.sh` first. It records a hash baseline of critical binaries and shows what red team may already have done.
   Screenshot anything flagged for incident reports. Then `sudo ./harden.sh audit`, read it, and `sudo ./harden.sh harden --yes`.
   Add `--firewall` once you have checked the audit's listening-ports list.
3. **Windows:** `.\ccdc.ps1 -Mode Hunt`, then `.\ccdc.ps1` (audit), then `.\ccdc.ps1 -Mode Harden -Yes`.
4. **Submit the PCR** in Quotient right away. Each harden run prints the list of users whose password changed.
5. **Re-check from outside** with scorecheck. Anything DOWN? See "Recovery" below.
6. **Router:** `./ccdc-vyos.sh audit`, then `./ccdc-vyos.sh harden`. Optionally `./ccdc-vyos.sh firewall`.
   Confirm each within 10 minutes, but only after scorecheck shows everything UP:
   `configure; confirm; save; exit`
7. **Hunt every hour:** `sudo ./hunt.sh --since 1` and `.\ccdc.ps1 -Mode Hunt -Hours 1`, plus `splunk/searches.md`.
   The Linux hunt compares binaries against the 10:00 baseline, so a swapped `passwd` or `sshd` shows up as "changed since baseline".

## Recovery

| Problem | Fix |
|---|---|
| Linux service down | `sudo systemctl status <svc>`, then `journalctl -xeu <svc>`. The watchdog restarts it within a minute (log: `/var/log/ccdc-watchdog.log`). |
| Linux firewall broke something | `sudo ./harden.sh restore-firewall` |
| Restore one Linux file | `tar -xzpf /root/ccdc-backup/<time>/files.tar.gz -C / etc/path/to/file` |
| sshd change broke SSH | `sudo cp /etc/ssh/sshd_config.ccdc-bak /etc/ssh/sshd_config && sudo systemctl reload sshd` |
| Windows firewall broke something | `.\ccdc.ps1 -Mode RestoreFirewall` |
| IIS config damaged | `%windir%\system32\inetsrv\appcmd restore backup ccdc-<time>` |
| Router change broke scoring | Don't confirm it. It rolls back in 10 minutes. |
| Web page content changed (scorecheck WARN) | Compare against the backup copy of the web root and restore the changed files. |

## Files

| File | Purpose |
|---|---|
| `linux/harden.sh` | Audit and harden Ubuntu 18.04 and Rocky 9 |
| `linux/hunt.sh` | Read-only hunt: tampered binaries, PAM and shell hijacks, shell history, auth and web logs, log tampering, recent files |
| `linux/backup.sh` | Snapshot `/etc`, web and FTP roots, mail, crontabs and databases |
| `linux/watchdog.sh` | Restarts protected services. Installed as a systemd timer by `harden.sh` |
| `windows/ccdc.ps1` | Audit, hunt and harden Server 2016: DC-aware, with an IIS and service watchdog task |
| `vyos/ccdc-vyos.sh` | Router audit and hardening, using commit-confirm |
| `tools/scorecheck.sh` | Checks scored services from outside, like the scoring engine |
| `splunk/searches.md` | Hunting searches for Windows and Linux logs |

## What the hunt checks

**Linux (`hunt.sh`, read-only):**
- Each critical binary (`passwd`, `sudo`, `su`, `sshd`, `ps`, `ss`, `ls`, `find` and about 30 more):
  - its checksum is verified against the installed package (`dpkg --verify` / `rpm -V`)
  - it is flagged if it has been replaced by a script
  - it is compared against the hash baseline from the first run
- Files in bin directories that no package owns, and setuid files that no package owns.
- PAM hooks (`pam_exec`) and modified PAM modules.
- `/etc/ld.so.preload`, aliases or functions that shadow `sudo`/`ls`/`ps`, `PROMPT_COMMAND` hooks, and immutable files that block your fixes.
- Every user's shell history, with suspicious commands flagged, plus history that has been symlinked to `/dev/null` or disabled in startup files.
- Auth logs:
  - failed logins by source
  - successful logins
  - 5+ failures followed by a success from the same source
  - `sudo` commands
  - account changes
- Logs that were emptied, and logging services that were stopped.
- `wtmp`/`btmp`/`lastlog`, web access logs (web-shell and scanner patterns), recently changed files, and executables in temp directories.
- Files that a package owns and that are unmodified are skipped, so distro defaults don't raise false alarms.

**Windows (`-Mode Hunt`, read-only):**
- Signatures on critical system binaries and every service binary.
- Accessibility tools that are copies of `cmd.exe` (the sticky-keys trick).
- LSA packages, and changes to Winlogon's Userinit and Shell settings.
- Every user's PowerShell (PSReadLine) history.
- Event logs:
  - logs cleared (1102/104)
  - failed logons (4625) and network or RDP logons (4624)
  - brute force followed by success
  - account created (4720) and group changes (4728/4732/4756)
  - scheduled task created (4698) and service installed (7045)
  - process command lines (4688) and PowerShell script blocks (4104)
- Recently changed executables and scripts.

## Testing done

- **Linux harden:** full runs of `audit` and `harden --yes --firewall` on Ubuntu 18.04 and Rocky 9 (firewalld) containers with SSH, vsftpd, Dovecot and Apache. A second container then checked every service from outside, including passive FTP through the new firewall. The watchdog was tested by stopping and disabling vsftpd. The firewall undo was tested on a clean box.
- **Linux hunt:**
  - Clean boxes: no false alarms on Ubuntu 18.04 or Rocky 9, apart from two Docker-only artifacts.
  - Planted box: caught all 19 planted items. These included `passwd` swapped for a wrapper script, a changed binary, a PAM hook, a preload entry, a `sudo` alias, wiped or disabled history, brute force followed by a successful login in `auth.log`, web-shell requests and a binary in `/dev/shm`.
  - Tampered `id`: the root check uses bash's `$EUID` instead of `id -u`, so the scripts still run when `id` has been tampered with.
- **Windows:** run live on Windows 11: audit, hunt, harden (run twice, to check that a repeat run is clean), watchdog recovery of a stopped and disabled service, and `RestoreFirewall`.
  - The script refuses to run when it is not elevated.
  - Code paths specific to a domain controller (AD users, groups, DNS zones) and the IIS app-pool watchdog were **not** run, because there was no Windows Server or IIS. On lapis, run the audit first.
- **VyOS:** run live on a VyOS rolling router under QEMU:
  - audit, harden and firewall
  - the unconfirmed-change rollback, which reloads the previous config without rebooting
  - `confirm` then `save`, and repeat runs
  - a real traffic test through the 1:1 NAT: scored ports allowed, other ports blocked, passive FTP works
  - Every config path was also checked against the VyOS schema.
