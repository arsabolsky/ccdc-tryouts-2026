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
2. **Linux boxes:** `sudo ./harden.sh audit`, read it, then `sudo ./harden.sh harden --yes`.
   Add `--firewall` once you have checked the audit's listening-ports list.
3. **Windows:** `.\ccdc.ps1` (audit), then `.\ccdc.ps1 -Mode Harden -Yes`.
4. **Submit the PCR** in Quotient right away. Each harden run prints the list of users whose password changed.
5. **Re-check from outside** with scorecheck. Anything DOWN? See "Recovery" below.
6. **Router:** `./ccdc-vyos.sh audit`, then `./ccdc-vyos.sh harden`. Optionally `./ccdc-vyos.sh firewall`.
   Confirm each within 10 minutes, but only after scorecheck shows everything UP:
   `configure; confirm; save; exit`
7. **Hunt** with `splunk/searches.md` and re-run the audits every hour. Anything new stands out against the first run.

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
| `linux/backup.sh` | Snapshot `/etc`, web and FTP roots, mail, crontabs and databases |
| `linux/watchdog.sh` | Restarts protected services. Installed as a systemd timer by `harden.sh` |
| `windows/ccdc.ps1` | Audit and harden Server 2016: DC-aware, with an IIS and service watchdog task |
| `vyos/ccdc-vyos.sh` | Router audit and hardening, using commit-confirm |
| `tools/scorecheck.sh` | Checks scored services from outside, like the scoring engine |
| `splunk/searches.md` | Hunting searches for Windows and Linux logs |

## Testing done

- **Linux:** full runs of `audit` and `harden --yes --firewall` on Ubuntu 18.04 and Rocky 9 (firewalld) containers with SSH, vsftpd, Dovecot and Apache. A second container then checked every service from outside, including passive FTP through the new firewall. The watchdog was tested by stopping and disabling vsftpd. The firewall undo was tested on a clean box.
- **Windows:** parsed with the PowerShell parser and linted with PSScriptAnalyzer. The port-matching logic has unit tests. It has not been run on a real Server 2016 box yet, so run the audit first.
- **VyOS:** syntax-checked only, not run on a router. That is why every change goes through commit-confirm.
