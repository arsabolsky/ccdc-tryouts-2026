# CCDC tryouts 2026: defense scripts

Scripts for a small CCDC-style network:

| Box | IP (x = team #) | OS | Script |
|---|---|---|---|
| bedrock | 192.168.200+x.2 | VyOS router | `vyos/ccdc-vyos.sh` |
| iron | 192.168.200+x.10 | Ubuntu 18.04 | `linux/*.sh` |
| lapis | 192.168.200+x.11 | Windows Server 2016 (AD/DNS) | `windows/ccdc.ps1` |
| redstone | 192.168.200+x.12 | Rocky 9 + Splunk | `linux/*.sh` |
| your laptop | - | macOS/Linux | `tools/scorecheck.sh` |

Scored services: HTTP, SSH, FTP, AD/DNS, POP3.

Contents: [1. Competition-day guide](#1-competition-day-guide) - [2. Instructions](#2-instructions) - [3. Details and docs](#3-details-and-docs)

---

## 1. Competition-day guide

Follow this in order. Each step links to its full instructions in section 2.

**Before 10:00 (setup)**
1. Log in to Proxmox, Quotient and Discord. Note your team number (x).
2. On the laptop, download `scorecheck.sh` ([2.1](#21-download-the-scripts)).

**10:00 - first 15 minutes**

3. **Laptop: take the baseline from outside, before anyone changes anything.** Details in [2.5](#25-laptop-scorecheck).
   1. Connect the NetBird VPN.
   2. Replace `x` with your team number (team 12 is `12`) and run:
      `./scorecheck.sh x steve 'iyearn4theMines!'`
   3. Check the output. Every service a box runs should say **UP**, and the first run says "baseline md5 saved" for each web page.
      - **Everything DOWN:** the VPN is not connected, or the team number is wrong.
      - **One service DOWN:** it was already broken at the start. Fix it first (see [2.7](#27-recovery)).
4. **iron and redstone** (both at once), as root:
   1. Download the Linux scripts ([2.1](#21-download-the-scripts)).
   2. `./hunt.sh`: screenshot every `[!!]` (evidence for incident reports).
   3. `./harden.sh audit`: read the listening-ports list.
   4. `./harden.sh harden --yes --firewall`: type your new password once.
5. **lapis**, in an elevated PowerShell:
   `.\ccdc.ps1 -Mode Hunt`, then `.\ccdc.ps1`, then `.\ccdc.ps1 -Mode Harden -Yes`.
6. **Submit the PCR in Quotient now.** Each harden run printed the list of users whose password changed.
7. **Laptop:** `./scorecheck.sh x steve '<new password>'`. Everything must say UP.
   If anything says DOWN, see [2.7 Recovery](#27-recovery).

**Next 15 minutes**

8. **bedrock**, as vyos:
   1. `./ccdc-vyos.sh audit`
   2. `./ccdc-vyos.sh harden`
   3. Run scorecheck. If everything is UP: `configure; confirm; save; exit`
   4. Optional: `./ccdc-vyos.sh firewall`, then run scorecheck and confirm the same way.

   If you do not confirm within 10 minutes, the router undoes the change by itself.
9. **Leave scorecheck running** in its own terminal, with the **new** password:
   `WATCH=60 ./scorecheck.sh x steve '<new password>'`
   It re-checks every 60 seconds. Glance at it often: a DOWN or CONTENT CHANGED means act now.

**Rest of the day**

10. **Every hour:** `./hunt.sh --since 1` on Linux, and `.\ccdc.ps1 -Mode Hunt -Hours 1` on Windows.
    Also check Splunk with [`splunk/searches.md`](splunk/searches.md).
11. **Anything flagged:** screenshot it first, then fix it, then write it up as an incident report (your own words, no AI).
12. **Injects:** they are 50% of the score. Submit each one before its deadline as `teamXX_injectYY.pdf`.

---

## 2. Instructions

### 2.1 Download the scripts

The boxes can reach GitHub. Always download fresh copies at the start.

**Linux (iron, redstone), as root:**
```bash
for f in harden.sh backup.sh watchdog.sh hunt.sh; do curl -fsSLO https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/linux/$f; done
curl -fsSLO https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/tools/share.sh
chmod +x *.sh
```

**Windows (lapis):** right-click PowerShell and choose **Run as administrator**, then:
```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
cd C:\
iwr https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/windows/ccdc.ps1 -OutFile ccdc.ps1
iwr https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/windows/share.ps1 -OutFile share.ps1
Set-ExecutionPolicy -Scope Process Bypass -Force
```
If the script says "Not elevated", you opened a normal PowerShell. Reopen it as administrator.

**VyOS (bedrock), as vyos:**
```bash
curl -fsSLO https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/vyos/ccdc-vyos.sh && chmod +x ccdc-vyos.sh
curl -fsSLO https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/tools/share.sh && chmod +x share.sh
```

**Laptop:**
```bash
curl -fsSLO https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/tools/scorecheck.sh && chmod +x scorecheck.sh
curl -fsSLO https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/tools/share.sh && chmod +x share.sh
curl -fsSLO https://raw.githubusercontent.com/arsabolsky/ccdc-tryouts-2026/main/tools/ask.sh && chmod +x ask.sh
```

### 2.2 Linux: `harden.sh`, `hunt.sh`, `backup.sh`

| Command | What it does |
|---|---|
| `./hunt.sh` | Read-only hunt. Its first run saves a hash baseline of critical binaries |
| `./hunt.sh --since 1` | Only look at the last hour. Add `--full` to verify every package (about 30 s) |
| `./hunt.sh --share` | Hunt, then upload the report and print the link |
| `./harden.sh audit` | Read-only report: users, admins, keys, sshd, cron, listeners, login settings |
| `./harden.sh harden` | Asks y/N before each step |
| `./harden.sh harden --yes` | Runs every safe step without asking, except the firewall |
| `./harden.sh harden --yes --firewall` | Same, plus the inbound firewall |
| `... --share` | Add to `audit` or any harden command: upload this run's log at the end and print the link |
| `./harden.sh restore-firewall` | Undo the firewall step completely |
| `./backup.sh` | Take a fresh backup any time (harden also runs it) |
| `./backup.sh --share` | Backup, then upload the state snapshot (listeners, services, users, crontabs, firewall) |

Every `--share` needs `share.sh` in the same folder (the download command above puts it there). The link is public; passwords and hashes are redacted.

Harden runs these steps in order:
1. back up
2. set one password for all listed users and root
3. lock unknown accounts (never deletes them)
4. move `authorized_keys` files to quarantine
5. sshd: `PermitRootLogin no`
6. turn off anonymous FTP
7. stop unneeded services
8. set up the firewall
9. check that services are still up
10. install the watchdog

### 2.3 Windows: `ccdc.ps1`

| Command | What it does |
|---|---|
| `.\ccdc.ps1` | Read-only audit |
| `.\ccdc.ps1 -Mode Hunt [-Hours 1]` | Read-only hunt: signatures, sticky-keys trick, PowerShell history, event logs |
| `.\ccdc.ps1 -Mode Harden` | Asks y/N before each step |
| `.\ccdc.ps1 -Mode Harden -Yes` | Runs every step without asking (still prompts once for the password) |
| `... -Share` | Add to the audit, Hunt or Harden: upload the run's log with `share.ps1` at the end and print the link (needs `share.ps1` in the same folder) |
| `.\ccdc.ps1 -Mode RestoreFirewall` | Put the firewall back the way it was before harden |

Harden runs these steps in order:
1. back up the firewall, GPOs, DNS zones and IIS
2. set passwords
3. disable unknown accounts (never deletes them)
4. clean out privileged groups
5. firewall
6. Defender: real-time protection on, exclusions removed
7. remove sticky-keys hijacks
8. SMBv1 and Spooler off
9. logging
10. check that services are still up
11. install the watchdog task

### 2.4 VyOS: `ccdc-vyos.sh`

| Command | What it does |
|---|---|
| `./ccdc-vyos.sh audit` | Read-only: users, keys, NAT, firewall, services, scheduled tasks, boot scripts |
| `./ccdc-vyos.sh harden` | Router password, removes extra users/keys/tasks (asks for each), SSH on the LAN only, HTTPS API off |
| `./ccdc-vyos.sh firewall` | WAN to LAN filter that allows scored ports from anywhere and drops everything else new |
| `./ccdc-vyos.sh share` | Run the audit and upload it (needs `share.sh` next to the script) |

After `harden` or `firewall`, you have 10 minutes:
- **Everything UP in scorecheck:** `configure; confirm; save; exit`
- **Something broke:** do nothing. The previous config reloads by itself, without a reboot.
- **"A commit-confirm is still pending":** confirm or wait out the previous change first.

### 2.5 Laptop: `scorecheck.sh`

**Why:** the scoring engine checks your services from outside, through the router, at the public IPs. scorecheck does the same from your laptop, so you see what the scorer sees. Run it before you change anything: that first run defines "working", so later you can tell what broke.

**How to run it**

| When | Command |
|---|---|
| 10:00, before any changes (baseline) | `./scorecheck.sh x steve 'iyearn4theMines!'` |
| After harden changes the passwords | `./scorecheck.sh x steve '<new password>'` |
| All day, in its own terminal | `WATCH=60 ./scorecheck.sh x steve '<new password>'` |
| To also test DNS and LDAP | `DOMAIN=<ad.domain> ./scorecheck.sh x steve '<password>'` |
| One pass, then upload the results | `SHARE=1 ./scorecheck.sh x steve '<password>'` (needs `share.sh` next to it) |

- `x` is your team number. It sets the IPs: team 12 means iron is `192.168.212.10`, lapis `.11`, redstone `.12`.
- The username and password are what it logs in with for FTP and POP3, just like the scorer. Use the current password: an old one makes FTP and POP3 look DOWN when they're fine.
- Connect the NetBird VPN first.

**What the first run does**
1. It finds which scored services each box has (SSH, HTTP, HTTPS, FTP, POP3, DNS, LDAP) and saves the list in `~/.scorecheck/`. Later runs check that same list, so a service that dies shows as DOWN instead of disappearing from the output.
2. It logs in to FTP (including a file listing) and POP3, because an open port is not enough: the scorer needs a working login.
3. It saves each web page's MD5. The scorer compares pages by MD5 too, so a defaced page or a broken app shows up.

**Reading the output**

| Result | Meaning | What to do |
|---|---|---|
| `UP` | Working the way the scorer checks it | Nothing |
| `DOWN port closed` | The service stopped, or a firewall blocks it | Check the service on the box, then the firewall ([2.7](#27-recovery)) |
| `DOWN ... login failed` | Port open but login fails | Wrong password given to scorecheck, or login settings changed (`./harden.sh audit` shows them) |
| `WARN ... CONTENT CHANGED` | The web page differs from the 10:00 baseline | Compare the web root with the backup and restore the changed files |
| `WARN set DOMAIN=...` on DNS | It could not work out the AD domain | Re-run with `DOMAIN=<ad.domain>` |
| `Splunk web :8000 WARN unreachable` | Splunk's web page on redstone is unreachable | Not scored, but you need Splunk: check it |
| Everything DOWN | VPN not connected or wrong team number | Fix that and re-run |

**Starting over:** if the baseline was taken after something had already changed, delete `~/.scorecheck` and run it again.

### 2.6 Sharing a report, log or config (`share.sh` / `share.ps1`)

```bash
./share.sh /root/ccdc-backup                             # every text file in a folder (and subfolders), one link
./share.sh .                                             # every text file in the current folder, one link
./share.sh /root/ccdc-backup/hunt-*.txt                  # one link per file
./share.sh --one /etc/ssh/sshd_config /etc/vsftpd.conf   # several files in one link
./hunt.sh | ./share.sh -                                 # command output
curl -X DELETE https://paste.rs/<id>                     # delete a paste afterwards
```
```powershell
.\share.ps1 C:\ccdc-backup                  # every text file in a folder, one link
.\share.ps1 C:\ccdc-backup\ccdc-*.log
Get-Service | Out-String | .\share.ps1
```
- Pastes are public to anyone with the link.
- Folders: binary files and files over 2 MB are skipped; each file gets a `===== host:path =====` header in the paste.
- By default, shadow files and private keys are refused, and password values and hashes are replaced with `<redacted>`. `--raw` / `-Raw` turns that off.

**Second opinion from a local model (laptop, Ollama):** upload a report from the box with `share.sh`, then on the laptop run:
```bash
./ask.sh https://paste.rs/<id>                                   # triage: likely-real findings first
./ask.sh https://paste.rs/<id> "build a timeline of the attacker's actions"
tail -200 access.log | ./ask.sh - "any web shell or scanner activity?"
OLLAMA_MODEL=<name> ./ask.sh ...                                 # pick a model (default: first installed)
```
- The model only answers; nothing it says is run. Treat answers as leads to verify, never as commands to paste.
- Logs from an attacked box can contain text planted to mislead the model.
- Not for injects or incident reports: AI writing is against the tryout rules.

### 2.7 Recovery

| Problem | Fix |
|---|---|
| Linux service down | `systemctl status <svc>` and `journalctl -xeu <svc>`. The watchdog restarts it within a minute (log: `/var/log/ccdc-watchdog.log`) |
| Windows service down | The watchdog task restarts it within a minute (log: `C:\ccdc-backup\watchdog.log`) |
| Linux firewall broke something | `./harden.sh restore-firewall` |
| Windows firewall broke something | `.\ccdc.ps1 -Mode RestoreFirewall` |
| sshd change broke SSH | `cp /etc/ssh/sshd_config.ccdc-bak /etc/ssh/sshd_config && systemctl reload sshd` |
| Restore one Linux file | `tar -xzpf /root/ccdc-backup/<time>/files.tar.gz -C / etc/path/to/file` |
| IIS config damaged | `%windir%\system32\inetsrv\appcmd restore backup ccdc-<time>` |
| A locked account must come back | Linux: `usermod -U <u>; chage -E -1 <u>; usermod -s /bin/bash <u>`. Windows: `Enable-LocalUser <u>` or `Enable-ADAccount <u>` |
| Router change broke scoring | Don't confirm it. It reloads the old config within 10 minutes |
| Router says "Configuration system temporarily locked" | The automatic rollback did not happen. Fix the config by hand |
| scorecheck shows CONTENT CHANGED | Compare the web root with the backup and restore the changed files |
| POP3 or FTP login fails from outside | `./harden.sh audit` shows the login settings; plaintext logins must be allowed for the scorer |

---

## 3. Details and docs

### 3.1 How the scripts behave

| Mode | What it does |
|---|---|
| audit / hunt (default) | Read-only. Changes nothing |
| harden | Asks before every step |
| harden --yes / -Yes | Runs the safe steps without asking. Still prompts once for the new password (or reads `CCDC_PASSWORD`) |

Harden always backs up first. Afterwards it checks that every service that was running is still running, and restarts any that stopped.

### 3.2 Safety rules the scripts follow

- **Accounts:** never deleted. Unknown accounts are locked or disabled. The packet's users are changed only by the password step.
- **Source IPs:** never blocked. Firewalls allow scored ports from anywhere, as rule 4 requires.
- **Outbound traffic:** stays open, so the Splunk forwarders keep reaching both indexers. Forwarder config is never edited.
- **Scored-service logins:** never changed. No forced TLS, no FTP chroot, no disabling plaintext POP3.
- **Undo:** every firewall change has one, and VyOS changes roll back by themselves unless confirmed.
- **Firewall allow list:** it opens every port that has a listener at harden time. Read the printed "TCP allowed" list: a red-team listener that was already running would be on it.

### 3.3 Files

| File | Purpose |
|---|---|
| `linux/harden.sh` | Audit and harden Ubuntu 18.04 and Rocky 9 |
| `linux/hunt.sh` | Read-only hunt: tampered binaries, PAM and shell hijacks, shell history, auth and web logs, log tampering, recent files |
| `linux/backup.sh` | Snapshot `/etc`, web and FTP roots, mail, crontabs and databases |
| `linux/watchdog.sh` | Restarts protected services; `harden.sh` installs it as a systemd timer |
| `windows/ccdc.ps1` | Audit, hunt and harden Server 2016. DC-aware, with an IIS and service watchdog task |
| `windows/share.ps1` | Paste upload with redaction (Windows) |
| `vyos/ccdc-vyos.sh` | Router audit, hardening and firewall, using commit-confirm |
| `tools/scorecheck.sh` | Checks scored services from outside, like the scoring engine |
| `tools/share.sh` | Paste upload with redaction (Linux, VyOS, macOS) |
| `tools/ask.sh` | Laptop: send a paste link, file or piped text to a local Ollama model for triage |
| `splunk/searches.md` | Splunk hunting searches for Windows and Linux logs |

### 3.4 What the hunt checks

**Linux (`hunt.sh`):**
- **Critical binaries** (`passwd`, `sudo`, `su`, `sshd`, `ps`, `ss`, `ls`, `find` and about 30 more). Each one is:
  - verified against its package checksum (`dpkg --verify` / `rpm -V`)
  - checked for replacement by a wrapper script
  - compared with the first run's hash baseline
- **Unowned files:** files in bin directories, and setuid files, that no package owns.
- **Login hooks:**
  - PAM hooks (`pam_exec`) and modified PAM modules
  - `/etc/ld.so.preload`
  - aliases or functions that shadow commands, and `PROMPT_COMMAND` hooks
  - immutable files that block your fixes
- **Shell history:** every user's, with suspicious commands flagged. History symlinked to `/dev/null` or disabled in startup files is flagged too.
- **Auth logs:**
  - failed logins by source, and successful logins
  - 5+ failures followed by a success from the same source
  - `sudo` commands and account changes
- **Log tampering:** emptied logs and stopped logging services. Also `wtmp`/`btmp`/`lastlog`.
- **Other:**
  - web access logs (web-shell and scanner patterns)
  - recently changed files
  - executables in temp directories
- **False alarms:** files that a package owns and that are unmodified are skipped, so distro defaults don't raise false alarms.

**Windows (`-Mode Hunt`):**
- **Binaries:** signatures on critical system binaries and every service binary. Accessibility tools that are copies of `cmd.exe` (the sticky-keys trick) are flagged.
- **Logon hooks:** LSA packages, and Winlogon's Userinit and Shell settings.
- **PowerShell history:** every user's PSReadLine history.
- **Event logs:**
  - logs cleared (1102/104)
  - failed logons (4625) and network/RDP logons (4624), plus brute force followed by success
  - account created (4720) and group changes (4728/4732/4756)
  - scheduled task created (4698) and service installed (7045)
  - process command lines (4688) and PowerShell script blocks (4104)
- **Recent files:** recently changed executables and scripts.

### 3.5 Testing done

- **Linux:**
  - Tested on Ubuntu 18.04 and Rocky 9 containers and on full machines (Ubuntu 22.04, Rocky 9.8).
  - Harden: audit, confirm mode (y and n answers), and `--yes --firewall`, then a check from outside. SSH, HTTP, FTP login with a passive listing, and POP3 were all UP, and a rogue port was blocked.
  - Reboot:
    - the firewall persists, and was re-checked on real Ubuntu 18.04
    - the watchdog timer restarts a stopped *and disabled* service by itself
    - `restore-firewall` undoes both the iptables and firewalld versions exactly
  - Restoring a single file from backup works.
  - The hunt had no false alarms on clean boxes and caught all 19 planted items. Among them were a `passwd` wrapper, swapped binaries, a PAM hook, a preload entry, a `sudo` alias, wiped history, brute force followed by a successful login, and web-shell requests. It still runs when `id` has been tampered with.
- **Windows:** run live on Windows 11:
  - audit and hunt; hunt caught the brute force, new accounts and planted history
  - harden, run twice with no errors and no duplicates on the second run
  - the watchdog revived a stopped and disabled service within about 60 s
  - `RestoreFirewall`
  - the script refuses to run when not elevated
  - Defender itself blocked two planted tricks (a `C:\` exclusion and the sticky-keys hijack)
- **VyOS:** run live on a VyOS rolling router under QEMU:
  - audit, harden and firewall
  - an unconfirmed change reloads the old config (no reboot)
  - `confirm` then `save`, and repeat runs
  - a real traffic test through the 1:1 NAT: scored ports open, others blocked, passive FTP works
  - every config path was checked against the VyOS schema
- **share.sh / share.ps1:** tested against a local mock paste server (refusal, binaries, redaction, combined pastes, folders, stdin, raw), plus one real paste.rs upload, fetch and delete.
- **Not tested:**
  - Windows code specific to a domain controller (AD users, groups, DNS zones) and the IIS app-pool watchdog; there was no Windows Server or IIS. On lapis, run the audit first and read it.
  - VyOS 2025.11 exactly; a 2026 rolling build was used.
  - The DNS and LDAP checks in scorecheck.
