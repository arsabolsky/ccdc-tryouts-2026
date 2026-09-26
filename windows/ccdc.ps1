<#
ccdc.ps1 - audit and harden Windows Server 2016 (domain controller or member).

  .\ccdc.ps1                      read-only audit (default)
  .\ccdc.ps1 -Mode Harden         asks before every step
  .\ccdc.ps1 -Mode Harden -Yes    runs the safe steps without asking
  add -Share (Audit, Harden or Hunt) to upload the run's log with share.ps1 (redacted, public link)
  .\ccdc.ps1 -Mode Hunt           read-only hunt: signatures, PowerShell history, event logs
  .\ccdc.ps1 -Mode Hunt -Hours 3  ...only look at the last 3 hours of events
  .\ccdc.ps1 -Mode Watch          one watchdog pass (the installed task runs this)
  .\ccdc.ps1 -Mode RestoreFirewall

Run from an elevated PowerShell:
  Set-ExecutionPolicy -Scope Process Bypass -Force

Rules this script follows (from the team packet):
  - never deletes accounts (disables only), never blocks by source IP
  - never touches the Splunk forwarder's outputs; outbound traffic stays open
  - never removes default AD group nesting or built-in accounts
#>
param(
  [ValidateSet('Audit','Harden','Hunt','Watch','RestoreFirewall')][string]$Mode = 'Audit',
  [switch]$Yes,
  [int]$Hours = 24,
  [switch]$Share
)
$ErrorActionPreference = 'Continue'

# Without elevation most checks silently return nothing and every change fails.
$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'Not elevated. Right-click PowerShell > Run as administrator, then run this again.' -ForegroundColor Red
  exit 1
}

$Admins   = @('steve','alex')
$Listed   = @('steve','alex','enderman','creeper','villager','zombie','enderdragon','irongolem','chickenjockey','ghast')
$BuiltIn  = @('Administrator','Guest','krbtgt','DefaultAccount','WDAGUtilityAccount')
# Scored-service ports, plus AD ports a DC needs. Allowed inbound from anywhere.
$ScoredTcp = @(21,22,53,80,88,110,135,389,443,445,464,636,995,3268,3269,3389,5985,9389)
$ScoredUdp = @(53,88,123,389,464)

$State = 'C:\ccdc-backup'
New-Item -ItemType Directory -Force -Path $State | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Log   = Join-Path $State "ccdc-$Stamp.log"
if ($Mode -ne 'Watch') { Start-Transcript -Path $Log -Append | Out-Null }

function Hdr($t)  { Write-Host "`n== $t ==" -ForegroundColor Cyan }
function Good($t) { Write-Host "  [ok] $t" -ForegroundColor Green }
function Flag($t) { Write-Host "  [!!] $t" -ForegroundColor Red }
function Note($t) { Write-Host "  [--] $t" -ForegroundColor Yellow }
function Ask($q) {
  if ($Mode -ne 'Harden') { return $false }
  if ($Yes) { Write-Host "  -> $q (auto)"; return $true }
  $r = Read-Host "  ?? $q [y/N]"
  return ($r -match '^[Yy]')
}

$IsDC = $false
try { $IsDC = ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) } catch { Note "could not read domain role: $_" }
if ($IsDC) { Import-Module ActiveDirectory -ErrorAction SilentlyContinue }

function Get-Listeners {
  Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort,
      @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
      OwningProcess | Sort-Object LocalPort -Unique
}

# Services worth keeping alive if present and running now.
$Candidates = @('NTDS','DNS','Netlogon','Kdc','ADWS','W3SVC','WAS','FTPSVC','sshd','SplunkForwarder','TermService','DFSR','IsmServ')

# ------------------------------------------------------------------ Audit --
function Invoke-Audit {
  Hdr "System: $((Get-CimInstance Win32_OperatingSystem).Caption)  ($env:COMPUTERNAME)  DC=$IsDC"

  Hdr 'Listening TCP ports'
  Get-Listeners | ForEach-Object { '  {0,-6} {1,-18} {2}' -f $_.LocalPort, $_.LocalAddress, $_.Process }

  Hdr 'Accounts'
  if ($IsDC) { $users = Get-ADUser -Filter * -Properties Enabled, whenCreated | Select-Object SamAccountName, Enabled, whenCreated }
  else       { $users = Get-LocalUser | Select-Object @{n='SamAccountName';e={$_.Name}}, Enabled, @{n='whenCreated';e={$null}} }
  foreach ($u in $users) {
    $n = $u.SamAccountName
    if ($Listed -contains $n)      { Good "$n (enabled=$($u.Enabled))" }
    elseif ($BuiltIn -contains $n) { Note "$n built-in (enabled=$($u.Enabled))" }
    elseif ($n -like '*$')         { continue }
    else                           { Flag "$n is not on the packet's user list (enabled=$($u.Enabled), created $($u.whenCreated))" }
  }

  Hdr 'Privileged group members'
  foreach ($g in (Get-PrivGroups)) {
    foreach ($m in (Get-PrivMembers $g)) {
      if ($m.objectClass -ne 'user') { Note "${g}: group $($m.Name)"; continue }
      if (($Admins + 'Administrator') -contains $m.SamAccountName) { Good "${g}: $($m.SamAccountName)" }
      else { Flag "${g}: $($m.SamAccountName) should not be here" }
    }
  }

  Hdr 'Firewall'
  Get-NetFirewallProfile | ForEach-Object {
    $line = "$($_.Name): enabled=$($_.Enabled) inbound=$($_.DefaultInboundAction) outbound=$($_.DefaultOutboundAction)"
    if (-not $_.Enabled -or $_.DefaultOutboundAction -eq 'Block') { Flag $line } else { Good $line }
  }
  Get-BlockingRules | ForEach-Object { Flag "block rule touching a scored port: '$($_.DisplayName)'" }

  Hdr 'Defender'
  try {
    $p = Get-MpPreference; $s = Get-MpComputerStatus
    if ($s.RealTimeProtectionEnabled) { Good 'real-time protection on' } else { Flag 'real-time protection OFF' }
    foreach ($x in @($p.ExclusionPath) + @($p.ExclusionProcess) + @($p.ExclusionExtension)) { if ($x) { Flag "exclusion: $x" } }
  } catch { Note 'Defender not available' }

  Hdr 'Accessibility-binary hijacks (sticky keys etc.)'
  $hit = $false
  foreach ($b in @('sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe')) {
    $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$b"
    $d = (Get-ItemProperty $k -ErrorAction SilentlyContinue).Debugger
    if ($d) { Flag "$b has a Debugger set: $d"; $hit = $true }
  }
  if (-not $hit) { Good 'none' }

  Hdr 'Scheduled tasks outside \Microsoft\'
  Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } |
    ForEach-Object { Note "$($_.TaskPath)$($_.TaskName) -> $(($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; ')" }

  Hdr 'Run keys'
  foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')) {
    $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
    if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { Note "$($_.Name) = $($_.Value)" } }
  }

  Hdr 'Services running from unusual paths'
  # Defender platform updates legitimately run from ProgramData\Microsoft\Windows Defender.
  Get-CimInstance Win32_Service | Where-Object { $_.PathName -match '\\(Users|Temp|ProgramData|AppData)\\|\\Windows\\Temp\\' -and
                                                 $_.PathName -notmatch '\\ProgramData\\Microsoft\\Windows Defender\\Platform\\' } |
    ForEach-Object { Flag "$($_.Name) -> $($_.PathName)" }

  if ($IsDC) {
    Hdr 'DNS zones'
    try { Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated } | ForEach-Object {
        $l = "$($_.ZoneName) dynamicUpdate=$($_.DynamicUpdate) transfers=$($_.SecureSecondaries)"
        if ($_.DynamicUpdate -eq 'NonsecureAndSecure' -or $_.SecureSecondaries -eq 'TransferAnyServer') { Flag $l } else { Good $l } } } catch { Note 'DnsServer module unavailable' }
  }

  Hdr 'Protected services'
  foreach ($s in $Candidates) {
    $svc = Get-Service $s -ErrorAction SilentlyContinue
    if (-not $svc) { continue }
    if ($svc.Status -eq 'Running') { Good "$s running" }
    elseif ($svc.StartType -eq 'Automatic') { Flag "$s is $($svc.Status) (start type Automatic)" }
    else { Note "$s is $($svc.Status) (start type $($svc.StartType))" }
  }
}

function Get-PrivGroups {
  if ($IsDC) { @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','DnsAdmins','Group Policy Creator Owners') }
  else       { @('Administrators') }
}
function Get-PrivMembers($g) {
  if ($IsDC) { Get-ADGroupMember $g -ErrorAction SilentlyContinue | Select-Object Name, SamAccountName, objectClass }
  else { Get-LocalGroupMember $g -ErrorAction SilentlyContinue | Select-Object Name,
           @{n='SamAccountName';e={($_.Name -split '\\')[-1]}}, @{n='objectClass';e={ if ($_.ObjectClass -eq 'User') {'user'} else {'group'} }} }
}
function Test-PortHit($spec) {
  # $spec is 'Any', '80', or '1000-2000'; true if it covers a scored port.
  foreach ($p in @($spec)) {
    if ("$p" -eq 'Any') { return $true }
    if ("$p" -match '^(\d+)-(\d+)$') {
      $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
      if ($ScoredTcp | Where-Object { $_ -ge $lo -and $_ -le $hi }) { return $true }
    } elseif ("$p" -match '^\d+$' -and $ScoredTcp -contains [int]"$p") { return $true }
  }
  return $false
}
function Get-BlockingRules {
  Get-NetFirewallRule -Enabled True -Direction Inbound -Action Block -ErrorAction SilentlyContinue |
    Where-Object { Test-PortHit ($_ | Get-NetFirewallPortFilter).LocalPort }
}

# ----------------------------------------------------------------- Harden --
function Step-Backup {
  Hdr 'Backup'
  $d = Join-Path $State $Stamp; New-Item -ItemType Directory -Force -Path $d | Out-Null
  netsh advfirewall export (Join-Path $d 'firewall.wfw') | Out-Null
  if (-not (Test-Path (Join-Path $State 'firewall-original.wfw'))) { Copy-Item (Join-Path $d 'firewall.wfw') (Join-Path $State 'firewall-original.wfw') }
  Get-Service | Select-Object Name, Status, StartType | Export-Csv (Join-Path $d 'services.csv') -NoTypeInformation
  Get-Listeners | Export-Csv (Join-Path $d 'listeners.csv') -NoTypeInformation
  if ($IsDC) {
    Get-ADUser -Filter * -Properties * | Select-Object SamAccountName, Enabled, whenCreated, MemberOf | Export-Csv (Join-Path $d 'ad-users.csv') -NoTypeInformation
    try { New-Item -ItemType Directory -Force (Join-Path $d 'gpo') | Out-Null; Backup-GPO -All -Path (Join-Path $d 'gpo') | Out-Null; Good 'GPOs backed up' } catch { Note "GPO backup failed: $_" }
    try { Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' } | ForEach-Object {
          $f = "ccdc-$Stamp-$($_.ZoneName).dns"; Export-DnsServerZone -Name $_.ZoneName -FileName $f
          Copy-Item "$env:windir\System32\dns\$f" $d }
          Good 'DNS zones exported' } catch { Note "DNS export failed: $_" }
  }
  $appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
  if (Test-Path $appcmd) { & $appcmd add backup "ccdc-$Stamp" | Out-Null; Good "IIS config backed up (restore: appcmd restore backup ccdc-$Stamp)" }
  if (Test-Path 'C:\inetpub') { robocopy C:\inetpub (Join-Path $d 'inetpub') /E /R:0 /W:0 /NFL /NDL /NJH /NJS | Out-Null; Good 'C:\inetpub copied' }
  Good "backup: $d"
  # Record which services to protect.
  $prot = @($Candidates | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' })
  [IO.File]::WriteAllLines((Join-Path $State 'protected-services.txt'), [string[]]$prot)
  Note "protected: $((Get-Content (Join-Path $State 'protected-services.txt')) -join ', ')"
}

function Step-Passwords {
  Hdr 'Passwords'
  if (-not (Ask 'Set one new password for all listed users and Administrator?')) { return }
  while ($env:CCDC_PASSWORD) {   # unattended runs: take the password from the environment
    $a = ConvertTo-SecureString $env:CCDC_PASSWORD -AsPlainText -Force; $pa = $env:CCDC_PASSWORD; break
  }
  while (-not $env:CCDC_PASSWORD) {
    $a = Read-Host -AsSecureString '  New password'; $b = Read-Host -AsSecureString '  Again'
    $pa = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($a))
    $pb = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($b))
    if ($pa -ne $pb) { Flag 'did not match'; continue }
    if ($pa.Length -lt 12) { Flag 'use at least 12 characters'; continue }
    break
  }
  $changed = @()
  foreach ($u in ($Listed + 'Administrator')) {
    try {
      if ($IsDC) {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$u'")) { Note "$u does not exist"; continue }
        Set-ADAccountPassword -Identity $u -Reset -NewPassword $a -ErrorAction Stop
      } else {
        if (-not (Get-LocalUser $u -ErrorAction SilentlyContinue)) { Note "$u does not exist"; continue }
        Set-LocalUser -Name $u -Password $a -ErrorAction Stop
      }
      $changed += $u
    } catch { Flag "failed for ${u}: $($_.Exception.Message)" }
  }
  Good "changed: $($changed -join ' ')"
  Write-Host "`n  PCR for Quotient (box $env:COMPUTERNAME):"
  $changed | Where-Object { $_ -ne 'Administrator' } | ForEach-Object { "    $_" }
  '  (all set to the password you just typed)'
}

function Step-Users {
  Hdr 'Unexpected accounts'
  # Accounts that services log on as must stay enabled.
  $svcAccts = Get-CimInstance Win32_Service | ForEach-Object { ($_.StartName -split '\\|@')[-1] } | Where-Object { $_ } | Sort-Object -Unique
  if ($IsDC) { $all = Get-ADUser -Filter 'Enabled -eq $true' | Select-Object -ExpandProperty SamAccountName }
  else { $all = Get-LocalUser | Where-Object Enabled | Select-Object -ExpandProperty Name }
  foreach ($n in $all) {
    if ($Listed -contains $n -or $n -eq 'Administrator') { continue }
    if ($svcAccts -contains $n) { Note "$n is used by a service; left enabled"; continue }
    if ($n -eq 'krbtgt') { continue }
    if (Ask "Disable account '$n'? (kept, not deleted)") {
      if ($IsDC) { Disable-ADAccount $n } else { Disable-LocalUser $n }
      Good "disabled $n (undo: $(if ($IsDC) {'Enable-ADAccount'} else {'Enable-LocalUser'}) $n)"
    }
  }
  foreach ($g in (Get-PrivGroups)) {
    foreach ($m in (Get-PrivMembers $g)) {
      if ($m.objectClass -ne 'user') { continue }   # keep default group nesting
      if (($Admins + 'Administrator') -contains $m.SamAccountName) { continue }
      if (Ask "Remove $($m.SamAccountName) from '$g'?") {
        if ($IsDC) { Remove-ADGroupMember $g -Members $m.SamAccountName -Confirm:$false } else { Remove-LocalGroupMember $g -Member $m.Name }
        Good "removed $($m.SamAccountName) from $g"
      }
    }
  }
}

function Step-Firewall {
  Hdr 'Firewall (inbound only; outbound stays allowed)'
  # Loopback-only listeners are unreachable from outside; do not open them.
  $listen = (Get-Listeners | Where-Object { $_.LocalAddress -notin @('127.0.0.1','::1') }).LocalPort | Where-Object { $_ -lt 49152 }
  $tcp = ($ScoredTcp + $listen) | Sort-Object -Unique
  Note "TCP allowed from anywhere: $($tcp -join ' ')"
  Note "UDP allowed from anywhere: $($ScoredUdp -join ' ')"
  if (-not (Ask 'Disable block rules on scored ports, add allow rules, and turn all profiles on?')) { return }
  Get-BlockingRules | ForEach-Object { Disable-NetFirewallRule -Name $_.Name; Good "disabled block rule '$($_.DisplayName)'" }
  Get-NetFirewallRule -Group 'CCDC' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  New-NetFirewallRule -DisplayName 'CCDC allow TCP' -Group 'CCDC' -Direction Inbound -Protocol TCP -LocalPort $tcp -Action Allow | Out-Null
  New-NetFirewallRule -DisplayName 'CCDC allow UDP' -Group 'CCDC' -Direction Inbound -Protocol UDP -LocalPort $ScoredUdp -Action Allow | Out-Null
  # Keep the built-in AD rules (they cover dynamic RPC for lsass/netlogon).
  foreach ($grp in @('Active Directory Domain Services','DNS Service','Kerberos Key Distribution Center','Core Networking')) {
    Enable-NetFirewallRule -DisplayGroup $grp -ErrorAction SilentlyContinue
  }
  netsh advfirewall set global StatefulFTP enable | Out-Null
  Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
  Good "firewall on. Undo: .\ccdc.ps1 -Mode RestoreFirewall"
}

function Step-Defender {
  Hdr 'Defender'
  try { $p = Get-MpPreference } catch { Note 'Defender not available'; return }
  $ex = @($p.ExclusionPath) + @($p.ExclusionProcess) + @($p.ExclusionExtension) | Where-Object { $_ }
  if (-not (Ask "Turn on real-time protection and remove $($ex.Count) exclusion(s)?")) { return }
  foreach ($x in @($p.ExclusionPath))      { if ($x) { Remove-MpPreference -ExclusionPath $x } }
  foreach ($x in @($p.ExclusionProcess))   { if ($x) { Remove-MpPreference -ExclusionProcess $x } }
  foreach ($x in @($p.ExclusionExtension)) { if ($x) { Remove-MpPreference -ExclusionExtension $x } }
  Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -ErrorAction SilentlyContinue
  Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false
  Good 'real-time protection on, exclusions removed'
}

function Step-Accessibility {
  Hdr 'Accessibility-binary hijacks'
  foreach ($b in @('sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe')) {
    $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$b"
    if ((Get-ItemProperty $k -ErrorAction SilentlyContinue).Debugger) {
      if (Ask "Remove Debugger hijack on ${b}?") { Remove-ItemProperty $k -Name Debugger; Good "removed $b hijack" }
    }
  }
}

function Step-Services {
  Hdr 'Risky services and protocols'
  if ((Get-SmbServerConfiguration).EnableSMB1Protocol) {
    if (Ask 'Disable SMBv1?') { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; Good 'SMBv1 off' }
  } else { Good 'SMBv1 already off' }
  foreach ($s in @('Spooler','RemoteRegistry')) {
    $svc = Get-Service $s -ErrorAction SilentlyContinue
    if ($svc -and $svc.StartType -ne 'Disabled') {
      if (Ask "Stop and disable ${s}?") { Stop-Service $s -Force; Set-Service $s -StartupType Disabled; Good "$s disabled" }
    }
  }
  if ($IsDC) {
    try { Get-DnsServerZone | Where-Object { $_.IsDsIntegrated -and -not $_.IsAutoCreated -and $_.DynamicUpdate -eq 'NonsecureAndSecure' } | ForEach-Object {
        if (Ask "Set zone $($_.ZoneName) to secure-only dynamic updates?") { Set-DnsServerPrimaryZone -Name $_.ZoneName -DynamicUpdate Secure; Good "$($_.ZoneName): secure updates" } } } catch { Note "DNS zone step skipped: $_" }
  }
}

function Step-Logging {
  Hdr 'Logging'
  if (-not (Ask 'Turn on audit policy, command-line and PowerShell script-block logging?')) { return }
  foreach ($c in @('Logon','Logoff','Account Lockout','User Account Management','Security Group Management',
                   'Process Creation','Other Object Access Events','Audit Policy Change','Sensitive Privilege Use',
                   'Security System Extension','Directory Service Changes')) {
    auditpol /set /subcategory:"$c" /success:enable /failure:enable | Out-Null
  }
  $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
  New-Item $k -Force | Out-Null; Set-ItemProperty $k ProcessCreationIncludeCmdLine_Enabled 1
  $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
  New-Item $k -Force | Out-Null; Set-ItemProperty $k EnableScriptBlockLogging 1
  wevtutil sl Security /ms:1073741824 | Out-Null
  Good 'audit + script-block + command-line logging on; Security log 1 GB'
}

function Step-Verify {
  Hdr 'Verify protected services'
  foreach ($s in (Get-Content (Join-Path $State 'protected-services.txt') -ErrorAction SilentlyContinue)) {
    $svc = Get-Service $s -ErrorAction SilentlyContinue
    if ($svc.Status -eq 'Running') { Good "$s running" }
    else { Flag "$s is $($svc.Status), starting"; Start-Service $s -ErrorAction SilentlyContinue
           if ((Get-Service $s).Status -eq 'Running') { Good "$s recovered" } else { Flag "$s still down" } }
  }
}

function Step-Watchdog {
  Hdr 'Service watchdog'
  if (-not (Ask 'Install a scheduled task (SYSTEM, every minute) that restarts protected services?')) { return }
  $dst = Join-Path $State 'ccdc.ps1'; Copy-Item $PSCommandPath $dst -Force
  $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$dst`" -Mode Watch"
  $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3)
  Register-ScheduledTask -TaskName 'CCDC Watchdog' -Action $act -Trigger $trg -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
  Good "watchdog task installed (log: $State\watchdog.log)"
}

function Invoke-Watch {
  $wl = Join-Path $State 'watchdog.log'
  foreach ($s in (Get-Content (Join-Path $State 'protected-services.txt') -ErrorAction SilentlyContinue)) {
    $svc = Get-Service $s -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -eq 'Running') { continue }
    if ($svc.StartType -eq 'Disabled') { Set-Service $s -StartupType Automatic }
    Start-Service $s -ErrorAction SilentlyContinue
    $r = if ((Get-Service $s).Status -eq 'Running') { 'recovered' } else { 'STILL DOWN' }
    Add-Content $wl "$(Get-Date -Format s) $s was down -> $r"
  }
  if (Get-Module -ListAvailable WebAdministration) {
    Import-Module WebAdministration
    Get-ChildItem IIS:\AppPools | Where-Object { $_.State -ne 'Started' } | ForEach-Object { Start-WebAppPool $_.Name; Add-Content $wl "$(Get-Date -Format s) app pool $($_.Name) started" }
    Get-Website | Where-Object { $_.State -ne 'Started' } | ForEach-Object { Start-Website $_.Name; Add-Content $wl "$(Get-Date -Format s) site $($_.Name) started" }
  }
}

# ------------------------------------------------------------------- Hunt --
function Test-MsSigned($path) {
  # true if the file has a valid signature from Microsoft (embedded or catalog)
  $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
  return ($sig -and $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation')
}
function Get-ExePath($cmdline) {
  # "C:\x\y.exe" -k foo  /  C:\x\y.exe -k foo  ->  C:\x\y.exe
  if (-not $cmdline) { return $null }
  $c = [Environment]::ExpandEnvironmentVariables($cmdline.Trim())
  $c = $c -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', "$env:windir\" -replace '^System32\\', "$env:windir\System32\"
  if ($c -match '^"([^"]+)"') { return $Matches[1] }
  if ($c -match '^(.+?\.(exe|dll|sys))(\s|$)') { return $Matches[1] }
  return ($c -split ' ')[0]
}

function Invoke-Hunt {
  $since = (Get-Date).AddHours(-$Hours)

  Hdr 'Critical system binaries (must be Microsoft-signed)'
  $sys = "$env:windir\System32"
  $crit = @('sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe','cmd.exe',
            'WindowsPowerShell\v1.0\powershell.exe','lsass.exe','winlogon.exe','svchost.exe','services.exe',
            'net.exe','net1.exe','sc.exe','schtasks.exe','taskmgr.exe','explorer.exe','userinit.exe','logonui.exe',
            'whoami.exe','netstat.exe','tasklist.exe','wevtutil.exe','reg.exe')
  foreach ($b in $crit) {
    $f = if ($b -eq 'explorer.exe') { "$env:windir\explorer.exe" } else { Join-Path $sys $b }
    if (-not (Test-Path $f)) { continue }
    if (Test-MsSigned $f) { continue }
    Flag "$f is NOT validly Microsoft-signed ($((Get-AuthenticodeSignature $f).Status))"
  }
  # Sticky-keys trick: an accessibility tool that is really a copy of cmd.exe or powershell.exe
  $shells = @((Get-FileHash "$sys\cmd.exe").Hash, (Get-FileHash "$sys\WindowsPowerShell\v1.0\powershell.exe").Hash)
  foreach ($b in @('sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe')) {
    $f = Join-Path $sys $b
    if ((Test-Path $f) -and ($shells -contains (Get-FileHash $f).Hash)) { Flag "$b is a copy of cmd/powershell (sticky-keys backdoor). Fix: sfc /scanfile=$f" }
  }
  Good "checked $($crit.Count) binaries (lines above are problems)"

  Hdr 'Service binaries not signed by Microsoft (review each)'
  Get-CimInstance Win32_Service | ForEach-Object {
    $exe = Get-ExePath $_.PathName
    if (-not $exe -or -not (Test-Path $exe)) { if ($_.PathName) { Flag "$($_.Name): binary missing or unparsable: $($_.PathName)" }; return }
    $sig = Get-AuthenticodeSignature $exe -ErrorAction SilentlyContinue
    if ($sig.Status -ne 'Valid') { Flag "$($_.Name) [$($_.State)] unsigned/invalid: $exe" }
    elseif ($sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { Note "$($_.Name): signed by $(($sig.SignerCertificate.Subject -split ',')[0]) -> $exe" }
  }

  Hdr 'LSA packages and Winlogon (credential-theft and logon hooks)'
  $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  foreach ($k in @('Authentication Packages','Notification Packages','Security Packages')) {
    foreach ($pkg in @($lsa.$k)) {
      if (-not $pkg -or $pkg -eq '""') { continue }
      $f = Join-Path $sys "$pkg.dll"
      if (-not (Test-Path $f)) { Flag "$k '$pkg': $f not found" }
      elseif (-not (Test-MsSigned $f)) { Flag "$k '$pkg' is not Microsoft-signed: $f" }
    }
  }
  $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  if ($wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') { Flag "Winlogon Userinit = $($wl.Userinit)" } else { Good 'Winlogon Userinit default' }
  if ($wl.Shell -ne 'explorer.exe') { Flag "Winlogon Shell = $($wl.Shell)" } else { Good 'Winlogon Shell default' }

  Hdr 'PowerShell history (all users)'
  $sus = 'Invoke-WebRequest|iwr |wget |curl |DownloadString|DownloadFile|IEX|Invoke-Expression|-enc|EncodedCommand|FromBase64String|net user .* /add|net localgroup administrators|Add-LocalGroupMember|New-LocalUser|New-ADUser|Add-ADGroupMember|Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|netsh advfirewall|New-NetFirewallRule|Set-NetFirewallProfile|schtasks|Register-ScheduledTask|New-Service|sc\.exe (create|config)|reg add|wevtutil cl|Clear-EventLog|Remove-Item .*history|mimikatz|sekurlsa|procdump|ntdsutil|vssadmin|Stop-Service|Set-Service .*Disabled'
  $any = $false
  foreach ($h in (Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -ErrorAction SilentlyContinue)) {
    $any = $true
    $u = ($h.FullName -split '\\')[2]
    $lines = Get-Content $h.FullName
    Write-Host "  -- $u ($($lines.Count) lines, modified $($h.LastWriteTime))"
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match $sus) { Flag "${u}:$($i+1): $($lines[$i])" } }
  }
  if (-not $any) { Note 'no PSReadLine history files found' }

  Hdr "Event logs (last $Hours h)"
  function Ev($ids, $log = 'Security') { Get-WinEvent -FilterHashtable @{LogName=$log; Id=$ids; StartTime=$since} -ErrorAction SilentlyContinue }
  function Field($e, $name) { ([xml]$e.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq $name } | Select-Object -ExpandProperty '#text' }

  $cleared = @(Ev @(1102)) + @(Ev @(104) 'System')
  foreach ($e in $cleared) { Flag "$($e.TimeCreated) event log CLEARED (id $($e.Id))" }
  $oldest = Get-WinEvent -LogName Security -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue
  if ($oldest) { Note "oldest Security event: $($oldest.TimeCreated) (very recent = log was wiped)" }

  Write-Host '  -- failed logons by account and source (top 15)'
  $fails = Ev @(4625)
  $fails | ForEach-Object { '{0} from {1}' -f (Field $_ 'TargetUserName'), (Field $_ 'IpAddress') } |
    Group-Object | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object { '    {0,5}  {1}' -f $_.Count, $_.Name }

  Write-Host '  -- network/RDP logons (type 3, 10), by account and source'
  $ok = Ev @(4624) | Where-Object { @('3','10') -contains (Field $_ 'LogonType') }
  $ok | Where-Object { (Field $_ 'TargetUserName') -notmatch '\$$|^ANONYMOUS' } |
    ForEach-Object { '{0} from {1} (type {2})' -f (Field $_ 'TargetUserName'), (Field $_ 'IpAddress'), (Field $_ 'LogonType') } |
    Group-Object | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object { '    {0,5}  {1}' -f $_.Count, $_.Name }

  # Brute force that worked: 5+ failures then a success from the same source
  $bad = $fails | Group-Object { Field $_ 'IpAddress' } | Where-Object { $_.Count -ge 5 -and $_.Name -notin @('-','','127.0.0.1','::1') }
  foreach ($g in $bad) {
    $hit = $ok | Where-Object { (Field $_ 'IpAddress') -eq $g.Name } | Select-Object -First 1
    if ($hit) { Flag "$($g.Name): $($g.Count) failed logons, then success as $(Field $hit 'TargetUserName') at $($hit.TimeCreated)" }
  }

  foreach ($e in (Ev @(4720))) { Flag "$($e.TimeCreated) account created: $(Field $e 'TargetUserName') by $(Field $e 'SubjectUserName')" }
  foreach ($e in (Ev @(4728,4732,4756))) {
    $grp = Field $e 'TargetUserName'
    if ($grp -eq 'None') { continue }   # every new local user joins "None"
    $m = Field $e 'MemberName'
    if (-not $m -or $m -eq '-') {        # local groups record only the SID
      $sid = Field $e 'MemberSid'
      try { $m = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { $m = $sid }
    }
    Flag "$($e.TimeCreated) added to group ${grp}: $m by $(Field $e 'SubjectUserName')"
  }
  foreach ($e in (Ev @(4724))) { Note "$($e.TimeCreated) password reset: $(Field $e 'TargetUserName') by $(Field $e 'SubjectUserName')" }
  foreach ($e in (Ev @(4698))) { Flag "$($e.TimeCreated) scheduled task created: $(Field $e 'TaskName') by $(Field $e 'SubjectUserName')" }
  foreach ($e in (Ev @(7045) 'System')) { Flag "$($e.TimeCreated) service installed: $($e.Properties[0].Value) -> $($e.Properties[1].Value)" }
  foreach ($e in (Ev @(4946,4947,4948) )) { Note "$($e.TimeCreated) firewall rule change (id $($e.Id)): $(Field $e 'RuleName')" }

  Write-Host '  -- suspicious process command lines (needs 4688 with command line; the harden Logging step enables it)'
  Ev @(4688) | ForEach-Object { Field $_ 'CommandLine' } | Where-Object { $_ -match $sus } | Select-Object -First 25 -Unique | ForEach-Object { Flag "cmdline: $_" }
  Write-Host '  -- suspicious PowerShell script blocks (4104)'
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$since} -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[2].Value -match $sus -and $_.Properties[2].Value -notmatch 'function Invoke-Hunt|Step-Watchdog|ccdc\.ps1' } | Select-Object -First 15 |
    ForEach-Object { Flag "$($_.TimeCreated) scriptblock: $(($_.Properties[2].Value -replace '\s+',' ').Substring(0, [Math]::Min(160, ($_.Properties[2].Value -replace '\s+',' ').Length)))" }

  Hdr 'Files changed recently in sensitive places'
  foreach ($d in @("$env:windir\System32", "$env:windir\SysWOW64", 'C:\inetpub', 'C:\ProgramData', 'C:\Users\Public', "$env:windir\Temp", "$env:windir\System32\Tasks")) {
    if (-not (Test-Path $d)) { continue }
    $recurse = $d -notmatch 'System32$|SysWOW64$'
    Get-ChildItem $d -File -Recurse:$recurse -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTime -gt $since -and $_.Extension -match '\.(exe|dll|ps1|bat|cmd|vbs|js|hta|aspx?|php|jsp|xml)$' } |
      Select-Object -First 25 | ForEach-Object { Note "$($_.LastWriteTime)  $($_.FullName)" }
  }

  Hdr 'Summary'
  Write-Host "  Screenshot the evidence before removing anything (for incident reports). Log: $Log"
}

# ------------------------------------------------------------------- Main --
switch ($Mode) {
  'Audit'  { Invoke-Audit; Write-Host "`n  Audit only. Nothing was changed. Log: $Log" }
  'Harden' {
    if ($Yes) { Note 'Auto mode: safe steps run without prompts.' } else { Note 'Confirm mode: you approve each step.' }
    Step-Backup; Step-Passwords; Step-Users; Step-Firewall; Step-Defender
    Step-Accessibility; Step-Services; Step-Logging; Step-Verify; Step-Watchdog
    Hdr 'Done'
    Write-Host "  Log: $Log"
    Write-Host '  Next: run .\ccdc.ps1 (audit) and review every [!!] line. Submit the PCR list in Quotient.'
  }
  'Hunt'   { Invoke-Hunt }
  'Watch'  { Invoke-Watch }
  'RestoreFirewall' {
    $f = Join-Path $State 'firewall-original.wfw'
    if (Test-Path $f) { netsh advfirewall import $f | Out-Null; Good "firewall restored from $f" } else { Flag "no $f" }
  }
}
if ($Mode -ne 'Watch') { Stop-Transcript | Out-Null }

# Upload after the transcript is closed so the whole log is included.
if ($Share -and $Mode -in @('Audit','Harden','Hunt')) {
  $sp = Join-Path $PSScriptRoot 'share.ps1'
  if (Test-Path $sp) { & $sp $Log }
  else { Write-Host "  share.ps1 not found next to ccdc.ps1. Download it, then run: .\share.ps1 $Log" -ForegroundColor Yellow }
}
