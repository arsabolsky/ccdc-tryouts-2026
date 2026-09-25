<#
ccdc.ps1 - audit and harden Windows Server 2016 (domain controller or member).

  .\ccdc.ps1                      read-only audit (default)
  .\ccdc.ps1 -Mode Harden         asks before every step
  .\ccdc.ps1 -Mode Harden -Yes    runs the safe steps without asking
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
  [ValidateSet('Audit','Harden','Watch','RestoreFirewall')][string]$Mode = 'Audit',
  [switch]$Yes
)
$ErrorActionPreference = 'Continue'

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
  Get-CimInstance Win32_Service | Where-Object { $_.PathName -match '\\(Users|Temp|ProgramData|AppData)\\|\\Windows\\Temp\\' } |
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
    if ($svc) { if ($svc.Status -eq 'Running') { Good "$s running" } else { Flag "$s is $($svc.Status)" } }
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
  $Candidates | Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' } |
    Set-Content (Join-Path $State 'protected-services.txt')
  Note "protected: $((Get-Content (Join-Path $State 'protected-services.txt')) -join ', ')"
}

function Step-Passwords {
  Hdr 'Passwords'
  if (-not (Ask 'Set one new password for all listed users and Administrator?')) { return }
  while ($true) {
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
  $listen = (Get-Listeners).LocalPort | Where-Object { $_ -lt 49152 }
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
      if (Ask "Remove Debugger hijack on $b?") { Remove-ItemProperty $k -Name Debugger; Good "removed $b hijack" }
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
      if (Ask "Stop and disable $s?") { Stop-Service $s -Force; Set-Service $s -StartupType Disabled; Good "$s disabled" }
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
  'Watch'  { Invoke-Watch }
  'RestoreFirewall' {
    $f = Join-Path $State 'firewall-original.wfw'
    if (Test-Path $f) { netsh advfirewall import $f | Out-Null; Good "firewall restored from $f" } else { Flag "no $f" }
  }
}
if ($Mode -ne 'Watch') { Stop-Transcript | Out-Null }
