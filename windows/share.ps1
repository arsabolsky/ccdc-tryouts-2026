<#
share.ps1 - upload files (reports, logs, configs) to a paste service and print the URL.

  .\share.ps1 C:\ccdc-backup\ccdc-*.log            one paste per file
  .\share.ps1 -One C:\inetpub\wwwroot\web.config C:\ccdc-backup\watchdog.log
  .\share.ps1 C:\inetpub\wwwroot                   a folder: its text files, one paste
  Get-Service | Out-String | .\share.ps1            pipeline input

Pastes are PUBLIC to anyone with the link. By default private keys and hive/secret
files are refused and password values and hashes are blanked; -Raw turns that off.
Service: paste.rs (no account). -Url overrides the endpoint (used for testing).
#>
param(
  [Parameter(Position=0, ValueFromRemainingArguments=$true)][string[]]$Path,
  [Parameter(ValueFromPipeline=$true)][string]$InputText,
  [switch]$One,
  [switch]$Raw,
  [string]$Url = 'https://paste.rs/'
)
begin {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $piped = New-Object System.Collections.Generic.List[string]

  function Test-Refused($f) {
    if ($Raw) { return $false }
    $n = [IO.Path]::GetFileName($f)
    if ($n -match '^(SAM|SECURITY|SYSTEM|NTDS\.dit|shadow-?|gshadow-?)$' -or $n -match '\.(key|pem|pfx|p12)$' -or $n -match '^id_(rsa|ecdsa|ed25519|dsa)$') { return $true }
    return [bool](Select-String -Path $f -Pattern '-----BEGIN [A-Z ]*PRIVATE KEY-----' -Quiet -ErrorAction SilentlyContinue)
  }
  function Test-Text($f) {
    $b = [IO.File]::ReadAllBytes($f)
    if ($b.Length -eq 0) { return $true }
    $n = [Math]::Min($b.Length, 4096)
    # UTF-16 text (PowerShell transcripts) has zero bytes but a BOM
    if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { return $true }
    for ($i = 0; $i -lt $n; $i++) { if ($b[$i] -eq 0) { return $false } }
    return $true
  }
  function Get-Redacted([string]$t) {
    if ($Raw) { return $t }
    $t = $t -replace '\$(1|2[abxy]?|5|6|7|y|gy)\$[^:\s]+', '<hash-redacted>'
    $t = $t -replace '(?i)((?:plaintext-|encrypted-)?password|passwd|secret|pwd|pass)(["''\s]*[=:\s]["''\s]*)[^"''\s,;<]+', '$1$2<redacted>'
    return $t
  }
  function Send-Paste([string]$text) {
    if (-not $text.Trim()) { Write-Warning 'nothing to upload'; return }
    try {
      $r = Invoke-RestMethod -Uri $Url -Method Post -Body ([Text.Encoding]::UTF8.GetBytes($text)) -ContentType 'text/plain; charset=utf-8' -TimeoutSec 30
      "$r".Trim()
    } catch { Write-Warning "upload failed: $($_.Exception.Message)" }
  }
  function Get-Body($f) {
    if (Test-Refused $f) { Write-Warning "refused (secret material; use -Raw to override): $f"; return $null }
    if (-not (Test-Text $f)) { Write-Warning "skip (binary): $f"; return $null }
    return (Get-Redacted (Get-Content $f -Raw))
  }
}
process { if ($InputText) { $piped.Add($InputText) } }
end {
  if ($piped.Count -gt 0 -and -not $Path) { Send-Paste (Get-Redacted ($piped -join "`n")); return }
  if (-not $Path) { Get-Help $PSCommandPath; return }
  $files = @(); $combine = [bool]$One
  foreach ($p in $Path) {
    foreach ($item in (Get-Item $p -ErrorAction SilentlyContinue)) {
      if ($item.PSIsContainer) {
        $combine = $true
        $files += Get-ChildItem $item.FullName -File -Recurse -ErrorAction SilentlyContinue | Where-Object Length -lt 2MB | Select-Object -ExpandProperty FullName
      } else { $files += $item.FullName }
    }
  }
  if (-not $files) { Write-Warning 'no files found'; return }
  if ($combine) {
    $sb = New-Object Text.StringBuilder
    foreach ($f in $files) { $b = Get-Body $f; if ($null -ne $b) { [void]$sb.Append("===== ${env:COMPUTERNAME}:$f =====`n$b`n`n") } }
    Send-Paste $sb.ToString()
  } else {
    foreach ($f in $files) { $b = Get-Body $f; if ($null -ne $b) { $u = Send-Paste $b; if ($u) { "$u  $f" } } }
  }
}
