<#
share.ps1 - upload files (reports, logs, configs) to a paste service.

  .\share.ps1 C:\ccdc-backup\ccdc-*.log            files
  .\share.ps1 C:\inetpub\wwwroot                   a folder (its text files, up to 1 MB each)
  Get-Service | Out-String | .\share.ps1            pipeline input
  .\share.ps1 -One C:\inetpub\wwwroot\web.config C:\ccdc-backup\watchdog.log   one readable paste, no index

Each file is its own paste, split into parts of at most 60 KB (paste.rs refuses bigger
bodies). When there is more than one paste, a final INDEX paste lists every file with
its size, SHA-256 and part links in order. Rebuild everything on the laptop with:
  ./fetch.sh <index-link>        (tools/fetch.sh; same format as share.sh)

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
  $Chunk = 60000      # paste.rs rejects bodies over about 64 KB (HTTP 500/503)
  $DirMax = 1MB       # folder uploads skip bigger files (name a file to include it)
  $Utf8 = New-Object Text.UTF8Encoding($false)

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
    # Only "=" or ":" mark a value (plus VyOS "*-password '...'"), so log lines
    # like "Failed password for root from ..." stay intact.
    $t = $t -replace '(?i)((?:plaintext|encrypted)-password +)[''"]?[^''"\s]+[''"]?', '$1''<redacted>'''
    $t = $t -replace '(?i)(password|passwd|secret|pwd|pass)(["''\s]*[=:]["''\s]*)[^"''\s,;<]+', '$1$2<redacted>'
    return $t
  }
  function Get-BodyBytes([string]$text) {
    # UTF-8 without BOM, ending with a newline, so parts reassemble byte-exactly.
    if ($text.Length -gt 0 -and -not $text.EndsWith("`n")) { $text += "`n" }
    return ,$Utf8.GetBytes($text)
  }
  function Get-Sha([byte[]]$b) {
    $h = [Security.Cryptography.SHA256]::Create()
    return (-join ($h.ComputeHash($b) | ForEach-Object { $_.ToString('x2') }))
  }
  function Send-Bytes([byte[]]$b) {
    # One paste; retries with backoff. Returns the URL or $null.
    for ($try = 1; $try -le 3; $try++) {
      try {
        $r = Invoke-RestMethod -Uri $Url -Method Post -Body $b -ContentType 'text/plain; charset=utf-8' -TimeoutSec 30
        $u = "$r".Trim(); if ($u -match '^https?://') { return $u }
      } catch { $err = $_.Exception.Message }
      if ($try -lt 3) { Start-Sleep -Seconds ($try * 2) }
    }
    Write-Warning "upload failed: $err"; return $null
  }
  function Send-Parts([byte[]]$b) {
    # Split at line boundaries into parts of at most $Chunk bytes (cut a very long
    # line by bytes). Returns the part URLs in order, or $null on any failure.
    $urls = @(); $pos = 0
    while ($pos -lt $b.Length) {
      $len = [Math]::Min($Chunk, $b.Length - $pos)
      if ($pos + $len -lt $b.Length) {
        $nl = [Array]::LastIndexOf($b, [byte]10, $pos + $len - 1, $len)
        if ($nl -ge $pos) { $len = $nl - $pos + 1 }
      }
      $part = New-Object byte[] $len; [Array]::Copy($b, $pos, $part, 0, $len)
      $u = Send-Bytes $part; if (-not $u) { return $null }
      $urls += $u; $pos += $len
      if ($pos -lt $b.Length) { Start-Sleep -Milliseconds 300 }
    }
    return ,$urls
  }
  function Get-Body($f) {
    if (Test-Refused $f) { Write-Warning "refused (secret material; use -Raw to override): $f"; return $null }
    if (-not (Test-Text $f)) { Write-Warning "skip (binary): $f"; return $null }
    $t = Get-Content $f -Raw
    if ($null -eq $t) { $t = '' }
    return (Get-Redacted $t)
  }
  function Get-Label($f) {
    # C:\inetpub\x.config -> /C/inetpub/x.config (fetch.sh rebuilds it as a folder tree)
    if ($f -eq 'stdin.txt') { return $f }
    return '/' + (($f -replace '^([A-Za-z]):', '$1' -replace '\\', '/').TrimStart('/'))
  }
}
process { if ($InputText) { $piped.Add($InputText) } }
end {
  $host_ = $env:COMPUTERNAME; if (-not $host_) { $host_ = 'windows' }
  $items = New-Object System.Collections.Generic.List[object]   # @{label; text}
  if ($piped.Count -gt 0 -and -not $Path) {
    $items.Add(@{ label = 'stdin.txt'; text = (Get-Redacted ($piped -join "`n")) })
  } elseif (-not $Path) { Get-Help $PSCommandPath; return }
  foreach ($p in $Path) {
    $found = Get-Item $p -ErrorAction SilentlyContinue
    if (-not $found) { Write-Warning "skip (not found): $p"; continue }
    foreach ($item in $found) {
      $list = if ($item.PSIsContainer) {
        Get-ChildItem $item.FullName -File -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName | ForEach-Object {
          if ($_.Length -gt $DirMax) { Write-Warning "skip (over 1 MB; name it to include it): $($_.FullName)" } else { $_.FullName } }
      } else { $item.FullName }
      foreach ($f in $list) { $t = Get-Body $f; if ($null -ne $t) { $items.Add(@{ label = $f; text = $t }) } }
    }
  }
  if ($items.Count -eq 0) { Write-Warning 'nothing to upload'; return }

  if ($One) {
    # One readable paste with a header per file (split into parts if large, no index).
    $sb = New-Object Text.StringBuilder
    foreach ($i in $items) { [void]$sb.Append("===== ${host_}:$($i.label) =====`n$($i.text)`n`n") }
    $urls = Send-Parts (Get-BodyBytes $sb.ToString()); if (-not $urls) { exit 1 }
    if ($urls.Count -eq 1) { $urls[0] } else { for ($k = 0; $k -lt $urls.Count; $k++) { "$($urls[$k]) (part $($k+1)/$($urls.Count))" } }
    return
  }

  # Default: one paste (or parts) per file, then an index paste if there is more than one.
  $lines = New-Object System.Collections.Generic.List[string]; $posts = 0; $failed = $false; $first = $null
  foreach ($i in $items) {
    $b = Get-BodyBytes $i.text; $label = Get-Label $i.label
    if ($b.Length -eq 0) { $urls = @() }
    else { $urls = Send-Parts $b; if (-not $urls) { Write-Warning "FAILED: $($i.label)"; $failed = $true; continue } }
    $posts += $urls.Count; if (-not $first) { $first = $urls }
    Write-Host "  $($i.label)  ($($b.Length) bytes, $($urls.Count) part(s))"
    $joined = if ($urls.Count) { $urls -join ' ' } else { '-' }
    $lines.Add("$label`t$($b.Length)`t$(Get-Sha $b)`t$joined")
  }
  if ($lines.Count -eq 0) { Write-Warning 'nothing uploaded'; exit 1 }
  if ($lines.Count -eq 1 -and $posts -le 1) { if ($first) { $first[0] }; if ($failed) { exit 1 }; return }

  $index = "# ccdc-share index v1`n# host=$host_ created=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) files=$($lines.Count) pastes=$posts`n" +
           "# rebuild with: fetch.sh <this-link>`n# file<TAB>bytes<TAB>sha256<TAB>part links in order`n" + ($lines -join "`n") + "`n"
  $iurls = Send-Parts ($Utf8.GetBytes($index)); if (-not $iurls) { Write-Warning 'index upload failed'; exit 1 }
  "INDEX: $($iurls -join ' ')"
  "rebuild on the laptop: ./fetch.sh $($iurls -join ' ')"
  if ($failed) { exit 1 }
}
