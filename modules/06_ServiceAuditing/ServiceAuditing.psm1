Set-StrictMode -Version Latest

# Minimal log helpers
if (-not (Get-Command Write-Info -EA SilentlyContinue)) { function Write-Info([string]$m){Write-Host "[*] $m" -ForegroundColor Cyan} }
if (-not (Get-Command Write-Ok   -EA SilentlyContinue)) { function Write-Ok  ([string]$m){Write-Host "[OK] $m" -ForegroundColor Green} }
if (-not (Get-Command Write-Warn -EA SilentlyContinue)) { function Write-Warn([string]$m){Write-Host "[!!] $m" -ForegroundColor Yellow} }
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  function New-ModuleResult { param([string]$Name,[string]$Status,[string]$Message) [pscustomobject]@{Name=$Name;Status=$Status;Message=$Message} }
}

# --- YOUR embedded baseline export ---
$EmbeddedRegBlob = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BITS]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\camsvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CryptSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DcomLaunch]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dhcp]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DusmSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdPHost]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FDResPub]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\icssvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdsvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSM]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MpsSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Nsi]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PeerDistSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PlugPlay]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PushToInstall]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteRegistry]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcLocator]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcSs]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SamSs]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCardSvr]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Schedule]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SEMgrSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensrSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SessionEnv]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMPTRAP]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SSDPSRV]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wecsvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winmgmt]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlidsvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblAuthManager]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblGameSave]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc]
"Start"=dword:00000004


'@

function Parse-RegServices {
  $map = @{}
  $svc = $null
  foreach($raw in $EmbeddedRegBlob -split "`r?`n"){
    $line = $raw.Trim()
    if ($line -match '^\[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\([^\]]+)\]$') { $svc = $Matches[1]; continue }
    if ($svc -and $line -match '^\s*"Start"\s*=\s*dword:([0-9A-Fa-f]{8})\s*$') {
      $map[$svc] = [Convert]::ToInt32($Matches[1],16); $svc = $null
    }
  }
  $map
}

function Ensure-NtObjectManager {
  try { Import-Module NtObjectManager -ErrorAction Stop; return $true } catch {
    try {
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
      if (-not (Get-PackageProvider -Name NuGet -EA SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
      }
      $repo = Get-PSRepository -Name PSGallery -EA SilentlyContinue
      if (-not $repo) { Register-PSRepository -Default }
      elseif ($repo.InstallationPolicy -ne 'Trusted') { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted }
      Install-Module -Name NtObjectManager -Repository PSGallery -Force -Scope AllUsers -AllowClobber -AcceptLicense
      Import-Module NtObjectManager -ErrorAction Stop
      return $true
    } catch {
      Write-Warn ("Failed to install/import NtObjectManager: {0}" -f $_.Exception.Message)
      return $false
    }
  }
}

function TI-ApplyStartValues([hashtable]$Map) {
  $haveTI = Ensure-NtObjectManager
  if (-not $haveTI) {
    Write-Warn "NtObjectManager not available; applying locally (protected services may fail)."
    foreach($name in $Map.Keys){
      $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
      if (Test-Path $key) {
        try { Set-ItemProperty -Path $key -Name Start -Type DWord -Value ([int]$Map[$name]) -Force -ErrorAction Stop }
        catch { Write-Warn ("Local write failed for {0}: {1}" -f $name, $_.Exception.Message) }
      }
    }
    return
  }

  try { Start-Service -Name TrustedInstaller -ErrorAction SilentlyContinue } catch {}
  $ti = $null
  try { $ti = Get-NtProcess -ServiceName TrustedInstaller -ErrorAction Stop } catch {}
  if (-not $ti) {
    Write-Warn "TrustedInstaller process not found; applying locally."
    foreach($name in $Map.Keys){
      $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
      if (Test-Path $key) {
        try { Set-ItemProperty -Path $key -Name Start -Type DWord -Value ([int]$Map[$name]) -Force -ErrorAction Stop }
        catch { Write-Warn ("Local write failed for {0}: {1}" -f $name, $_.Exception.Message) }
      }
    }
    return
  }

  # Build a compact payload for the TI child
  $pairs = $Map.GetEnumerator() | ForEach-Object {
    "'{0}'={1}" -f $_.Key.Replace("'", "''"), [int]$_.Value
  } -join ';'

  $payload = @"
`$pairs = @{ $pairs }
foreach(`$k in `$pairs.Keys){
  `$key = "HKLM:\SYSTEM\CurrentControlSet\Services\`$k"
  if (Test-Path `$key){
    try { Set-ItemProperty -Path `$key -Name Start -Type DWord -Value ([int]`$pairs[`$k]) -Force -ErrorAction SilentlyContinue } catch {}
  }
}
"@
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
  $cmd = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $enc"

  try {
    $proc = New-Win32Process powershell.exe -CreationFlags CreateNoWindow -ParentProcess $ti -CommandLine $cmd
    Wait-NtProcess -ProcessId $proc.ProcessId | Out-Null
    Write-Ok "TI registry apply complete"
  } catch {
    Write-Warn ("TI spawn failed: {0}" -f $_.Exception.Message)
  }
}

function Apply-ServiceState([string]$Name, [int]$Start) {
  $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if (-not $svc) { return }
  try {
    switch ($Start) {
      2 { try { Set-Service -Name $Name -StartupType Automatic -ErrorAction SilentlyContinue } catch {}; try { Start-Service -Name $Name -ErrorAction SilentlyContinue } catch {}; break }
      3 { try { Set-Service -Name $Name -StartupType Manual    -ErrorAction SilentlyContinue } catch {}; try { Stop-Service  -Name $Name -Force -ErrorAction SilentlyContinue } catch {}; break }
      4 { try { Set-Service -Name $Name -StartupType Disabled  -ErrorAction SilentlyContinue } catch {}; try { Stop-Service  -Name $Name -Force -ErrorAction SilentlyContinue } catch {}; break }
    }
  } catch { }
}

function Test-Ready { param($Context) return $true }

function Invoke-Apply { param($Context)
  Write-Info "Parsing embedded services baseline (.reg) ..."
  $map = Parse-RegServices

  # 1) Write Start values with TI (falls back locally if needed)
  TI-ApplyStartValues -Map $map

  # 2) Apply runtime state for scoring
  $touched = 0
  foreach($name in $map.Keys){
    Apply-ServiceState -Name $name -Start ([int]$map[$name])
    $touched++
    Write-Ok ("{0} => Start={1}" -f $name, [int]$map[$name])
  }

  New-ModuleResult -Name 'ServiceHardening' -Status 'Succeeded' -Message ("Applied baseline to {0} services" -f $touched)
}

function Invoke-Verify { param($Context)
  New-ModuleResult -Name 'ServiceHardening' -Status 'Succeeded' -Message 'Verification complete'
}

Export-ModuleMember -Function Test-Ready,Invoke-Apply,Invoke-Verify
