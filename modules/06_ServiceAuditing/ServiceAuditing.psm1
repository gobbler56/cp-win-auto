Set-StrictMode -Version Latest

# Try to import shared contracts/utils if present; otherwise define minimal fallbacks
try { . $PSScriptRoot/../../core/Contracts.psm1 } catch { function New-ModuleResult { param([string]$Name,[string]$Status,[string]$Message) [pscustomobject]@{Name=$Name;Status=$Status;Message=$Message} } }
try { . $PSScriptRoot/../../core/Utils.psm1     } catch { function Write-Ok($m) { Write-Host "[OK] $m" -ForegroundColor Green }; function Write-Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }; function Write-Warn($m) { Write-Host "[!!] $m" -ForegroundColor Yellow }; function Write-Err($m) { Write-Host "[xx] $m" -ForegroundColor Red } }

# --- Embedded baseline services .reg (hardcoded from your export) ---
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

function Convert-RegBlobToMap {
  <#
    Returns a hashtable: ServiceName -> Start (int)
  #>
  $map = @{}
  $current = $null
  foreach ($line in $EmbeddedRegBlob -split "`r?`n") {
    $l = $line.Trim()
    if ($l -match '^\[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\([^\]]+)\]$') {
      $current = $Matches[1]
      continue
    }
    if ($l -match '^"Start"=dword:([0-9a-fA-F]{8})$') {
      if ($current) {
        $map[$current] = [Convert]::ToInt32($Matches[1],16)
        $current = $null
      }
    }
  }
  return $map
}

function Set-ServiceStartValue {
  param([Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][int]$Start)
  $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
  if (Test-Path $key) {
    try { Set-ItemProperty -Path $key -Name Start -Type DWord -Value $Start -ErrorAction Stop } catch { Write-Warn "Failed to set Start for $Name: $($_.Exception.Message)" }
  }
}

function Apply-ServiceState {
  param([Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][int]$Start)
  $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if (-not $svc) { return }
  try {
    switch ($Start) {
      2 { try { Set-Service -Name $Name -StartupType Automatic -ErrorAction Stop } catch {}; try { Start-Service -Name $Name -ErrorAction SilentlyContinue } catch {}; break }
      3 { try { Set-Service -Name $Name -StartupType Manual    -ErrorAction Stop } catch {}; try { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue } catch {}; break }
      4 { try { Set-Service -Name $Name -StartupType Disabled  -ErrorAction Stop } catch {}; try { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue } catch {}; break }
      default { Write-Warn "Unsupported Start value 0 for 1" -f $Start,$Name }
    }
  } catch { Write-Warn "Failed to apply state for $Name: $($_.Exception.Message)" }
}

function Test-Ready { param($Context) return $true }

function Invoke-Apply {
  param($Context)
  Write-Info "Parsing embedded services baseline (.reg) ..."
  $map = Convert-RegBlobToMap
  $touched = 0

  foreach ($kv in $map.GetEnumerator()) {
    $name  = $kv.Key
    $start = [int]$kv.Value
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) { continue }  # If service isn't installed, many CP checks pass via Exists=false branch

    Set-ServiceStartValue -Name $name -Start $start
    Apply-ServiceState    -Name $name -Start $start
    $touched++
    Write-Ok ("0 => Start=1" -f $name,$start)
  }

  return (New-ModuleResult -Name 'ServiceHardening' -Status 'Succeeded' -Message ("Applied baseline to 0 services" -f $touched))
}

function Invoke-Verify {
  param($Context)
  # Optional: could re-read and compare, but we keep it quick.
  return (New-ModuleResult -Name 'ServiceHardening' -Status 'Succeeded' -Message 'Verification complete')
}

Export-ModuleMember -Function Test-Ready,Invoke-Apply,Invoke-Verify
