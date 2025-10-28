Set-StrictMode -Version Latest

if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

$script:ModuleName = 'OSUpdates'

function Invoke-Safely {
  param(
    [ScriptBlock]$Action,
    [string]$FailureMessage
  )

  try {
    & $Action
  } catch {
    throw ("{0}: {1}" -f $FailureMessage, $_.Exception.Message)
  }
}

function Ensure-PsWindowsUpdateModule {
  Write-Info 'Configuring PowerShell Gallery trust and PSWindowsUpdate module'

  try {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
  } catch {
    Write-Warn ("Failed to adjust execution policy: {0}" -f $_.Exception.Message)
  }

  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  } catch {
    Write-Warn ("Unable to enforce TLS 1.2: {0}" -f $_.Exception.Message)
  }

  Invoke-Safely -Action {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
  } -FailureMessage 'Failed to install NuGet package provider'

  try {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
  } catch {
    Write-Warn ("Failed to set PSGallery trust: {0}" -f $_.Exception.Message)
  }

  $module = Get-Module -ListAvailable -Name 'PSWindowsUpdate' | Select-Object -First 1
  if (-not $module) {
    Invoke-Safely -Action {
      Install-Module -Name 'PSWindowsUpdate' -Force -ErrorAction Stop
    } -FailureMessage 'Failed to install PSWindowsUpdate module'
  }

  Invoke-Safely -Action {
    Import-Module -Name 'PSWindowsUpdate' -Force -ErrorAction Stop
  } -FailureMessage 'Failed to import PSWindowsUpdate module'
}

function Ensure-MicrosoftUpdateService {
  try {
    Add-WUServiceManager -MicrosoftUpdate -Confirm:$false -ErrorAction Stop
  } catch {
    Write-Warn ("Unable to register Microsoft Update service: {0}" -f $_.Exception.Message)
  }
}

function Invoke-UpdateInstallation {
  Write-Info 'Checking for Windows and Microsoft updates (no automatic reboot)'
  $updates = @()
  $restartNeeded = $false

  Invoke-Safely -Action {
    $updates = Install-WindowsUpdate -AcceptAll -MicrosoftUpdate -ErrorAction Stop
  } -FailureMessage 'Failed to download/install updates'

  if ($updates) {
    foreach ($entry in $updates) {
      if ($entry -and ($entry | Get-Member -Name 'RebootRequired' -ErrorAction SilentlyContinue)) {
        if ($entry.RebootRequired -eq $true -or $entry.RebootRequired -eq 'True') {
          $restartNeeded = $true
          break
        }
      }
    }
  }

  return [pscustomobject]@{
    Updates       = @($updates)
    RestartNeeded = $restartNeeded
  }
}

function Test-Ready {
  param($Context)

  $required = @('Install-PackageProvider','Set-PSRepository','Install-Module','Import-Module')
  foreach ($cmd in $required) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
      Write-Warn ("Command '{0}' not available; OSUpdates module may fail." -f $cmd)
    }
  }

  return $true
}

function Invoke-Verify {
  param($Context)

  $module = Get-Module -ListAvailable -Name 'PSWindowsUpdate' | Select-Object -First 1
  if ($module) {
    $message = "PSWindowsUpdate module available (v$($module.Version))."
  } else {
    $message = 'PSWindowsUpdate module not yet installed; it will be configured during apply.'
  }

  return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message $message)
}

function Invoke-Apply {
  param($Context)

  try {
    Ensure-PsWindowsUpdateModule
    Ensure-MicrosoftUpdateService
    $result = Invoke-UpdateInstallation
  } catch {
    Write-Err ("OSUpdates apply failed: {0}" -f $_.Exception.Message)
    return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message ('Failed to install updates: ' + $_.Exception.Message))
  }

  $count = $result.Updates.Count
  $summary = if ($count -gt 0) {
    "Processed $count update(s)."
  } else {
    'System already up to date; no updates installed.'
  }

  if ($result.RestartNeeded) {
    $summary += ' A restart is required to finish applying updates.'
  }

  return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message $summary)
}

Export-ModuleMember -Function Test-Ready,Invoke-Verify,Invoke-Apply
