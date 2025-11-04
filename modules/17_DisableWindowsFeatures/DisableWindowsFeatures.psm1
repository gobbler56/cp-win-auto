# ==========================================================================================
# Module: DisableWindowsFeatures
# Purpose: Disable unnecessary and potentially insecure Windows optional features
# ==========================================================================================

Set-StrictMode -Version Latest

# Import core modules
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

$script:ModuleName = 'DisableWindowsFeatures'

# ==========================================================================================
# Helper Functions
# ==========================================================================================

<#
.SYNOPSIS
  Checks if IIS is actively being used on the system.
.DESCRIPTION
  Determines if IIS should be preserved by checking for:
  - Configured websites
  - Configured application pools
  - Running IIS services
.OUTPUTS
  $true if IIS appears to be in use, $false otherwise
#>
function Test-IISInUse {
  try {
    # Check if IIS management module is available
    Import-Module WebAdministration -ErrorAction Stop

    # Check for websites (excluding default if it's stopped)
    $websites = Get-Website -ErrorAction SilentlyContinue
    $activeWebsites = $websites | Where-Object { $_.State -eq 'Started' }

    if ($activeWebsites) {
      Write-Info "Found $($activeWebsites.Count) active IIS website(s)"
      return $true
    }

    # Check for custom application pools (excluding defaults)
    $appPools = Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue
    $customAppPools = $appPools | Where-Object {
      $_.Name -notin @('DefaultAppPool', '.NET v4.5', '.NET v4.5 Classic')
    }

    if ($customAppPools) {
      Write-Info "Found $($customAppPools.Count) custom IIS application pool(s)"
      return $true
    }

    return $false
  }
  catch {
    # If WebAdministration module isn't available, IIS probably isn't installed/used
    Write-Info "IIS management module not available, assuming IIS not in use"
    return $false
  }
}

<#
.SYNOPSIS
  Safely disables a Windows optional feature if it exists and is enabled.
.PARAMETER FeatureName
  The name of the feature to disable
.PARAMETER Description
  Human-readable description for logging
.OUTPUTS
  Result object with Success (bool) and Message (string)
#>
function Disable-OptionalFeatureSafe {
  param(
    [Parameter(Mandatory)][string]$FeatureName,
    [Parameter(Mandatory)][string]$Description
  )

  try {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue

    if (-not $feature) {
      Write-Info "[$Description] Feature not found, skipping"
      return @{ Success = $true; Message = 'Not installed' }
    }

    if ($feature.State -match 'Disabled|DisablePending') {
      Write-Ok "[$Description] Already disabled"
      return @{ Success = $true; Message = 'Already disabled' }
    }

    Write-Info "[$Description] Disabling..."
    Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -Remove -NoRestart -ErrorAction Stop | Out-Null
    Write-Ok "[$Description] Disabled successfully"
    return @{ Success = $true; Message = 'Disabled' }
  }
  catch {
    Write-Warn ("[$Description] Failed to disable: {0}" -f $_.Exception.Message)
    return @{ Success = $false; Message = "Failed: $($_.Exception.Message)" }
  }
}

<#
.SYNOPSIS
  Safely removes a Windows capability if it exists and is installed.
.PARAMETER CapabilityName
  The name of the capability to remove
.PARAMETER Description
  Human-readable description for logging
.OUTPUTS
  Result object with Success (bool) and Message (string)
#>
function Remove-CapabilitySafe {
  param(
    [Parameter(Mandatory)][string]$CapabilityName,
    [Parameter(Mandatory)][string]$Description
  )

  try {
    $capability = Get-WindowsCapability -Online | Where-Object Name -eq $CapabilityName

    if (-not $capability) {
      Write-Info "[$Description] Capability not found, skipping"
      return @{ Success = $true; Message = 'Not available' }
    }

    if ($capability.State -ne 'Installed') {
      Write-Ok "[$Description] Not installed"
      return @{ Success = $true; Message = 'Not installed' }
    }

    Write-Info "[$Description] Removing..."
    Remove-WindowsCapability -Online -Name $CapabilityName -ErrorAction Stop | Out-Null
    Write-Ok "[$Description] Removed successfully"
    return @{ Success = $true; Message = 'Removed' }
  }
  catch {
    Write-Warn ("[$Description] Failed to remove: {0}" -f $_.Exception.Message)
    return @{ Success = $false; Message = "Failed: $($_.Exception.Message)" }
  }
}

<#
.SYNOPSIS
  Disables all IIS-related features.
.PARAMETER Force
  If $true, disables IIS even if it appears to be in use
.OUTPUTS
  Result object with Success (bool) and Message (string)
#>
function Disable-IISFeatures {
  param([switch]$Force)

  # Check if IIS is in use
  $iisInUse = Test-IISInUse

  if ($iisInUse -and -not $Force) {
    Write-Warn "[IIS] IIS appears to be in use. Skipping to avoid breaking services."
    Write-Warn "[IIS] To force disable, set environment variable: `$env:DISABLE_IIS_FORCE = '1'"
    return @{ Success = $true; Message = 'Skipped (in use)' }
  }

  try {
    $iisFeatures = Get-WindowsOptionalFeature -Online | Where-Object FeatureName -like 'IIS*'

    if (-not $iisFeatures) {
      Write-Ok "[IIS] No IIS features found"
      return @{ Success = $true; Message = 'Not installed' }
    }

    $disabledCount = 0
    $totalCount = $iisFeatures.Count

    foreach ($feature in $iisFeatures) {
      if ($feature.State -match 'Enabled|EnablePending') {
        try {
          Write-Info "[IIS] Disabling $($feature.FeatureName)..."
          Disable-WindowsOptionalFeature -Online -FeatureName $feature.FeatureName -Remove -NoRestart -ErrorAction Stop | Out-Null
          $disabledCount++
        }
        catch {
          Write-Warn "[IIS] Failed to disable $($feature.FeatureName): $($_.Exception.Message)"
        }
      }
    }

    if ($disabledCount -gt 0) {
      Write-Ok "[IIS] Disabled $disabledCount/$totalCount IIS feature(s)"
      return @{ Success = $true; Message = "Disabled $disabledCount features" }
    }
    else {
      Write-Ok "[IIS] Already disabled"
      return @{ Success = $true; Message = 'Already disabled' }
    }
  }
  catch {
    Write-Warn "[IIS] Failed: $($_.Exception.Message)"
    return @{ Success = $false; Message = "Failed: $($_.Exception.Message)" }
  }
}

# ==========================================================================================
# Required Module Functions
# ==========================================================================================

<#
.SYNOPSIS
  Tests if the system is ready to run this module.
#>
function Test-Ready {
  param($Context)

  # Check for required cmdlets
  $requiredCmdlets = @(
    'Get-WindowsOptionalFeature',
    'Disable-WindowsOptionalFeature',
    'Get-WindowsCapability',
    'Remove-WindowsCapability'
  )

  foreach ($cmdlet in $requiredCmdlets) {
    if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
      Write-Warn "Required cmdlet '$cmdlet' is not available"
      return $false
    }
  }

  return $true
}

<#
.SYNOPSIS
  Applies the module configuration by disabling unnecessary Windows features.
#>
function Invoke-Apply {
  param($Context)

  Write-Info "Disabling unnecessary Windows features..."

  $results = [ordered]@{}

  # PowerShell 2.0 (legacy, insecure)
  $results['PowerShell 2.0'] = Disable-OptionalFeatureSafe -FeatureName 'MicrosoftWindowsPowerShellV2' -Description 'PowerShell 2.0'

  # SMBv1 (vulnerable protocol)
  $results['SMBv1'] = Disable-OptionalFeatureSafe -FeatureName 'SMB1Protocol' -Description 'SMBv1 Protocol'

  # Telnet Client (insecure)
  $results['Telnet Client'] = Disable-OptionalFeatureSafe -FeatureName 'TelnetClient' -Description 'Telnet Client'

  # TFTP Client (insecure)
  $results['TFTP Client'] = Disable-OptionalFeatureSafe -FeatureName 'TFTP' -Description 'TFTP Client'

  # IIS (with usage check)
  $forceDisableIIS = $env:DISABLE_IIS_FORCE -eq '1'
  $results['IIS'] = Disable-IISFeatures -Force:$forceDisableIIS

  # Work Folders Client
  $results['Work Folders'] = Disable-OptionalFeatureSafe -FeatureName 'WorkFolders-Client' -Description 'Work Folders Client'

  # Internet Printing Client
  $results['Internet Printing'] = Disable-OptionalFeatureSafe -FeatureName 'Printing-InternetPrinting-Client' -Description 'Internet Printing Client'

  # LPR Port Monitor
  $results['LPR Monitor'] = Disable-OptionalFeatureSafe -FeatureName 'Printing-LPRPortMonitor' -Description 'LPR Port Monitor'

  # NFS Client
  $results['NFS Client'] = Disable-OptionalFeatureSafe -FeatureName 'NFS-Client' -Description 'NFS Client'

  # Windows Media Player
  $results['Windows Media Player'] = Disable-OptionalFeatureSafe -FeatureName 'WindowsMediaPlayer' -Description 'Windows Media Player'

  # SNMP Client (capability)
  $results['SNMP Client'] = Remove-CapabilitySafe -CapabilityName 'SNMP.Client~~~~0.0.1.0' -Description 'SNMP Client'

  # XPS Viewer (capability)
  $results['XPS Viewer'] = Remove-CapabilitySafe -CapabilityName 'XPS.Viewer~~~~0.0.1.0' -Description 'XPS Viewer'

  # Calculate summary
  $successful = ($results.Values | Where-Object { $_.Success }).Count
  $total = $results.Count

  # Build detailed message
  $summary = $results.GetEnumerator() | ForEach-Object {
    "$($_.Key): $($_.Value.Message)"
  }
  $message = "Processed $total features ($successful successful)`n" + ($summary -join "`n")

  $status = if ($successful -eq $total) { 'Succeeded' } else { 'PartialSuccess' }

  return New-ModuleResult -Name $script:ModuleName -Status $status -Message $message
}

<#
.SYNOPSIS
  Verifies that unnecessary Windows features are disabled.
#>
function Invoke-Verify {
  param($Context)

  Write-Info "Verifying Windows features are disabled..."

  $checks = [ordered]@{}

  # Define features to check
  $featuresToCheck = @{
    'PowerShell 2.0' = 'MicrosoftWindowsPowerShellV2'
    'SMBv1' = 'SMB1Protocol'
    'Telnet Client' = 'TelnetClient'
    'TFTP Client' = 'TFTP'
    'Work Folders' = 'WorkFolders-Client'
    'Internet Printing' = 'Printing-InternetPrinting-Client'
    'LPR Monitor' = 'Printing-LPRPortMonitor'
    'NFS Client' = 'NFS-Client'
    'Windows Media Player' = 'WindowsMediaPlayer'
  }

  foreach ($desc in $featuresToCheck.Keys) {
    $featureName = $featuresToCheck[$desc]
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue

    if (-not $feature) {
      $checks[$desc] = 'Not installed'
    }
    elseif ($feature.State -match 'Disabled|DisablePending') {
      $checks[$desc] = 'Disabled'
    }
    else {
      $checks[$desc] = 'ENABLED'
    }
  }

  # Check IIS
  $iisFeatures = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like 'IIS*' -and $_.State -match 'Enabled' }
  if ($iisFeatures) {
    $checks['IIS'] = "ENABLED ($($iisFeatures.Count) features)"
  }
  else {
    $checks['IIS'] = 'Disabled'
  }

  # Check capabilities
  $capabilitiesToCheck = @{
    'SNMP Client' = 'SNMP.Client~~~~0.0.1.0'
    'XPS Viewer' = 'XPS.Viewer~~~~0.0.1.0'
  }

  foreach ($desc in $capabilitiesToCheck.Keys) {
    $capName = $capabilitiesToCheck[$desc]
    $capability = Get-WindowsCapability -Online | Where-Object Name -eq $capName

    if (-not $capability) {
      $checks[$desc] = 'Not available'
    }
    elseif ($capability.State -eq 'Installed') {
      $checks[$desc] = 'INSTALLED'
    }
    else {
      $checks[$desc] = 'Not installed'
    }
  }

  # Build summary message
  $summary = $checks.GetEnumerator() | ForEach-Object {
    "$($_.Key): $($_.Value)"
  }
  $message = $summary -join ', '

  # Check if any are still enabled/installed
  $anyEnabled = $checks.Values | Where-Object { $_ -match 'ENABLED|INSTALLED' }
  $status = if ($anyEnabled) { 'PartialSuccess' } else { 'Succeeded' }

  return New-ModuleResult -Name $script:ModuleName -Status $status -Message $message
}

# ==========================================================================================
# Export Module Members
# ==========================================================================================

Export-ModuleMember -Function Test-Ready, Invoke-Apply, Invoke-Verify
