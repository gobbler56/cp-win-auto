<#
.SYNOPSIS
  BitLocker encryption module for Windows hardening.

.DESCRIPTION
  Enables BitLocker drive encryption on OS and data drives with:
    - TPM-based protection (TPM 1.2 or 2.0)
    - Recovery password protectors
    - XTS-AES-256 encryption by default
    - Used-Space-Only encryption for faster deployment
    - Automatic unlock for data drives
    - Recovery key backup to secure location and AD (when domain-joined)
    - Support for systems with and without TPM

.NOTES
  Module Name: BitLocker
  Version: 1.0
  Author: CyberPatriot Windows Automation
#>

Set-StrictMode -Version Latest

# Import core dependencies
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

# Module-level script variables
$script:ModuleName = 'BitLocker'
$script:RecoveryKeyPath = "$env:SystemDrive\BitLockerRecovery"
$script:EncryptionMethod = 'XtsAes256'

# ============================================================================
# Helper Functions
# ============================================================================

function Assert-Admin {
  <#
  .SYNOPSIS
    Verifies the script is running with administrator privileges.
  #>
  $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Test-DomainJoined {
  <#
  .SYNOPSIS
    Checks if the computer is joined to a domain.
  #>
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    return $cs.PartOfDomain
  } catch {
    Write-Warn "Failed to check domain membership: $($_.Exception.Message)"
    return $false
  }
}

function Test-BitLockerAvailable {
  <#
  .SYNOPSIS
    Checks if BitLocker PowerShell cmdlets are available.
  #>
  $cmd = Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue
  return ($null -ne $cmd)
}

function Test-TPMPresent {
  <#
  .SYNOPSIS
    Checks if TPM is present and ready.
  #>
  try {
    $tpm = Get-Tpm -ErrorAction Stop
    return @{
      Present = $tpm.TpmPresent
      Ready = $tpm.TpmReady
      Enabled = $tpm.TpmEnabled
      Activated = $tpm.TpmActivated
    }
  } catch {
    Write-Warn "Failed to get TPM status: $($_.Exception.Message)"
    return @{
      Present = $false
      Ready = $false
      Enabled = $false
      Activated = $false
    }
  }
}

function Set-BitLockerPolicy {
  <#
  .SYNOPSIS
    Configures local Group Policy settings for BitLocker.
  #>
  param(
    [bool]$AllowWithoutTPM = $true
  )

  try {
    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'

    # Create registry path if it doesn't exist
    if (-not (Test-Path $regPath)) {
      New-Item -Path $regPath -Force | Out-Null
      Write-Info "Created BitLocker policy registry path"
    }

    # Enable BitLocker without compatible TPM (if needed)
    if ($AllowWithoutTPM) {
      New-ItemProperty -Path $regPath -Name 'EnableBDEWithNoTPM' -PropertyType DWord -Value 1 -Force | Out-Null
      Write-Info "Enabled BitLocker without TPM policy"
    }

    # Allow TPM
    New-ItemProperty -Path $regPath -Name 'UseTPM' -PropertyType DWord -Value 1 -Force | Out-Null

    # Allow TPM + Startup Key
    New-ItemProperty -Path $regPath -Name 'UseTPMKey' -PropertyType DWord -Value 1 -Force | Out-Null

    # Allow TPM + PIN
    New-ItemProperty -Path $regPath -Name 'UseTPMKeyPIN' -PropertyType DWord -Value 1 -Force | Out-Null

    # Allow TPM + PIN + Startup Key
    New-ItemProperty -Path $regPath -Name 'UseTPMPIN' -PropertyType DWord -Value 1 -Force | Out-Null

    # Use standard PINs (not enhanced alphanumeric)
    New-ItemProperty -Path $regPath -Name 'UseEnhancedPin' -PropertyType DWord -Value 0 -Force | Out-Null

    # Configure minimum PIN length (6 digits)
    New-ItemProperty -Path $regPath -Name 'MinimumPIN' -PropertyType DWord -Value 6 -Force | Out-Null

    # Require additional authentication at startup
    New-ItemProperty -Path $regPath -Name 'UseAdvancedStartup' -PropertyType DWord -Value 1 -Force | Out-Null

    # Enable use of BitLocker authentication requiring preboot keyboard input
    New-ItemProperty -Path $regPath -Name 'EnableBDEWithNoTPM' -PropertyType DWord -Value 1 -Force | Out-Null

    # Configure encryption method for OS drives
    $encPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
    New-ItemProperty -Path $encPath -Name 'EncryptionMethodWithXtsOs' -PropertyType DWord -Value 7 -Force | Out-Null # 7 = XTS-AES 256
    New-ItemProperty -Path $encPath -Name 'EncryptionMethodWithXtsFdv' -PropertyType DWord -Value 7 -Force | Out-Null # 7 = XTS-AES 256
    New-ItemProperty -Path $encPath -Name 'EncryptionMethodWithXtsRdv' -PropertyType DWord -Value 7 -Force | Out-Null # 7 = XTS-AES 256
    New-ItemProperty -Path $encPath -Name 'EncryptionMethod' -PropertyType DWord -Value 4 -Force | Out-Null # 4 = AES 256 (fallback)

    Write-Ok "BitLocker Group Policy configured successfully"
    return $true
  } catch {
    Write-Err "Failed to configure BitLocker policy: $($_.Exception.Message)"
    return $false
  }
}

function Get-OSDrive {
  <#
  .SYNOPSIS
    Gets the OS drive letter.
  #>
  try {
    $volume = Get-Volume | Where-Object {
      $_.DriveType -eq 'Fixed' -and
      $_.DriveLetter -ne $null
    } | Sort-Object DriveLetter | Select-Object -First 1

    if ($volume) {
      return "$($volume.DriveLetter):"
    }
    return $env:SystemDrive
  } catch {
    return $env:SystemDrive
  }
}

function Get-DataDrives {
  <#
  .SYNOPSIS
    Gets all fixed data drives (excluding OS drive).
  #>
  param([string]$OSDrive)

  try {
    $drives = Get-Volume | Where-Object {
      $_.DriveType -eq 'Fixed' -and
      $_.DriveLetter -ne $null -and
      "$($_.DriveLetter):" -ne $OSDrive
    }
    return $drives
  } catch {
    return @()
  }
}

function Test-BitLockerVolume {
  <#
  .SYNOPSIS
    Checks BitLocker status for a volume.
  #>
  param([string]$MountPoint)

  try {
    $blv = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
    return @{
      MountPoint = $blv.MountPoint
      ProtectionStatus = $blv.ProtectionStatus
      VolumeStatus = $blv.VolumeStatus
      EncryptionMethod = $blv.EncryptionMethod
      EncryptionPercentage = $blv.EncryptionPercentage
      KeyProtectors = $blv.KeyProtector
    }
  } catch {
    return $null
  }
}

function New-RecoveryKeyDirectory {
  <#
  .SYNOPSIS
    Creates a secure directory for recovery keys.
  #>
  param([string]$Path)

  try {
    if (-not (Test-Path $Path)) {
      $dir = New-Item -ItemType Directory -Path $Path -Force

      # Set restrictive ACL (SYSTEM and Administrators only)
      $acl = Get-Acl $dir.FullName
      $acl.SetAccessRuleProtection($true, $false) # Disable inheritance

      # Add SYSTEM - Full Control
      $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
      $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $systemSid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
      )
      $acl.AddAccessRule($systemRule)

      # Add Administrators - Full Control
      $adminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
      $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $adminSid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
      )
      $acl.AddAccessRule($adminRule)

      Set-Acl -Path $dir.FullName -AclObject $acl
      Write-Ok "Created secure recovery key directory: $Path"
      return $true
    }
    return $true
  } catch {
    Write-Err "Failed to create recovery key directory: $($_.Exception.Message)"
    return $false
  }
}

function Save-RecoveryKey {
  <#
  .SYNOPSIS
    Saves recovery key information to a JSON file.
  #>
  param(
    [string]$MountPoint,
    [string]$RecoveryPassword,
    [string]$KeyProtectorId
  )

  try {
    if (-not (New-RecoveryKeyDirectory -Path $script:RecoveryKeyPath)) {
      return $false
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $volumeName = $MountPoint.TrimEnd(':').Replace('\', '_')
    $fileName = "BitLocker_$env:COMPUTERNAME`_$volumeName`_$timestamp.json"
    $filePath = Join-Path $script:RecoveryKeyPath $fileName

    $recoveryInfo = [PSCustomObject]@{
      ComputerName = $env:COMPUTERNAME
      Volume = $MountPoint
      KeyProtectorId = $KeyProtectorId
      RecoveryPassword = $RecoveryPassword
      TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
      EncryptionMethod = $script:EncryptionMethod
    }

    $recoveryInfo | ConvertTo-Json -Depth 3 | Out-File -FilePath $filePath -Encoding UTF8 -Force
    Write-Ok "Saved recovery key for $MountPoint to $filePath"
    return $true
  } catch {
    Write-Err "Failed to save recovery key: $($_.Exception.Message)"
    return $false
  }
}

function Backup-RecoveryKeyToAD {
  <#
  .SYNOPSIS
    Backs up recovery key to Active Directory (if domain-joined).
  #>
  param(
    [string]$MountPoint,
    [string]$KeyProtectorId
  )

  try {
    if (Test-DomainJoined) {
      Backup-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $KeyProtectorId -ErrorAction Stop | Out-Null
      Write-Ok "Backed up recovery key for $MountPoint to Active Directory"
      return $true
    } else {
      Write-Info "Not domain-joined, skipping AD backup for $MountPoint"
      return $false
    }
  } catch {
    Write-Warn "Failed to backup recovery key to AD for $MountPoint`: $($_.Exception.Message)"
    return $false
  }
}

function Enable-BitLockerOSVolume {
  <#
  .SYNOPSIS
    Enables BitLocker on the OS volume with appropriate protectors.
  #>
  param([string]$OSDrive)

  try {
    $blStatus = Test-BitLockerVolume -MountPoint $OSDrive

    if ($blStatus -and $blStatus.ProtectionStatus -eq 'On') {
      Write-Info "BitLocker already enabled on OS drive $OSDrive"
      return $true
    }

    Write-Info "Enabling BitLocker on OS drive $OSDrive..."

    # Get TPM status
    $tpmStatus = Test-TPMPresent

    # Add appropriate protector based on TPM availability
    if ($tpmStatus.Present -and $tpmStatus.Ready) {
      Write-Info "TPM detected and ready, adding TPM protector"
      try {
        Add-BitLockerKeyProtector -MountPoint $OSDrive -TpmProtector -ErrorAction Stop | Out-Null
        Write-Ok "Added TPM protector to $OSDrive"
      } catch {
        Write-Warn "Failed to add TPM protector: $($_.Exception.Message)"
      }
    } else {
      Write-Warn "TPM not available or not ready. BitLocker will use recovery password only."
      Write-Info "TPM Status: Present=$($tpmStatus.Present), Ready=$($tpmStatus.Ready), Enabled=$($tpmStatus.Enabled)"
    }

    # Always add recovery password protector
    Write-Info "Adding recovery password protector to $OSDrive"
    $recoveryProtector = Add-BitLockerKeyProtector -MountPoint $OSDrive -RecoveryPasswordProtector -ErrorAction Stop

    if ($recoveryProtector -and $recoveryProtector.KeyProtector) {
      $keyProtectorId = $recoveryProtector.KeyProtector[0].KeyProtectorId
      $recoveryPassword = $recoveryProtector.KeyProtector[0].RecoveryPassword

      # Save recovery key to file
      Save-RecoveryKey -MountPoint $OSDrive -RecoveryPassword $recoveryPassword -KeyProtectorId $keyProtectorId

      # Backup to AD if domain-joined
      Backup-RecoveryKeyToAD -MountPoint $OSDrive -KeyProtectorId $keyProtectorId
    }

    # Enable BitLocker encryption
    Write-Info "Starting BitLocker encryption on $OSDrive (Method: $script:EncryptionMethod, Used-Space-Only)"
    Enable-BitLocker -MountPoint $OSDrive -EncryptionMethod $script:EncryptionMethod -UsedSpaceOnly -SkipHardwareTest -ErrorAction Stop | Out-Null

    Write-Ok "BitLocker enabled successfully on $OSDrive"
    return $true
  } catch {
    Write-Err "Failed to enable BitLocker on $OSDrive`: $($_.Exception.Message)"
    return $false
  }
}

function Enable-BitLockerDataVolume {
  <#
  .SYNOPSIS
    Enables BitLocker on a data volume.
  #>
  param([string]$MountPoint)

  try {
    $blStatus = Test-BitLockerVolume -MountPoint $MountPoint

    if ($blStatus -and $blStatus.ProtectionStatus -eq 'On') {
      Write-Info "BitLocker already enabled on data drive $MountPoint"
      return $true
    }

    Write-Info "Enabling BitLocker on data drive $MountPoint..."

    # Add recovery password protector
    Write-Info "Adding recovery password protector to $MountPoint"
    $recoveryProtector = Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector -ErrorAction Stop

    if ($recoveryProtector -and $recoveryProtector.KeyProtector) {
      $keyProtectorId = $recoveryProtector.KeyProtector[0].KeyProtectorId
      $recoveryPassword = $recoveryProtector.KeyProtector[0].RecoveryPassword

      # Save recovery key to file
      Save-RecoveryKey -MountPoint $MountPoint -RecoveryPassword $recoveryPassword -KeyProtectorId $keyProtectorId

      # Backup to AD if domain-joined
      Backup-RecoveryKeyToAD -MountPoint $MountPoint -KeyProtectorId $keyProtectorId
    }

    # Enable BitLocker encryption (used-space-only for faster deployment)
    Write-Info "Starting BitLocker encryption on $MountPoint (Method: $script:EncryptionMethod, Used-Space-Only)"
    Enable-BitLocker -MountPoint $MountPoint -EncryptionMethod $script:EncryptionMethod -UsedSpaceOnly -ErrorAction Stop | Out-Null

    # Enable auto-unlock for data drives
    try {
      Enable-BitLockerAutoUnlock -MountPoint $MountPoint -ErrorAction Stop | Out-Null
      Write-Ok "Enabled auto-unlock for $MountPoint"
    } catch {
      Write-Warn "Failed to enable auto-unlock for $MountPoint`: $($_.Exception.Message)"
    }

    Write-Ok "BitLocker enabled successfully on $MountPoint"
    return $true
  } catch {
    Write-Err "Failed to enable BitLocker on $MountPoint`: $($_.Exception.Message)"
    return $false
  }
}

# ============================================================================
# Required Module Functions
# ============================================================================

function Test-Ready {
  <#
  .SYNOPSIS
    Validates prerequisites for the BitLocker module.
  #>
  param($Context)

  # Check if running as administrator
  if (-not (Assert-Admin)) {
    Write-Err "Module requires administrator privileges"
    return $false
  }

  # Check if BitLocker cmdlets are available
  if (-not (Test-BitLockerAvailable)) {
    Write-Err "BitLocker PowerShell cmdlets not available. On Server, install with: Install-WindowsFeature BitLocker -IncludeAllSubFeature"
    return $false
  }

  # Check for required commands
  $requiredCommands = @('Get-BitLockerVolume', 'Enable-BitLocker', 'Add-BitLockerKeyProtector', 'Get-Tpm')
  foreach ($cmd in $requiredCommands) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
      Write-Err "Required command not found: $cmd"
      return $false
    }
  }

  Write-Ok "BitLocker module prerequisites validated"
  return $true
}

function Invoke-Apply {
  <#
  .SYNOPSIS
    Enables BitLocker on OS and data drives.
  #>
  param($Context)

  try {
    $results = @()

    Write-Info "Starting BitLocker configuration..."

    # Configure BitLocker Group Policy
    if (-not (Set-BitLockerPolicy -AllowWithoutTPM $true)) {
      $results += "Policy configuration failed"
    } else {
      $results += "Policy configured"
    }

    # Check TPM status
    $tpmStatus = Test-TPMPresent
    if ($tpmStatus.Present) {
      if ($tpmStatus.Ready) {
        Write-Ok "TPM is present and ready (Enabled: $($tpmStatus.Enabled), Activated: $($tpmStatus.Activated))"
        $results += "TPM ready"
      } else {
        Write-Warn "TPM is present but not ready. BitLocker will still be enabled with recovery password."
        $results += "TPM not ready, using recovery password only"
      }
    } else {
      Write-Warn "No TPM detected. BitLocker will use recovery password protection only."
      $results += "No TPM detected"
    }

    # Get OS drive
    $osDrive = Get-OSDrive
    Write-Info "OS Drive: $osDrive"

    # Enable BitLocker on OS drive
    if (Enable-BitLockerOSVolume -OSDrive $osDrive) {
      $results += "OS drive ($osDrive) encrypted"
    } else {
      $results += "OS drive ($osDrive) failed"
    }

    # Get and encrypt data drives
    $dataVolumes = Get-DataDrives -OSDrive $osDrive
    if ($dataVolumes -and $dataVolumes.Count -gt 0) {
      Write-Info "Found $($dataVolumes.Count) data drive(s)"

      foreach ($volume in $dataVolumes) {
        $mountPoint = "$($volume.DriveLetter):"
        if (Enable-BitLockerDataVolume -MountPoint $mountPoint) {
          $results += "Data drive ($mountPoint) encrypted"
        } else {
          $results += "Data drive ($mountPoint) failed"
        }
      }
    } else {
      Write-Info "No additional data drives found"
      $results += "No data drives found"
    }

    # Check for failures
    $failed = $results | Where-Object { $_ -match 'failed' }
    if ($failed) {
      $message = "BitLocker configuration completed with errors: $($results -join '; ')"
      Write-Warn $message
      return New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message $message
    }

    $message = "BitLocker enabled successfully. Recovery keys saved to $script:RecoveryKeyPath. Details: $($results -join '; ')"
    Write-Ok $message
    Write-Info "Encryption is running in background. Check status with: Get-BitLockerVolume"

    return New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message $message
  } catch {
    $message = "BitLocker configuration failed: $($_.Exception.Message)"
    Write-Err $message
    return New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message $message
  }
}

function Invoke-Verify {
  <#
  .SYNOPSIS
    Verifies BitLocker is enabled and functioning correctly.
  #>
  param($Context)

  try {
    $checks = @()
    $allPassed = $true

    # Check BitLocker policy
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
    if (Test-Path $policyPath) {
      $useTPM = Get-ItemProperty -Path $policyPath -Name 'UseTPM' -ErrorAction SilentlyContinue
      if ($useTPM -and $useTPM.UseTPM -eq 1) {
        $checks += "Policy: Configured"
      } else {
        $checks += "Policy: Incomplete"
        $allPassed = $false
      }
    } else {
      $checks += "Policy: Not configured"
      $allPassed = $false
    }

    # Check OS drive
    $osDrive = Get-OSDrive
    $osStatus = Test-BitLockerVolume -MountPoint $osDrive

    if ($osStatus) {
      if ($osStatus.ProtectionStatus -eq 'On') {
        $checks += "OS ($osDrive): Protected (Method: $($osStatus.EncryptionMethod), Progress: $($osStatus.EncryptionPercentage)%)"
      } else {
        $checks += "OS ($osDrive): Not protected (Status: $($osStatus.ProtectionStatus))"
        $allPassed = $false
      }

      # Check for recovery protector
      $hasRecovery = $osStatus.KeyProtectors | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
      if ($hasRecovery) {
        $checks += "OS Recovery Key: Present"
      } else {
        $checks += "OS Recovery Key: Missing"
        $allPassed = $false
      }
    } else {
      $checks += "OS ($osDrive): Not encrypted"
      $allPassed = $false
    }

    # Check TPM
    $tpmStatus = Test-TPMPresent
    if ($tpmStatus.Present -and $tpmStatus.Ready) {
      $checks += "TPM: Present and ready"
    } elseif ($tpmStatus.Present) {
      $checks += "TPM: Present but not ready"
    } else {
      $checks += "TPM: Not available"
    }

    # Check data drives
    $dataVolumes = Get-DataDrives -OSDrive $osDrive
    if ($dataVolumes -and $dataVolumes.Count -gt 0) {
      foreach ($volume in $dataVolumes) {
        $mountPoint = "$($volume.DriveLetter):"
        $dataStatus = Test-BitLockerVolume -MountPoint $mountPoint

        if ($dataStatus -and $dataStatus.ProtectionStatus -eq 'On') {
          $checks += "Data ($mountPoint): Protected (Progress: $($dataStatus.EncryptionPercentage)%)"
        } else {
          $checks += "Data ($mountPoint): Not protected"
          $allPassed = $false
        }
      }
    }

    # Check recovery key directory
    if (Test-Path $script:RecoveryKeyPath) {
      $keyFiles = Get-ChildItem -Path $script:RecoveryKeyPath -Filter "BitLocker_*.json" -ErrorAction SilentlyContinue
      if ($keyFiles) {
        $checks += "Recovery Keys: $($keyFiles.Count) file(s) in $script:RecoveryKeyPath"
      } else {
        $checks += "Recovery Keys: Directory exists but no keys found"
      }
    } else {
      $checks += "Recovery Keys: Directory not found"
      $allPassed = $false
    }

    $status = if ($allPassed) { 'Succeeded' } else { 'Failed' }
    $message = $checks -join '; '

    if ($allPassed) {
      Write-Ok "BitLocker verification passed"
    } else {
      Write-Warn "BitLocker verification found issues"
    }

    return New-ModuleResult -Name $script:ModuleName -Status $status -Message $message
  } catch {
    $message = "BitLocker verification failed: $($_.Exception.Message)"
    Write-Err $message
    return New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message $message
  }
}

# Export only the required module functions
Export-ModuleMember -Function Test-Ready, Invoke-Verify, Invoke-Apply
