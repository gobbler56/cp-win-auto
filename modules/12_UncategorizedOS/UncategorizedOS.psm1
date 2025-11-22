Set-StrictMode -Version Latest

if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

$script:ModuleName              = 'UncategorizedOS'
$script:ApiUrl                  = 'https://openrouter.ai/api/v1/chat/completions'
$script:ApiKeyEnvVar            = 'OPENROUTER_API_KEY'
$script:OpenRouterModel         = if ($env:OPENROUTER_MODEL) { $env:OPENROUTER_MODEL } else { 'openai/gpt-5' }
$script:MaxReadmeCharacters     = 6000
$script:MaxShareEntries         = 50
$script:DefaultShareNames       = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:LastRemovedShares       = @()
$script:WriteRightsMask         = [System.Security.AccessControl.FileSystemRights]::FullControl `
  -bor [System.Security.AccessControl.FileSystemRights]::Modify `
  -bor [System.Security.AccessControl.FileSystemRights]::Write `
  -bor [System.Security.AccessControl.FileSystemRights]::WriteData `
  -bor [System.Security.AccessControl.FileSystemRights]::CreateFiles `
  -bor [System.Security.AccessControl.FileSystemRights]::CreateDirectories `
  -bor [System.Security.AccessControl.FileSystemRights]::AppendData `
  -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions

foreach ($name in @('ADMIN$','IPC$','C$','D$','E$','F$','G$','H$','PRINT$','FAX$','SYSVOL','NETLOGON')) {
  [void]$script:DefaultShareNames.Add($name)
}

# ---- Helpers -----------------------------------------------------------------

function Get-OpenRouterApiKey {
  $key = [System.Environment]::GetEnvironmentVariable($script:ApiKeyEnvVar)
  if (-not $key) { return '' }
  return $key
}

function Get-OSVersionInfo {
  # Returns [pscustomobject] with Major, Minor, Build; Win7=6.1, Win8=6.2, Win10+=10.0
  $v = [System.Environment]::OSVersion.Version
  [pscustomobject]@{ Major=$v.Major; Minor=$v.Minor; Build=$v.Build; Raw=$v }
}

function Is-LegacyGadgetOS {
  # Gadgets existed through Win7 (6.1). From 6.2+ (Win8+), they’re gone.
  $os = Get-OSVersionInfo
  return (($os.Major -lt 6) -or ($os.Major -eq 6 -and $os.Minor -le 1))
}

function Ensure-HkuDrive {
  if (Get-PSDrive -Name 'HKU' -ErrorAction SilentlyContinue) { return 'HKU:' }
  try {
    New-PSDrive -Name 'HKU' -PSProvider Registry -Root 'HKEY_USERS' -ErrorAction Stop | Out-Null
    return 'HKU:'
  } catch {
    if (Test-Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) {
      return 'Registry::HKEY_USERS'
    }
    Write-Warn ("Failed to create HKU drive: {0}" -f $_.Exception.Message)
    return $null
  }
}

function Resolve-RegistryPath {
  param(
    [Parameter(Mandatory)][string]$Path
  )

  if ($Path -like 'HKU:*') {
    $hkuRoot = Ensure-HkuDrive
    if (-not $hkuRoot) {
      Write-Info ("Skipping {0} because HKU registry hive is unavailable." -f $Path)
      return $null
    }

    if ($hkuRoot -eq 'HKU:') { return $Path }

    $relative = $Path -replace '^HKU:\\', ''
    return (Join-Path $hkuRoot $relative)
  }

  return $Path
}

function Ensure-RegistryValue {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('String','ExpandString','MultiString','Binary','DWord','QWord')][string]$Type,
    [Parameter(Mandatory)][object]$Value
  )

  try {
    $resolvedPath = Resolve-RegistryPath -Path $Path
    if (-not $resolvedPath) { return $false }

    if (-not (Test-Path -LiteralPath $resolvedPath)) {
      # Create missing key (handles nested under existing parents)
      try {
        New-Item -Path $resolvedPath -Force -ErrorAction Stop | Out-Null
      } catch {
        # If parent is missing, create parent+leaf explicitly
        $parent = Split-Path -Path $resolvedPath -Parent
        $leaf   = Split-Path -Path $resolvedPath -Leaf
        if ($parent -and (Test-Path $parent)) {
          New-Item -Path $parent -Name $leaf -ItemType RegistryKey -Force | Out-Null
        } else {
          throw
        }
      }
    }

    if ($Type -eq 'DWord') { $Value = [int]$Value }
    elseif ($Type -eq 'QWord') { $Value = [long]$Value }

    New-ItemProperty -Path $resolvedPath -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
    return $true
  } catch {
    Write-Warn ("Failed to set {0}\{1}: {2}" -f $Path, $Name, $_.Exception.Message)
    return $false
  }
}

function Get-RegistryValueSafe {
  param([string]$Path, [string]$Name)

  try {
    $resolvedPath = Resolve-RegistryPath -Path $Path
    if (-not $resolvedPath) { return $null }

    return (Get-ItemProperty -Path $resolvedPath -Name $Name -ErrorAction Stop).$Name
  } catch {
    return $null
  }
}

# ---- Settings: RDP / Remote Assistance --------------------------------------

function Disable-RemoteDesktopFeatures {
  $changed = $false
  $changed = (Ensure-RegistryValue -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Type 'DWord' -Value 1) -or $changed
  $changed = (Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Type 'DWord' -Value 0) -or $changed
  $changed = (Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowFullControl' -Type 'DWord' -Value 0) -or $changed
  return $changed
}

function Test-RemoteDesktopDisabled {
  $deny = (Get-RegistryValueSafe -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections') -eq 1
  $assist = (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp') -eq 0
  return ($deny -and $assist)
}

# ---- Settings: Desktop Gadgets (legacy only) --------------------------------

function Disable-DesktopGadgets {
  if (-not (Is-LegacyGadgetOS)) { return $false }  # Skip on Win8+ to avoid bogus keys/errors
  $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar'
  $changed = $false
  $changed = (Ensure-RegistryValue -Path $path -Name 'TurnOffSidebar' -Type 'DWord' -Value 1) -or $changed
  $changed = (Ensure-RegistryValue -Path $path -Name 'DisableSidebar' -Type 'DWord' -Value 1) -or $changed
  return $changed
}

function Test-DesktopGadgetsDisabled {
  if (-not (Is-LegacyGadgetOS)) { return $true } # Treated as compliant on modern OS
  $value = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar' -Name 'TurnOffSidebar'
  return ($value -eq 1)
}

# ---- Settings: DEP / Process mitigations ------------------------------------

function Set-DepPolicy {
  $changed = $false
  try {
    $current = ''
    try {
      $enum = & bcdedit /enum '{current}' 2>$null
      if ($LASTEXITCODE -eq 0 -and $enum) { $current = ($enum | Out-String) }
    } catch {}
    if (-not ($current -match 'nx\s+AlwaysOn')) {
      & bcdedit /set '{current}' nx AlwaysOn | Out-Null
      if ($LASTEXITCODE -eq 0) { $changed = $true }
    }
  } catch {
    Write-Warn ("Failed to configure DEP policy: {0}" -f $_.Exception.Message)
  }

  if (Get-Command Set-ProcessMitigation -ErrorAction SilentlyContinue) {
    try {
      Set-ProcessMitigation -System -Enable DEP -ErrorAction Stop | Out-Null
      $changed = $true
    } catch {
      Write-Warn ("Set-ProcessMitigation DEP failed: {0}" -f $_.Exception.Message)
    }
  }

  return $changed
}

function Test-DepPolicy {
  try {
    $enum = & bcdedit /enum '{current}' 2>$null
    if ($LASTEXITCODE -eq 0 -and $enum) {
      if ($enum -match 'nx\s+AlwaysOn') { return $true }
    }
  } catch {}
  return $false
}

# ---- Settings: UAC CredUI enumeration ---------------------------------------

function Set-UacAdministratorEnumeration {
  return (Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name 'EnumerateAdministrators' -Type 'DWord' -Value 0)
}

function Test-UacAdministratorEnumeration {
  return ((Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name 'EnumerateAdministrators') -eq 0)
}

# ---- Settings: Screen saver enforcement --------------------------------------

function Ensure-ScreenSaverPolicy {
  $changed = $false
  $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
  $changed = (Ensure-RegistryValue -Path $policyPath -Name 'ScreenSaveActive' -Type 'String' -Value '1') -or $changed
  $changed = (Ensure-RegistryValue -Path $policyPath -Name 'ScreenSaverIsSecure' -Type 'String' -Value '1') -or $changed
  $changed = (Ensure-RegistryValue -Path $policyPath -Name 'ScreenSaveTimeOut' -Type 'String' -Value '600') -or $changed
  $changed = (Ensure-RegistryValue -Path $policyPath -Name 'SCRNSAVE.EXE' -Type 'String' -Value 'scrnsave.scr') -or $changed

  $userPaths = @('HKCU:\Control Panel\Desktop')
  try {
    $hkuRoot = Ensure-HkuDrive
    if ($hkuRoot) {
      foreach ($sidKey in Get-ChildItem -Path $hkuRoot -ErrorAction SilentlyContinue) {
        if ($sidKey.Name -match 'S-1-5-21-') {
          $userPaths += (Join-Path $sidKey.PSPath 'Control Panel\Desktop')
        }
      }
    }
  } catch {}

  foreach ($path in ($userPaths | Select-Object -Unique)) {
    $changed = (Ensure-RegistryValue -Path $path -Name 'ScreenSaveActive' -Type 'String' -Value '1') -or $changed
    $changed = (Ensure-RegistryValue -Path $path -Name 'ScreenSaverIsSecure' -Type 'String' -Value '1') -or $changed
    $changed = (Ensure-RegistryValue -Path $path -Name 'ScreenSaveTimeOut' -Type 'String' -Value '600') -or $changed
    $changed = (Ensure-RegistryValue -Path $path -Name 'SCRNSAVE.EXE' -Type 'String' -Value 'scrnsave.scr') -or $changed
  }

  return $changed
}

function Test-ScreenSaverPolicy {
  $policy = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaverIsSecure'
  return ($policy -eq '1')
}

# ---- Settings: AutoRun / AutoPlay -------------------------------------------

function Ensure-AutorunDisabled {
  $changed = $false
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
  )

  foreach ($path in $paths) {
    $changed = (Ensure-RegistryValue -Path $path -Name 'NoDriveTypeAutoRun' -Type 'DWord' -Value 255) -or $changed
    $changed = (Ensure-RegistryValue -Path $path -Name 'NoAutorun' -Type 'DWord' -Value 1) -or $changed
    $changed = (Ensure-RegistryValue -Path $path -Name 'NoDriveAutoRun' -Type 'DWord' -Value 1) -or $changed
  }

  return $changed
}

function Ensure-AutoplayDisabled {
  $changed = $false
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'
  )

  foreach ($path in $paths) {
    $changed = (Ensure-RegistryValue -Path $path -Name 'DisableAutoplay' -Type 'DWord' -Value 1) -or $changed
  }

  return $changed
}

function Test-AutoplayDisabled {
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'
  )

  foreach ($path in $paths) {
    $value = Get-RegistryValueSafe -Path $path -Name 'DisableAutoplay'
    if ($value -ne 1) { return $false }
  }

  return $true
}

# ---- Settings: ASLR / Memory mitigations ------------------------------------

function Ensure-MemoryMitigations {
  $changed = $false
  $mmPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
  $changed = (Ensure-RegistryValue -Path $mmPath -Name 'MoveImages' -Type 'DWord' -Value 1) -or $changed
  $changed = (Ensure-RegistryValue -Path $mmPath -Name 'FeatureSettingsOverride' -Type 'DWord' -Value 0) -or $changed
  $changed = (Ensure-RegistryValue -Path $mmPath -Name 'FeatureSettingsOverrideMask' -Type 'DWord' -Value 3) -or $changed

  # Removed Set-ProcessMitigation call due to array bounds errors on some Windows versions
  # Registry settings above provide equivalent ASLR enforcement

  return $changed
}

function Test-MemoryMitigations {
  $move = (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'MoveImages')
  return ($move -eq 1)
}

function Ensure-EarlyLaunchPolicy {
  return (Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\EarlyLaunch' -Name 'DriverLoadPolicy' -Type 'DWord' -Value 1)
}

function Test-EarlyLaunchPolicy {
  return ((Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\EarlyLaunch' -Name 'DriverLoadPolicy') -eq 1)
}

function Ensure-ValidateHeapIntegrity {
  $kernelPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel'
  return (Ensure-RegistryValue -Path $kernelPath -Name 'ValidateHeapIntegrity' -Type 'DWord' -Value 1)
}

function Test-ValidateHeapIntegrity {
  $value = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel' -Name 'ValidateHeapIntegrity'
  return ($value -eq 1)
}

function Ensure-HeapMitigationOptions {
  $kernelPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel'
  $expected = [byte[]](0x11,0x12,0x11,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
  return (Ensure-RegistryValue -Path $kernelPath -Name 'MitigationOptions' -Type 'Binary' -Value $expected)
}

# ---- Settings: Networking ----------------------------------------------------

function Ensure-IpSourceRoutingDisabled {
  $changed = $false
  $changed = (Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableIPSourceRouting' -Type 'DWord' -Value 2) -or $changed
  $changed = (Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIPSourceRouting' -Type 'DWord' -Value 2) -or $changed
  return $changed
}

# ---- System integrity / crash handling --------------------------------------

function Ensure-CoreDumpsDisabled {
  return (Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'CrashDumpEnabled' -Type 'DWord' -Value 0)
}

function Test-CoreDumpsDisabled {
  $value = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'CrashDumpEnabled'
  return ($value -eq 0)
}

function Ensure-FipsAlgorithmsEnabled {
  return (Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name 'Enabled' -Type 'DWord' -Value 1)
}

function Test-FipsAlgorithmsEnabled {
  $value = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name 'Enabled'
  return ($value -eq 1)
}

# ---- Virtualization-based security -----------------------------------------

function Ensure-VbsMandatoryMode {
  return (Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'Mandatory' -Type 'DWord' -Value 1)
}

function Test-VbsMandatoryMode {
  $value = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'Mandatory'
  return ($value -eq 1)
}

function Ensure-MachineIdentityIsolation {
  return (Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'MachineIdentityIsolation' -Type 'DWord' -Value 2)
}

function Test-MachineIdentityIsolation {
  $value = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'MachineIdentityIsolation'
  return ($value -eq 1 -or $value -eq 2)
}

# ---- Devices / peripherals --------------------------------------------------

function Ensure-PrinterDriverRestriction {
  return (Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'RestrictDriverInstallationToAdministrators' -Type 'DWord' -Value 1)
}

function Test-PrinterDriverRestriction {
  $value = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'RestrictDriverInstallationToAdministrators'
  return ($value -eq 1)
}

# ---- Notifications / Store / lock screen -----------------------------------

function Ensure-LockScreenNotificationsDisabled {
  $paths = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications',
    'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
  )

  $changed = $false
  foreach ($path in $paths) {
    $changed = (Ensure-RegistryValue -Path $path -Name 'NoToastApplicationNotificationOnLockScreen' -Type 'DWord' -Value 1) -or $changed
    $changed = (Ensure-RegistryValue -Path $path -Name 'LockScreenToastEnabled' -Type 'DWord' -Value 0) -or $changed
  }

  return $changed
}

function Test-LockScreenNotificationsDisabled {
  $paths = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications',
    'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
  )

  foreach ($path in $paths) {
    $lockScreenOff = (Get-RegistryValueSafe -Path $path -Name 'NoToastApplicationNotificationOnLockScreen')
    $toastDisabled = (Get-RegistryValueSafe -Path $path -Name 'LockScreenToastEnabled')
    if ($lockScreenOff -ne 1 -or $toastDisabled -ne 0) { return $false }
  }

  return $true
}

function Ensure-WindowsStoreDisabled {
  return (Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'RemoveWindowsStore' -Type 'DWord' -Value 1)
}

function Test-WindowsStoreDisabled {
  $value = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'RemoveWindowsStore'
  return ($value -eq 1)
}

# ---- Boot security ----------------------------------------------------------

function Ensure-SecureBootEnabled {
  if (Test-SecureBootEnabled) { return $false }
  Write-Warn 'UEFI Secure Boot is not enabled; enable it in firmware settings.'
  return $false
}

function Test-SecureBootEnabled {
  try {
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
      return [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
    }
  } catch {}

  $value = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled'
  return ($value -eq 1)
}

# ---- Filesystem ACL hardening -----------------------------------------------

function Remove-IdentityWriteAccess {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Identity
  )

  if (-not (Test-Path $Path)) { return $false }

  try {
    $acl = Get-Acl -Path $Path -ErrorAction Stop
  } catch {
    Write-Warn ("Failed to read ACL for {0}: {1}" -f $Path, $_.Exception.Message)
    return $false
  }

  try {
    $ntAccount = New-Object System.Security.Principal.NTAccount($Identity)
    $target = $ntAccount.Value
  } catch {
    Write-Warn ("Failed to resolve identity {0}: {1}" -f $Identity, $_.Exception.Message)
    return $false
  }

  $changed = $false
  foreach ($rule in @($acl.Access)) {
    $match = [string]::Equals($rule.IdentityReference.Value, $target, [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $match) { continue }
    if (($rule.FileSystemRights -band $script:WriteRightsMask) -eq 0) { continue }
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
    if ($acl.RemoveAccessRule($rule)) { $changed = $true }
  }

  if ($changed) {
    try {
      Set-Acl -Path $Path -AclObject $acl
    } catch {
      Write-Warn ("Failed to update ACL for {0}: {1}" -f $Path, $_.Exception.Message)
      return $false
    }
  }

  return $changed
}

function Ensure-DirectoryRestrictions {
  $changed = $false
  if (Test-Path 'C:\Share')       { if (Remove-IdentityWriteAccess -Path 'C:\Share'       -Identity 'Everyone')     { $changed = $true } }
  if (Test-Path 'C:\inetpub')     { if (Remove-IdentityWriteAccess -Path 'C:\inetpub'     -Identity 'Everyone')     { $changed = $true } }
  if (Test-Path 'C:\Windows\NTDS'){ if (Remove-IdentityWriteAccess -Path 'C:\Windows\NTDS'-Identity 'Domain Users'){ $changed = $true } }
  return $changed
}

function Test-IdentityWriteAccess {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Identity
  )

  try {
    $acl = Get-Acl -Path $Path -ErrorAction Stop
    $ntAccount = New-Object System.Security.Principal.NTAccount($Identity)
    $target = $ntAccount.Value
  } catch {
    return $false
  }

  foreach ($rule in @($acl.Access)) {
    $match = [string]::Equals($rule.IdentityReference.Value, $target, [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $match) { continue }
    if (($rule.FileSystemRights -band $script:WriteRightsMask) -eq 0) { continue }
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
    return $true
  }

  return $false
}

function Ensure-HomeDirectoryIsolation {
  $basePath = 'C:\Users'
  if (-not (Test-Path $basePath)) { return $false }

  $exempt = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($name in @('Public','Default','Default User','All Users')) { [void]$exempt.Add($name) }

  $changed = $false
  try {
    $userDirs = Get-ChildItem -Path $basePath -Directory -ErrorAction Stop
  } catch {
    Write-Warn ("Failed to enumerate user directories: {0}" -f $_.Exception.Message)
    return $false
  }

  foreach ($dir in $userDirs) {
    if ($exempt.Contains($dir.Name)) { continue }
    $changed = (Remove-IdentityWriteAccess -Path $dir.FullName -Identity 'Users') -or $changed
    $changed = (Remove-IdentityWriteAccess -Path $dir.FullName -Identity 'Authenticated Users') -or $changed
  }

  return $changed
}

function Test-HomeDirectoryIsolation {
  $basePath = 'C:\Users'
  if (-not (Test-Path $basePath)) { return $true }

  $exempt = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($name in @('Public','Default','Default User','All Users')) { [void]$exempt.Add($name) }

  try {
    $userDirs = Get-ChildItem -Path $basePath -Directory -ErrorAction Stop
  } catch {
    return $false
  }

  foreach ($dir in $userDirs) {
    if ($exempt.Contains($dir.Name)) { continue }
    if (Test-IdentityWriteAccess -Path $dir.FullName -Identity 'Users') { return $false }
    if (Test-IdentityWriteAccess -Path $dir.FullName -Identity 'Authenticated Users') { return $false }
  }

  return $true
}

# ---- SMB share auditing/removal (with AI allowlist from README) --------------

function Remove-SpecificShare {
  param([string]$Name)
  if (-not $Name) { return $false }
  $removed = $false
  if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
    try {
      $share = Get-SmbShare -Name $Name -ErrorAction Stop
      if ($share) {
        Remove-SmbShare -Name $Name -Force -Confirm:$false -ErrorAction Stop
        $removed = $true
      }
    } catch {}
  }
  if (-not $removed) {
    try {
      $null = & net share $Name /delete /y 2>$null
      if ($LASTEXITCODE -eq 0) { $removed = $true }
    } catch {}
  }
  return $removed
}

function Get-ReadMeContent {
  $candidates = @('C:\CyberPatriot\README.url')
  if ($env:PUBLIC)      { $candidates += (Join-Path $env:PUBLIC      'Desktop\README.url') }
  if ($env:USERPROFILE) { $candidates += (Join-Path $env:USERPROFILE 'Desktop\README.url') }

  foreach ($candidate in $candidates) {
    if (-not $candidate) { continue }
    if (-not (Test-Path $candidate)) { continue }

    try {
      $lines = Get-Content -LiteralPath $candidate -ErrorAction Stop
      $urlLine = $lines | Where-Object { $_ -match '^\s*URL=' } | Select-Object -First 1
      if (-not $urlLine) { continue }
      $url = ($urlLine -replace '^\s*URL=', '').Trim()
      if (-not $url) { continue }
      $response = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
      $html = $response.Content
      if (-not $html) { continue }
      $text = $html
      $text = $text -replace '(?is)<script.*?>.*?</script>', ''
      $text = $text -replace '(?is)<style.*?>.*?</style>', ''
      $text = $text -replace '(?is)<head.*?>.*?</head>', ''
      $text = $text -replace '<.*?>', ' '
      $text = ($text -replace '\s+', ' ').Trim()
      if ($text.Length -gt $script:MaxReadmeCharacters) {
        $text = $text.Substring(0, $script:MaxReadmeCharacters)
      }
      return [pscustomobject]@{ Url = $url; Content = $text }
    } catch {
      Write-Warn ("Failed to download README from {0}: {1}" -f $candidate, $_.Exception.Message)
    }
  }

  return $null
}

function Get-ShareInventory {
  $shares = @()

  if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
    try {
      $shares = @(Get-SmbShare -ErrorAction Stop | Select-Object Name, Path, Description)
    } catch {}
  }

  if (-not $shares -or $shares.Count -eq 0) {
    try {
      $output = & net share 2>$null
      if ($LASTEXITCODE -eq 0 -and $output) {
        foreach ($line in $output) {
          if ($line -match '^\s*$' -or
              $line -match '^Share name' -or
              $line -match '^---' -or
              $line -match '^The command completed successfully') { continue }

          $parts = $line -split '\s{2,}'
          if ($parts.Count -ge 2) {
            $name = $parts[0].Trim()
            $path = $parts[1].Trim()
            $desc = if ($parts.Count -ge 3) { $parts[2].Trim() } else { '' }
            if ($name) {
              $shares += [pscustomobject]@{ Name = $name; Path = $path; Description = $desc }
            }
          }
        }
      }
    } catch {}
  }

  return @($shares | Select-Object -First $script:MaxShareEntries)
}

function Build-ShareAiRequest {
  param(
    [object[]]$Shares,
    [string]$ReadmeText
  )

  $systemPrompt = @"
You are assisting with CyberPatriot hardening. Default administrative shares are always allowed:
$($script:DefaultShareNames | Sort-Object | ForEach-Object { "- $_" } | Out-String)
Review the README and share inventory to determine which NON-default shares are explicitly authorized.
Respond ONLY with JSON in the form { "allowed": ["ShareName", ...] } listing extra shares that must remain.
Only include a share when the README clearly states it should exist.
Do not repeat the default shares and do not explain your reasoning.
"@

  $shareLines = @()
  $max = [math]::Min($Shares.Count, $script:MaxShareEntries)
  for ($i = 0; $i -lt $max; $i++) {
    $share = $Shares[$i]
    $shareLines += "Name={0} | Path={1} | Description={2}" -f $share.Name, $share.Path, $share.Description
  }
  if ($Shares.Count -gt $max) {
    $shareLines += "... truncated {0} of {1} shares" -f $max, $Shares.Count
  }

  $userPrompt = @"
README CONTENT:
$ReadmeText

SHARE INVENTORY:
$($shareLines -join [Environment]::NewLine)

Respond with JSON only.
"@

  $body = @{ 
    model = $script:OpenRouterModel
    temperature = 0
    top_p = 1
    messages = @(
      @{ role = 'system'; content = $systemPrompt },
      @{ role = 'user'; content = $userPrompt }
    )
    response_format = @{
      type = 'json_schema'
      json_schema = @{
        name   = 'share_plan'
        schema = @{
          type                 = 'object'
          required             = @('allowed')
          additionalProperties = $false
          properties           = @{ allowed = @{ type = 'array'; items = @{ type = 'string' } } }
        }
      }
    }
  }

  return ($body | ConvertTo-Json -Depth 10)
}

function Invoke-SharePlan {
  param(
    [object[]]$Shares,
    [string]$ReadmeText
  )

  if (-not $Shares -or $Shares.Count -eq 0) { return $null }
  if ([string]::IsNullOrWhiteSpace($ReadmeText)) { return $null }

  $apiKey = Get-OpenRouterApiKey
  if (-not $apiKey) { throw 'OpenRouter API key not found' }

  $body = Build-ShareAiRequest -Shares $Shares -ReadmeText $ReadmeText
  $headers = @{ 'Authorization' = "Bearer $apiKey"; 'Content-Type' = 'application/json'; 'X-Title' = 'CP-Share-Review' }

  try {
    $response = Invoke-RestMethod -Method Post -Uri $script:ApiUrl -Headers $headers -Body $body -ErrorAction Stop
  } catch {
    throw ("OpenRouter request failed: {0}" -f $_.Exception.Message)
  }

  $content = $response.choices[0].message.content
  if (-not $content) { throw 'OpenRouter response was empty.' }
  if ($content -match '^\s*```') {
    $content = ($content -replace '^\s*```(?:json)?', '' -replace '```\s*$', '').Trim()
  }

  try {
    $parsed = $content | ConvertFrom-Json
  } catch {
    throw ("Failed to parse OpenRouter response: {0}" -f $_.Exception.Message)
  }

  $allowed = @()
  if ($parsed -and $parsed.PSObject.Properties.Name -contains 'allowed') {
    foreach ($item in @($parsed.allowed)) {
      $name = ($item -as [string]).Trim()
      if ($name) { $allowed += $name }
    }
  }

  return @($allowed | Select-Object -Unique)
}

function Remove-NonDefaultSharesWithAi {
  $shares = @(Get-ShareInventory)
  if ($shares.Count -eq 0) { return @() }

  $nonDefault = @($shares | Where-Object { -not $script:DefaultShareNames.Contains($_.Name) })
  if ($nonDefault.Count -eq 0) { return @() }

  $readme = Get-ReadMeContent
  $allowed = @()
  if ($readme) {
    try {
      $allowed = @(Invoke-SharePlan -Shares $shares -ReadmeText $readme.Content)
    } catch {
      Write-Warn ("Failed to classify shares via OpenRouter: {0}" -f $_.Exception.Message)
    }
  }

  $removed = @()
  foreach ($share in $nonDefault) {
    if ($allowed -and ($allowed | Where-Object { $_ -and ($_ -eq $share.Name) })) {
      continue
    }
    if (Remove-SpecificShare -Name $share.Name) {
      $removed += $share.Name
    }
  }

  return @($removed)
}

function Ensure-ShareRestrictions {
  $changed = $false
  $script:LastRemovedShares = @()

  try {
    $removedShares = @(Remove-NonDefaultSharesWithAi)
    if ($removedShares.Count -gt 0) {
      $script:LastRemovedShares = $removedShares
      $changed = $true
    }
  } catch {
    Write-Warn ("Failed to audit SMB shares with AI: {0}" -f $_.Exception.Message)
  }

  if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
    try {
      $access = Get-SmbShareAccess -Name 'SYSVOL' -ErrorAction Stop | Where-Object { $_.AccountName -eq 'Everyone' }
      if ($access) {
        Revoke-SmbShareAccess -Name 'SYSVOL' -AccountName 'Everyone' -Force -Confirm:$false -ErrorAction Stop
        $changed = $true
      }
    } catch {}
  }

  return $changed
}

function Test-UnauthorizedShares {
  $shares = Get-ShareInventory
  if (-not $shares) { return $true }
  foreach ($share in $shares) {
    if ($script:DefaultShareNames.Contains($share.Name)) { continue }
    return $false
  }
  return $true
}

# ---- Driver: Apply / Verify --------------------------------------------------

function Apply-AllSettings {
  $changes = @()

  if (Disable-RemoteDesktopFeatures) { $changes += 'Disabled Remote Desktop/Assistance' }
  if (Disable-DesktopGadgets)       { $changes += 'Disabled desktop gadgets (legacy OS)' }
  if (Set-DepPolicy)                { $changes += 'Configured DEP for all programs' }
  if (Set-UacAdministratorEnumeration) { $changes += 'Disabled UAC administrator enumeration' }
  if (Ensure-ScreenSaverPolicy)     { $changes += 'Enforced secure screen saver' }
  if (Ensure-AutorunDisabled)       { $changes += 'Disabled AutoRun' }
  if (Ensure-AutoplayDisabled)      { $changes += 'Disabled AutoPlay' }
  if (Ensure-CoreDumpsDisabled)     { $changes += 'Disabled crash dumps' }
  if (Ensure-MemoryMitigations)     { $changes += 'Enabled ASLR mitigations' }
  if (Ensure-EarlyLaunchPolicy)     { $changes += 'Restricted ELAM driver loading' }
  if (Ensure-ValidateHeapIntegrity) { $changes += 'Enabled heap integrity validation' }
  if (Ensure-HeapMitigationOptions) { $changes += 'Updated mitigation options' }
  if (Ensure-IpSourceRoutingDisabled){ $changes += 'Disabled IP source routing' }
  if (Ensure-VbsMandatoryMode)      { $changes += 'Enabled VBS mandatory mode' }
  if (Ensure-MachineIdentityIsolation) { $changes += 'Enforced Machine Identity Isolation' }
  if (Ensure-DirectoryRestrictions) { $changes += 'Hardened directory ACLs' }
  if (Ensure-HomeDirectoryIsolation){ $changes += 'Isolated user home directories' }
  if (Ensure-ShareRestrictions)     { $changes += 'Updated share restrictions' }
  if (Ensure-PrinterDriverRestriction) { $changes += 'Limited printer driver installs to admins' }
  if (Ensure-LockScreenNotificationsDisabled) { $changes += 'Disabled lock screen notifications' }
  if (Ensure-WindowsStoreDisabled)  { $changes += 'Disabled Windows Store access' }
  if (Ensure-FipsAlgorithmsEnabled) { $changes += 'Enforced FIPS algorithms' }
  if (Ensure-SecureBootEnabled)     { $changes += 'Checked Secure Boot requirement' }

  if ($script:LastRemovedShares.Count -gt 0) {
    $changes += ("Removed non-default shares: {0}" -f ($script:LastRemovedShares -join ', '))
  }

  return $changes
}

function Test-Ready {
  param($Context)

  $apiKey = Get-OpenRouterApiKey
  if (-not $apiKey) {
    Write-Warn "OpenRouter API key missing; set `$env:$($script:ApiKeyEnvVar) to enable AI-assisted share review."
  }
  return $true
}

function Invoke-Apply {
  param($Context)

  $changes = Apply-AllSettings
  $message = if ($changes.Count -gt 0) { $changes -join '; ' } else { 'All settings already compliant.' }
  $status = 'Succeeded'
  return New-ModuleResult -Name $script:ModuleName -Status $status -Message $message
}

function Invoke-Verify {
  param($Context)

  $checks = @()
  $checks += "RDP=$(if (Test-RemoteDesktopDisabled) { 'Disabled' } else { 'NeedsAttention' })"
  $checks += "Gadgets=$(if (Test-DesktopGadgetsDisabled) { 'Disabled' } else { 'NeedsAttention' })"
  $checks += "DEP=$(if (Test-DepPolicy) { 'AlwaysOn' } else { 'NeedsAttention' })"
  $checks += "UACEnum=$(if (Test-UacAdministratorEnumeration) { 'Disabled' } else { 'NeedsAttention' })"
  $checks += "Screensaver=$(if (Test-ScreenSaverPolicy) { 'Enforced' } else { 'NeedsAttention' })"
  $checks += "AutoRun=$(if ((Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun') -eq 255) { 'Disabled' } else { 'NeedsAttention' })"
  $checks += "AutoPlay=$(if (Test-AutoplayDisabled) { 'Disabled' } else { 'NeedsAttention' })"
  $checks += "ASLR=$(if (Test-MemoryMitigations) { 'Enabled' } else { 'NeedsAttention' })"
  $checks += "ELAM=$(if (Test-EarlyLaunchPolicy) { 'Strict' } else { 'NeedsAttention' })"
  $checks += "HeapIntegrity=$(if (Test-ValidateHeapIntegrity) { 'Enabled' } else { 'NeedsAttention' })"
  $checks += "IPSourceRouting=$(if ((Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableIPSourceRouting') -eq 2) { 'Disabled' } else { 'NeedsAttention' })"
  $checks += "CrashDumps=$(if (Test-CoreDumpsDisabled) { 'Disabled' } else { 'NeedsAttention' })"
  $checks += "VBSMandatory=$(if (Test-VbsMandatoryMode) { 'Enabled' } else { 'NeedsAttention' })"
  $checks += "MachineIdentityIsolation=$(if (Test-MachineIdentityIsolation) { 'Enabled' } else { 'NeedsAttention' })"
  $checks += "Shares=$(if (Test-UnauthorizedShares) { 'Clean' } else { 'NeedsReview' })"
  $checks += "HomeDirs=$(if (Test-HomeDirectoryIsolation) { 'Isolated' } else { 'NeedsAttention' })"
  $checks += "PrinterDrivers=$(if (Test-PrinterDriverRestriction) { 'AdminOnly' } else { 'NeedsAttention' })"
  $checks += "LockScreenNotifications=$(if (Test-LockScreenNotificationsDisabled) { 'Hidden' } else { 'NeedsAttention' })"
  $checks += "WindowsStore=$(if (Test-WindowsStoreDisabled) { 'Prohibited' } else { 'NeedsAttention' })"
  $checks += "SecureBoot=$(if (Test-SecureBootEnabled) { 'Enabled' } else { 'NeedsAttention' })"
  $checks += "FIPS=$(if (Test-FipsAlgorithmsEnabled) { 'Enabled' } else { 'NeedsAttention' })"

  $status = if ($checks -match 'Needs') { 'NeedsAttention' } else { 'Succeeded' }
  return New-ModuleResult -Name $script:ModuleName -Status $status -Message ($checks -join '; ')
}

Export-ModuleMember -Function Test-Ready,Invoke-Apply,Invoke-Verify
