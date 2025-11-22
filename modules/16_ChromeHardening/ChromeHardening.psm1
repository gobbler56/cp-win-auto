Set-StrictMode -Version Latest

if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

$script:ModuleName = 'ChromeHardening'
$script:ChromePolicyRoot = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
$script:DoHTemplate = 'https://dns.google/dns-query'

# ---- Helper Functions --------------------------------------------------------

function Ensure-RegistryValue {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('String','ExpandString','MultiString','Binary','DWord','QWord')][string]$Type,
    [Parameter(Mandatory)][object]$Value
  )

  try {
    if (-not (Test-Path -LiteralPath $Path)) {
      New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
    }

    if ($Type -eq 'DWord') { $Value = [int]$Value }
    elseif ($Type -eq 'QWord') { $Value = [long]$Value }

    New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
    return $true
  } catch {
    Write-Warn ("Failed to set {0}\{1}: {2}" -f $Path, $Name, $_.Exception.Message)
    return $false
  }
}

function Get-RegistryValueSafe {
  param([string]$Path, [string]$Name)

  try {
    return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
  } catch {
    return $null
  }
}

function Set-ChromeListPolicy {
  param(
    [Parameter(Mandatory)][string]$PolicyName,
    [Parameter(Mandatory)][string[]]$Values
  )

  try {
    $policyPath = Join-Path $script:ChromePolicyRoot $PolicyName

    # Create the policy subkey
    if (-not (Test-Path -LiteralPath $policyPath)) {
      New-Item -Path $policyPath -Force -ErrorAction Stop | Out-Null
    }

    # Clear existing numbered values
    if (Test-Path -LiteralPath $policyPath) {
      $props = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue
      if ($props) {
        $props.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object {
          Remove-ItemProperty -Path $policyPath -Name $_.Name -ErrorAction SilentlyContinue
        }
      }
    }

    # Add numbered values (starting from 1)
    $index = 1
    foreach ($value in $Values) {
      New-ItemProperty -Path $policyPath -Name "$index" -PropertyType String -Value $value -Force | Out-Null
      $index++
    }

    return $true
  } catch {
    Write-Warn ("Failed to set list policy {0}: {1}" -f $PolicyName, $_.Exception.Message)
    return $false
  }
}

function Set-ChromeJsonPolicy {
  param(
    [Parameter(Mandatory)][string]$PolicyName,
    [Parameter(Mandatory)][object]$PolicyObject
  )

  try {
    $jsonValue = ($PolicyObject | ConvertTo-Json -Depth 10 -Compress)
    return (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name $PolicyName -Type 'String' -Value $jsonValue)
  } catch {
    Write-Warn ("Failed to set JSON policy {0}: {1}" -f $PolicyName, $_.Exception.Message)
    return $false
  }
}

# ---- Core Privacy & Security Settings ----------------------------------------

function Set-ChromePrivacySettings {
  $changed = $false

  Write-Info 'Blocking third-party cookies'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'BlockThirdPartyCookies' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Enabling Enhanced Safe Browsing'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'SafeBrowsingProtectionLevel' -Type 'DWord' -Value 2) -or $changed

  Write-Info 'Disabling cloud spellcheck'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'SpellCheckServiceEnabled' -Type 'DWord' -Value 0) -or $changed

  Write-Info 'Disabling built-in password manager'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'PasswordManagerEnabled' -Type 'DWord' -Value 0) -or $changed

  Write-Info 'Disabling Chrome Sync'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'SyncDisabled' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Disabling Chrome browser sign-in'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'BrowserSignin' -Type 'DWord' -Value 0) -or $changed

  Write-Info 'Disallowing SSL error bypass'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'SSLErrorOverrideAllowed' -Type 'DWord' -Value 0) -or $changed

  return $changed
}

# ---- Disable Unsafe Features -------------------------------------------------

function Disable-ChromeUnsafeFeatures {
  $changed = $false

  Write-Info 'Disabling Developer Tools'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'DeveloperToolsDisabled' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Disabling Incognito mode'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'IncognitoModeAvailability' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Disabling Guest mode'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'BrowserGuestModeEnabled' -Type 'DWord' -Value 0) -or $changed

  return $changed
}

# ---- Site Permissions & Prompts ----------------------------------------------

function Set-ChromePermissionDefaults {
  $changed = $false

  Write-Info 'Blocking pop-ups by default'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'DefaultPopupsSetting' -Type 'DWord' -Value 2) -or $changed

  Write-Info 'Blocking notifications by default'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'DefaultNotificationsSetting' -Type 'DWord' -Value 2) -or $changed

  Write-Info 'Blocking geolocation by default'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'DefaultGeolocationSetting' -Type 'DWord' -Value 2) -or $changed

  Write-Info 'Blocking camera access by default'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'DefaultMediaStreamSetting' -Type 'DWord' -Value 2) -or $changed

  Write-Info 'Blocking microphone access by default'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'AudioCaptureAllowed' -Type 'DWord' -Value 0) -or $changed
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'VideoCaptureAllowed' -Type 'DWord' -Value 0) -or $changed

  Write-Info 'Blocking clipboard access by default'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'DefaultClipboardSetting' -Type 'DWord' -Value 2) -or $changed

  Write-Info 'Blocking automatic downloads'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'DefaultDownloadsSetting' -Type 'DWord' -Value 2) -or $changed

  Write-Info 'Blocking USB device access (WebUSB)'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'DefaultWebUsbGuardSetting' -Type 'DWord' -Value 2) -or $changed

  Write-Info 'Blocking serial port access (Web Serial)'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'DefaultSerialGuardSetting' -Type 'DWord' -Value 2) -or $changed

  Write-Info 'Blocking HID device access (WebHID)'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'DefaultWebHidGuardSetting' -Type 'DWord' -Value 2) -or $changed

  Write-Info 'Blocking Bluetooth access (Web Bluetooth)'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'DefaultWebBluetoothGuardSetting' -Type 'DWord' -Value 2) -or $changed

  return $changed
}

# ---- Download & Extension Restrictions ---------------------------------------

function Set-ChromeDownloadRestrictions {
  $changed = $false

  # DownloadRestrictions: 0=none, 1=block dangerous, 2=block dangerous+potentially unwanted, 3=block all, 4=malicious only
  Write-Info 'Setting strict download restrictions (block dangerous and potentially unwanted files)'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'DownloadRestrictions' -Type 'DWord' -Value 2) -or $changed

  return $changed
}

function Block-ChromeExtensions {
  $changed = $false

  Write-Info 'Blocking all extensions via ExtensionInstallBlocklist'
  $changed = (Set-ChromeListPolicy -PolicyName 'ExtensionInstallBlocklist' -Values @('*')) -or $changed

  Write-Info 'Setting empty ExtensionInstallAllowlist'
  $changed = (Set-ChromeListPolicy -PolicyName 'ExtensionInstallAllowlist' -Values @()) -or $changed

  Write-Info 'Clearing extension force install list'
  $changed = (Set-ChromeListPolicy -PolicyName 'ExtensionInstallForcelist' -Values @()) -or $changed

  Write-Info 'Blocking external extensions'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'BlockExternalExtensions' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Configuring ExtensionSettings to block all installations'
  $extSettings = @{
    '*' = @{
      installation_mode = 'blocked'
      blocked_install_message = 'Extensions are disabled on this system for security.'
    }
  }
  $changed = (Set-ChromeJsonPolicy -PolicyName 'ExtensionSettings' -PolicyObject $extSettings) -or $changed

  return $changed
}

function Clear-ChromeSiteExceptions {
  $changed = $false

  Write-Info 'Clearing site-specific permission allowlists'
  $policyLists = @(
    'CookiesAllowedForUrls',
    'CookiesSessionOnlyForUrls',
    'PopupsAllowedForUrls',
    'NotificationsAllowedForUrls',
    'GeolocationAllowedForUrls',
    'VideoCaptureAllowedUrls',
    'AudioCaptureAllowedUrls'
  )

  foreach ($policy in $policyLists) {
    $changed = (Set-ChromeListPolicy -PolicyName $policy -Values @()) -or $changed
  }

  return $changed
}

# ---- Data Clearing Policies --------------------------------------------------

function Set-ChromeDataClearing {
  $changed = $false

  Write-Info 'Configuring data to clear on browser exit'
  $clearOnExitTypes = @(
    'browsing_history',
    'download_history',
    'cookies_and_other_site_data',
    'cached_images_and_files',
    'password_signin',
    'autofill',
    'site_settings',
    'hosted_app_data'
  )
  $changed = (Set-ChromeListPolicy -PolicyName 'ClearBrowsingDataOnExitList' -Values $clearOnExitTypes) -or $changed

  Write-Info 'Setting browsing data lifetime policies'
  $lifetimePolicy = @{
    data_types = @(
      @{ data_type = 'browsing_history'; time_to_live_in_hours = 1 },
      @{ data_type = 'cookies_and_other_site_data'; time_to_live_in_hours = 1 },
      @{ data_type = 'cached_images_and_files'; time_to_live_in_hours = 1 }
    )
  }
  $changed = (Set-ChromeJsonPolicy -PolicyName 'BrowsingDataLifetime' -PolicyObject $lifetimePolicy) -or $changed

  return $changed
}

# ---- Secure DNS (DNS-over-HTTPS) ---------------------------------------------

function Set-ChromeSecureDns {
  $changed = $false

  Write-Info 'Enabling DNS-over-HTTPS (DoH) in secure mode'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'DnsOverHttpsMode' -Type 'String' -Value 'secure') -or $changed

  Write-Info "Setting DoH template to $script:DoHTemplate"
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'DnsOverHttpsTemplates' -Type 'String' -Value $script:DoHTemplate) -or $changed

  Write-Info 'Enabling built-in DNS client'
  $changed = (Ensure-RegistryValue -Path $script:ChromePolicyRoot -Name 'BuiltInDnsClientEnabled' -Type 'DWord' -Value 1) -or $changed

  return $changed
}

# ---- Main Apply/Verify Functions ---------------------------------------------

function Test-Ready {
  param($Context)

  # Check if Chrome policy registry path can be created
  # No special prerequisites - just need registry access
  return $true
}

function Invoke-Apply {
  param($Context)

  try {
    # Ensure the Chrome policy root exists
    if (-not (Test-Path -LiteralPath $script:ChromePolicyRoot)) {
      New-Item -Path $script:ChromePolicyRoot -Force | Out-Null
    }

    $changes = @()

    if (Set-ChromePrivacySettings) { $changes += 'Applied privacy and security settings' }
    if (Disable-ChromeUnsafeFeatures) { $changes += 'Disabled unsafe features (DevTools, Incognito, Guest mode)' }
    if (Set-ChromePermissionDefaults) { $changes += 'Set restrictive site permission defaults' }
    if (Clear-ChromeSiteExceptions) { $changes += 'Cleared site-specific exceptions' }
    if (Set-ChromeDownloadRestrictions) { $changes += 'Configured download restrictions' }
    if (Block-ChromeExtensions) { $changes += 'Blocked all extensions' }
    if (Set-ChromeDataClearing) { $changes += 'Configured data clearing policies' }
    if (Set-ChromeSecureDns) { $changes += 'Enabled DNS-over-HTTPS' }

    $message = if ($changes.Count -gt 0) {
      'Chrome hardening applied: ' + ($changes -join '; ')
    } else {
      'All Chrome hardening settings already in place'
    }

    Write-Info 'Chrome users should restart their browsers for policies to take full effect'
    Write-Info 'Users can verify policies at chrome://policy'

    return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message $message)
  } catch {
    Write-Err ("Chrome hardening failed: {0}" -f $_.Exception.Message)
    return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message ('Chrome hardening error: ' + $_.Exception.Message))
  }
}

function Invoke-Verify {
  param($Context)

  $checks = @()

  # Check privacy settings
  $safeBrowsing = (Get-RegistryValueSafe -Path $script:ChromePolicyRoot -Name 'SafeBrowsingProtectionLevel') -eq 2
  $checks += "SafeBrowsing=$(if ($safeBrowsing) { 'Enhanced' } else { 'Weak' })"

  $block3rdCookies = (Get-RegistryValueSafe -Path $script:ChromePolicyRoot -Name 'BlockThirdPartyCookies') -eq 1
  $checks += "ThirdPartyCookies=$(if ($block3rdCookies) { 'Blocked' } else { 'Allowed' })"

  $syncDisabled = (Get-RegistryValueSafe -Path $script:ChromePolicyRoot -Name 'SyncDisabled') -eq 1
  $checks += "Sync=$(if ($syncDisabled) { 'Disabled' } else { 'Enabled' })"

  # Check unsafe features disabled
  $devToolsDisabled = (Get-RegistryValueSafe -Path $script:ChromePolicyRoot -Name 'DeveloperToolsDisabled') -eq 1
  $checks += "DevTools=$(if ($devToolsDisabled) { 'Blocked' } else { 'Allowed' })"

  $incognitoDisabled = (Get-RegistryValueSafe -Path $script:ChromePolicyRoot -Name 'IncognitoModeAvailability') -eq 1
  $checks += "Incognito=$(if ($incognitoDisabled) { 'Disabled' } else { 'Enabled' })"

  # Check permissions
  $popupsBlocked = (Get-RegistryValueSafe -Path $script:ChromePolicyRoot -Name 'DefaultPopupsSetting') -eq 2
  $checks += "Popups=$(if ($popupsBlocked) { 'Blocked' } else { 'Allowed' })"

  $notificationsBlocked = (Get-RegistryValueSafe -Path $script:ChromePolicyRoot -Name 'DefaultNotificationsSetting') -eq 2
  $checks += "Notifications=$(if ($notificationsBlocked) { 'Blocked' } else { 'Allowed' })"

  $geoBlocked = (Get-RegistryValueSafe -Path $script:ChromePolicyRoot -Name 'DefaultGeolocationSetting') -eq 2
  $checks += "Geolocation=$(if ($geoBlocked) { 'Blocked' } else { 'Allowed' })"

  # Check extensions
  $extBlocklistPath = Join-Path $script:ChromePolicyRoot 'ExtensionInstallBlocklist'
  $extBlocked = $false
  if (Test-Path -LiteralPath $extBlocklistPath) {
    $blocklistValue = Get-RegistryValueSafe -Path $extBlocklistPath -Name '1'
    $extBlocked = ($blocklistValue -eq '*')
  }
  $checks += "Extensions=$(if ($extBlocked) { 'Blocked' } else { 'Allowed' })"

  $extForceListPath = Join-Path $script:ChromePolicyRoot 'ExtensionInstallForcelist'
  $forceListPresent = (Test-Path -LiteralPath $extForceListPath) -and ((Get-Item $extForceListPath).Property.Count -gt 0)
  $checks += "ExtensionForcelist=$(if (-not $forceListPresent) { 'Cleared' } else { 'Present' })"

  # Check download restrictions
  $dlRestrictions = Get-RegistryValueSafe -Path $script:ChromePolicyRoot -Name 'DownloadRestrictions'
  $dlRestricted = ($dlRestrictions -ge 2)
  $checks += "Downloads=$(if ($dlRestricted) { 'Restricted' } else { 'Unrestricted' })"

  # Check DoH
  $dohMode = Get-RegistryValueSafe -Path $script:ChromePolicyRoot -Name 'DnsOverHttpsMode'
  $dohEnabled = ($dohMode -eq 'secure')
  $checks += "DoH=$(if ($dohEnabled) { 'Enabled' } else { 'Disabled' })"

  # Check data clearing
  $clearOnExitPath = Join-Path $script:ChromePolicyRoot 'ClearBrowsingDataOnExitList'
  $clearConfigured = (Test-Path -LiteralPath $clearOnExitPath) -and ((Get-Item $clearOnExitPath).Property.Count -gt 0)
  $checks += "ClearOnExit=$(if ($clearConfigured) { 'Configured' } else { 'NotConfigured' })"

  $exceptionPolicies = @(
    'CookiesAllowedForUrls',
    'CookiesSessionOnlyForUrls',
    'PopupsAllowedForUrls',
    'NotificationsAllowedForUrls',
    'GeolocationAllowedForUrls',
    'VideoCaptureAllowedUrls',
    'AudioCaptureAllowedUrls'
  )
  $exceptionsCleared = $true
  foreach ($policy in $exceptionPolicies) {
    $policyPath = Join-Path $script:ChromePolicyRoot $policy
    if ((Test-Path -LiteralPath $policyPath) -and ((Get-Item $policyPath).Property.Count -gt 0)) {
      $exceptionsCleared = $false
      break
    }
  }
  $checks += "SiteExceptions=$(if ($exceptionsCleared) { 'Cleared' } else { 'Present' })"

  # Determine status based on checks
  $status = if ($checks -match 'Weak|Allowed|Enabled|Unrestricted|NotConfigured|Present' -and $checks -notmatch 'DoH=Enabled|SafeBrowsing=Enhanced') {
    'NeedsAttention'
  } else {
    'Succeeded'
  }

  return (New-ModuleResult -Name $script:ModuleName -Status $status -Message ($checks -join '; '))
}

Export-ModuleMember -Function Test-Ready,Invoke-Verify,Invoke-Apply
