Set-StrictMode -Version Latest

if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

$script:ModuleName = 'RDPHardening'

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

# ---- Enable RDP + Single Session Per User ------------------------------------

function Enable-RdpWithSingleSession {
  $changed = $false

  # Enable RDP (fDenyTSConnections = 0)
  Write-Info 'Enabling Remote Desktop Protocol'
  $changed = (Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Type 'DWord' -Value 0) -or $changed

  # Single session per user
  Write-Info 'Enforcing single session per user'
  $changed = (Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fSingleSessionPerUser' -Type 'DWord' -Value 1) -or $changed

  return $changed
}

# ---- Require NLA, Force TLS Security Layer, Strong Encryption ----------------

function Set-RdpSecuritySettings {
  $changed = $false
  $rdpTcpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

  # Require Network Level Authentication
  Write-Info 'Requiring Network Level Authentication (NLA)'
  $changed = (Ensure-RegistryValue -Path $rdpTcpPath -Name 'UserAuthentication' -Type 'DWord' -Value 1) -or $changed

  # Force TLS security layer (2 = TLS)
  Write-Info 'Setting security layer to TLS'
  $changed = (Ensure-RegistryValue -Path $rdpTcpPath -Name 'SecurityLayer' -Type 'DWord' -Value 2) -or $changed

  # High encryption level (3 = 128-bit)
  Write-Info 'Setting minimum encryption level to High (128-bit)'
  $changed = (Ensure-RegistryValue -Path $rdpTcpPath -Name 'MinEncryptionLevel' -Type 'DWord' -Value 3) -or $changed

  return $changed
}

# ---- Block All Client Redirection & Password Caching ------------------------

function Block-RdpClientRedirection {
  $changed = $false
  $tsPoliciesPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

  Write-Info 'Blocking drive redirection'
  $changed = (Ensure-RegistryValue -Path $tsPoliciesPath -Name 'fDisableCdm' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Blocking printer redirection'
  $changed = (Ensure-RegistryValue -Path $tsPoliciesPath -Name 'fDisableCpm' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Blocking COM port redirection'
  $changed = (Ensure-RegistryValue -Path $tsPoliciesPath -Name 'fDisableCcm' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Blocking LPT port redirection'
  $changed = (Ensure-RegistryValue -Path $tsPoliciesPath -Name 'fDisableLPT' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Blocking PnP device/USB redirection'
  $changed = (Ensure-RegistryValue -Path $tsPoliciesPath -Name 'fDisablePNPRedir' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Blocking clipboard redirection'
  $changed = (Ensure-RegistryValue -Path $tsPoliciesPath -Name 'DisableClipboardRedirection' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Disabling password saving'
  $changed = (Ensure-RegistryValue -Path $tsPoliciesPath -Name 'DisablePasswordSaving' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Requiring password prompt on connection'
  $changed = (Ensure-RegistryValue -Path $tsPoliciesPath -Name 'fPromptForPassword' -Type 'DWord' -Value 1) -or $changed

  return $changed
}

# ---- Session Limits (Aggressive) ---------------------------------------------

function Set-RdpSessionLimits {
  $changed = $false
  $tsPoliciesPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

  # 15 minutes = 900000 milliseconds
  Write-Info 'Setting maximum idle time to 15 minutes'
  $changed = (Ensure-RegistryValue -Path $tsPoliciesPath -Name 'MaxIdleTime' -Type 'DWord' -Value 900000) -or $changed

  Write-Info 'Setting maximum disconnection time to 15 minutes'
  $changed = (Ensure-RegistryValue -Path $tsPoliciesPath -Name 'MaxDisconnectionTime' -Type 'DWord' -Value 900000) -or $changed

  Write-Info 'Ending session when time limit is reached'
  $changed = (Ensure-RegistryValue -Path $tsPoliciesPath -Name 'fResetBroken' -Type 'DWord' -Value 1) -or $changed

  return $changed
}

# ---- Disable Remote Assistance -----------------------------------------------

function Disable-RemoteAssistance {
  $changed = $false
  $tsPoliciesPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

  Write-Info 'Disabling solicited Remote Assistance'
  $changed = (Ensure-RegistryValue -Path $tsPoliciesPath -Name 'fAllowToGetHelp' -Type 'DWord' -Value 0) -or $changed

  Write-Info 'Disabling unsolicited Remote Assistance'
  $changed = (Ensure-RegistryValue -Path $tsPoliciesPath -Name 'fAllowUnsolicited' -Type 'DWord' -Value 0) -or $changed

  Write-Info 'Disabling unsolicited full control Remote Assistance'
  $changed = (Ensure-RegistryValue -Path $tsPoliciesPath -Name 'fAllowUnsolicitedFullControl' -Type 'DWord' -Value 0) -or $changed

  return $changed
}

# ---- TLS/SCHANNEL Hardening (Server Side) ------------------------------------

function Set-SchannelProtocols {
  $changed = $false
  $schannelBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

  # Disable old/weak protocols
  $oldProtocols = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')
  foreach ($protocol in $oldProtocols) {
    Write-Info "Disabling protocol: $protocol"
    $serverPath = Join-Path $schannelBase "$protocol\Server"
    $changed = (Ensure-RegistryValue -Path $serverPath -Name 'Enabled' -Type 'DWord' -Value 0) -or $changed
    $changed = (Ensure-RegistryValue -Path $serverPath -Name 'DisabledByDefault' -Type 'DWord' -Value 1) -or $changed
  }

  # Enable modern protocols
  Write-Info 'Enabling TLS 1.2'
  $tls12Path = Join-Path $schannelBase 'TLS 1.2\Server'
  $changed = (Ensure-RegistryValue -Path $tls12Path -Name 'Enabled' -Type 'DWord' -Value 1) -or $changed
  $changed = (Ensure-RegistryValue -Path $tls12Path -Name 'DisabledByDefault' -Type 'DWord' -Value 0) -or $changed

  # TLS 1.3 (optional, if supported)
  Write-Info 'Enabling TLS 1.3 (if supported)'
  $tls13Path = Join-Path $schannelBase 'TLS 1.3\Server'
  $changed = (Ensure-RegistryValue -Path $tls13Path -Name 'Enabled' -Type 'DWord' -Value 1) -or $changed
  $changed = (Ensure-RegistryValue -Path $tls13Path -Name 'DisabledByDefault' -Type 'DWord' -Value 0) -or $changed

  return $changed
}

function Disable-WeakCiphers {
  $changed = $false
  $cipherBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'

  # List of weak ciphers to disable
  $weakCiphers = @(
    'RC4 128/128',
    'RC4 56/128',
    'RC4 40/128',
    'Triple DES 168/168',
    'DES 56/56',
    'NULL'
  )

  foreach ($cipher in $weakCiphers) {
    Write-Info "Disabling weak cipher: $cipher"
    $cipherPath = Join-Path $cipherBase $cipher
    $changed = (Ensure-RegistryValue -Path $cipherPath -Name 'Enabled' -Type 'DWord' -Value 0) -or $changed
  }

  return $changed
}

# ---- CredSSP: Encryption Oracle Locked Down ----------------------------------

function Set-CredsspEncryptionOracle {
  $changed = $false
  $credsspPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'

  Write-Info 'Setting CredSSP Encryption Oracle to Force Updated Clients (strictest)'
  $changed = (Ensure-RegistryValue -Path $credsspPath -Name 'AllowEncryptionOracle' -Type 'DWord' -Value 2) -or $changed

  return $changed
}

# ---- Core LSA/Auth Hardening That Impacts RDP --------------------------------

function Set-LsaAuthHardening {
  $changed = $false
  $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

  Write-Info 'Setting LM compatibility level to 5 (NTLMv2 only)'
  $changed = (Ensure-RegistryValue -Path $lsaPath -Name 'LmCompatibilityLevel' -Type 'DWord' -Value 5) -or $changed

  Write-Info 'Preventing storage of LM hash'
  $changed = (Ensure-RegistryValue -Path $lsaPath -Name 'NoLMHash' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Limiting blank password use to console only'
  $changed = (Ensure-RegistryValue -Path $lsaPath -Name 'LimitBlankPasswordUse' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Restricting anonymous access'
  $changed = (Ensure-RegistryValue -Path $lsaPath -Name 'RestrictAnonymous' -Type 'DWord' -Value 2) -or $changed
  $changed = (Ensure-RegistryValue -Path $lsaPath -Name 'RestrictAnonymousSAM' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Disabling Restricted Admin RDP mode'
  $changed = (Ensure-RegistryValue -Path $lsaPath -Name 'DisableRestrictedAdmin' -Type 'DWord' -Value 1) -or $changed

  # Optional but strong: LSA Protection (RunAsPPL)
  Write-Info 'Enabling LSA Protection (RunAsPPL - optional but recommended)'
  $changed = (Ensure-RegistryValue -Path $lsaPath -Name 'RunAsPPL' -Type 'DWord' -Value 1) -or $changed

  return $changed
}

# ---- Main Apply/Verify Functions ---------------------------------------------

function Test-Ready {
  param($Context)

  # No special prerequisites needed - just registry access
  return $true
}

function Invoke-Apply {
  param($Context)

  try {
    $changes = @()

    if (Enable-RdpWithSingleSession) { $changes += 'Enabled RDP with single session enforcement' }
    if (Set-RdpSecuritySettings) { $changes += 'Configured NLA, TLS, and high encryption' }
    if (Block-RdpClientRedirection) { $changes += 'Blocked all client device/resource redirection' }
    if (Set-RdpSessionLimits) { $changes += 'Set aggressive session timeout limits' }
    if (Disable-RemoteAssistance) { $changes += 'Disabled Remote Assistance' }
    if (Set-SchannelProtocols) { $changes += 'Hardened TLS/SCHANNEL protocols' }
    if (Disable-WeakCiphers) { $changes += 'Disabled weak ciphers' }
    if (Set-CredsspEncryptionOracle) { $changes += 'Locked down CredSSP encryption oracle' }
    if (Set-LsaAuthHardening) { $changes += 'Applied LSA/auth hardening' }

    $message = if ($changes.Count -gt 0) {
      'RDP hardening applied: ' + ($changes -join '; ')
    } else {
      'All RDP hardening settings already in place'
    }

    Write-Info 'NOTE: Some SCHANNEL and LSA changes require a reboot to fully apply'

    return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message $message)
  } catch {
    Write-Err ("RDP hardening failed: {0}" -f $_.Exception.Message)
    return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message ('RDP hardening error: ' + $_.Exception.Message))
  }
}

function Invoke-Verify {
  param($Context)

  $checks = @()

  # Check RDP is enabled
  $rdpEnabled = (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections') -eq 0
  $checks += "RDP=$(if ($rdpEnabled) { 'Enabled' } else { 'Disabled' })"

  # Check NLA is required
  $nlaRequired = (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication') -eq 1
  $checks += "NLA=$(if ($nlaRequired) { 'Required' } else { 'NotRequired' })"

  # Check TLS security layer
  $tlsLayer = (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer') -eq 2
  $checks += "TLS=$(if ($tlsLayer) { 'Enforced' } else { 'NotEnforced' })"

  # Check encryption level
  $highEncryption = (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel') -eq 3
  $checks += "Encryption=$(if ($highEncryption) { 'High' } else { 'Weak' })"

  # Check client redirection blocked
  $redirectionBlocked = (Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCdm') -eq 1
  $checks += "ClientRedirection=$(if ($redirectionBlocked) { 'Blocked' } else { 'Allowed' })"

  # Check Remote Assistance disabled
  $raDisabled = (Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fAllowToGetHelp') -eq 0
  $checks += "RemoteAssistance=$(if ($raDisabled) { 'Disabled' } else { 'Enabled' })"

  # Check TLS 1.2 enabled
  $tls12Enabled = (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled') -eq 1
  $checks += "TLS1.2=$(if ($tls12Enabled) { 'Enabled' } else { 'Disabled' })"

  # Check weak ciphers disabled
  $rc4Disabled = (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' -Name 'Enabled') -eq 0
  $checks += "WeakCiphers=$(if ($rc4Disabled) { 'Disabled' } else { 'Enabled' })"

  # Check CredSSP hardening
  $credsspHardened = (Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' -Name 'AllowEncryptionOracle') -eq 2
  $checks += "CredSSP=$(if ($credsspHardened) { 'Hardened' } else { 'Weak' })"

  # Check LSA hardening
  $lsaHardened = (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel') -eq 5
  $checks += "LSA=$(if ($lsaHardened) { 'Hardened' } else { 'Weak' })"

  $status = if ($checks -match 'Disabled|NotRequired|NotEnforced|Weak|Allowed|Enabled' -and $checks -notmatch 'RDP=Enabled') {
    'NeedsAttention'
  } else {
    'Succeeded'
  }

  return (New-ModuleResult -Name $script:ModuleName -Status $status -Message ($checks -join '; '))
}

Export-ModuleMember -Function Test-Ready,Invoke-Verify,Invoke-Apply
