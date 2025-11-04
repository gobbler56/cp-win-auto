Set-StrictMode -Version Latest

if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

$script:ModuleName = 'SMBHardening'

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

# ---- SMB Server Hardening ----------------------------------------------------

function Enable-SmbServerQUIC {
  $changed = $false
  $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer'

  Write-Info 'Enabling SMB over QUIC (server)'
  $changed = (Ensure-RegistryValue -Path $path -Name 'EnableSMBQUIC' -Type 'DWord' -Value 1) -or $changed

  return $changed
}

function Set-SmbServerDialects {
  $changed = $false
  $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer'

  # SMB 3.1.1 = 0x00000311 (785 decimal)
  Write-Info 'Enforcing SMB 3.1.1 only (server) - minimum dialect'
  $changed = (Ensure-RegistryValue -Path $path -Name 'MinSmb2Dialect' -Type 'DWord' -Value 0x311) -or $changed

  Write-Info 'Enforcing SMB 3.1.1 only (server) - maximum dialect'
  $changed = (Ensure-RegistryValue -Path $path -Name 'MaxSmb2Dialect' -Type 'DWord' -Value 0x311) -or $changed

  return $changed
}

function Enable-SmbServerAuthRateLimiter {
  $changed = $false
  $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer'

  Write-Info 'Enabling SMB authentication rate limiter'
  $changed = (Ensure-RegistryValue -Path $path -Name 'EnableAuthRateLimiter' -Type 'DWord' -Value 1) -or $changed

  # 2000 ms delay (0x7D0)
  Write-Info 'Setting auth rate limiter delay to 2000 ms'
  $changed = (Ensure-RegistryValue -Path $path -Name 'AuthRateLimiterDelayInMs' -Type 'DWord' -Value 0x7D0) -or $changed

  return $changed
}

function Enable-SmbServerAuditing {
  $changed = $false
  $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer'

  Write-Info 'Enabling audit for clients without encryption support'
  $changed = (Ensure-RegistryValue -Path $path -Name 'AuditClientDoesNotSupportEncryption' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Enabling audit for clients without signing support'
  $changed = (Ensure-RegistryValue -Path $path -Name 'AuditClientDoesNotSupportSigning' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Enabling audit for insecure guest logon'
  $changed = (Ensure-RegistryValue -Path $path -Name 'AuditInsecureGuestLogon' -Type 'DWord' -Value 1) -or $changed

  return $changed
}

function Enable-SmbServerSigning {
  $changed = $false
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'

  Write-Info 'Requiring SMB signing (server)'
  $changed = (Ensure-RegistryValue -Path $path -Name 'RequireSecuritySignature' -Type 'DWord' -Value 1) -or $changed

  # EnableSecuritySignature is ignored on SMB2+, but harmless to set for legacy
  Write-Info 'Enabling SMB signing (server - legacy support)'
  $changed = (Ensure-RegistryValue -Path $path -Name 'EnableSecuritySignature' -Type 'DWord' -Value 1) -or $changed

  return $changed
}

function Disable-SmbServerV1 {
  $changed = $false
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'

  Write-Info 'Disabling SMBv1 (server)'
  $changed = (Ensure-RegistryValue -Path $path -Name 'SMB1' -Type 'DWord' -Value 0) -or $changed

  return $changed
}

# ---- SMB Client/Workstation Hardening ----------------------------------------

function Enable-SmbClientQUIC {
  $changed = $false
  $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'

  Write-Info 'Enabling SMB over QUIC (client)'
  $changed = (Ensure-RegistryValue -Path $path -Name 'EnableSMBQUIC' -Type 'DWord' -Value 1) -or $changed

  return $changed
}

function Block-SmbClientNTLM {
  $changed = $false
  $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'

  Write-Info 'Blocking NTLM over SMB (forcing Kerberos)'
  $changed = (Ensure-RegistryValue -Path $path -Name 'BlockNTLM' -Type 'DWord' -Value 1) -or $changed

  return $changed
}

function Set-SmbClientDialects {
  $changed = $false
  $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'

  # SMB 3.1.1 = 0x00000311 (785 decimal)
  Write-Info 'Enforcing SMB 3.1.1 only (client) - minimum dialect'
  $changed = (Ensure-RegistryValue -Path $path -Name 'MinSmb2Dialect' -Type 'DWord' -Value 0x311) -or $changed

  Write-Info 'Enforcing SMB 3.1.1 only (client) - maximum dialect'
  $changed = (Ensure-RegistryValue -Path $path -Name 'MaxSmb2Dialect' -Type 'DWord' -Value 0x311) -or $changed

  return $changed
}

function Enable-SmbClientEncryption {
  $changed = $false
  $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'

  Write-Info 'Requiring encryption for client connections'
  $changed = (Ensure-RegistryValue -Path $path -Name 'RequireEncryption' -Type 'DWord' -Value 1) -or $changed

  return $changed
}

function Disable-SmbClientInsecureGuest {
  $changed = $false
  $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'

  Write-Info 'Disabling insecure guest logons'
  $changed = (Ensure-RegistryValue -Path $path -Name 'AllowInsecureGuestAuth' -Type 'DWord' -Value 0) -or $changed

  return $changed
}

function Enable-SmbClientAuditing {
  $changed = $false
  $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'

  Write-Info 'Enabling audit for servers without encryption support'
  $changed = (Ensure-RegistryValue -Path $path -Name 'AuditServerDoesNotSupportEncryption' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Enabling audit for servers without signing support'
  $changed = (Ensure-RegistryValue -Path $path -Name 'AuditServerDoesNotSupportSigning' -Type 'DWord' -Value 1) -or $changed

  Write-Info 'Enabling audit for insecure guest logon'
  $changed = (Ensure-RegistryValue -Path $path -Name 'AuditInsecureGuestLogon' -Type 'DWord' -Value 1) -or $changed

  return $changed
}

function Enable-SmbClientSigning {
  $changed = $false
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'

  Write-Info 'Requiring SMB signing (client)'
  $changed = (Ensure-RegistryValue -Path $path -Name 'RequireSecuritySignature' -Type 'DWord' -Value 1) -or $changed

  # EnableSecuritySignature is ignored on SMB2+, but harmless to set for legacy
  Write-Info 'Enabling SMB signing (client - legacy support)'
  $changed = (Ensure-RegistryValue -Path $path -Name 'EnableSecuritySignature' -Type 'DWord' -Value 1) -or $changed

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

    # Server hardening
    if (Enable-SmbServerQUIC) { $changes += 'Enabled SMB over QUIC (server)' }
    if (Set-SmbServerDialects) { $changes += 'Enforced SMB 3.1.1 only (server)' }
    if (Enable-SmbServerAuthRateLimiter) { $changes += 'Enabled authentication rate limiter' }
    if (Enable-SmbServerAuditing) { $changes += 'Enabled server auditing' }
    if (Enable-SmbServerSigning) { $changes += 'Required SMB signing (server)' }
    if (Disable-SmbServerV1) { $changes += 'Disabled SMBv1 (server)' }

    # Client hardening
    if (Enable-SmbClientQUIC) { $changes += 'Enabled SMB over QUIC (client)' }
    if (Block-SmbClientNTLM) { $changes += 'Blocked NTLM over SMB (client)' }
    if (Set-SmbClientDialects) { $changes += 'Enforced SMB 3.1.1 only (client)' }
    if (Enable-SmbClientEncryption) { $changes += 'Required encryption (client)' }
    if (Disable-SmbClientInsecureGuest) { $changes += 'Disabled insecure guest auth (client)' }
    if (Enable-SmbClientAuditing) { $changes += 'Enabled client auditing' }
    if (Enable-SmbClientSigning) { $changes += 'Required SMB signing (client)' }

    $message = if ($changes.Count -gt 0) {
      'SMB hardening applied: ' + ($changes -join '; ')
    } else {
      'All SMB hardening settings already in place'
    }

    Write-Info 'NOTE: Some changes may require restarting the SMB services or a reboot'
    Write-Info 'To apply immediately, run: net stop lanmanserver /y & net start lanmanserver'
    Write-Info 'NOTE: SMBv1 has been disabled. To fully remove the feature, run: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'

    return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message $message)
  } catch {
    Write-Err ("SMB hardening failed: {0}" -f $_.Exception.Message)
    return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message ('SMB hardening error: ' + $_.Exception.Message))
  }
}

function Invoke-Verify {
  param($Context)

  $checks = @()

  # Server checks
  $smbQuicServer = (Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer' -Name 'EnableSMBQUIC') -eq 1
  $checks += "ServerQUIC=$(if ($smbQuicServer) { 'Enabled' } else { 'Disabled' })"

  $minDialectServer = (Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer' -Name 'MinSmb2Dialect')
  $checks += "ServerMinDialect=$(if ($minDialectServer -eq 0x311) { 'SMB3.1.1' } else { 'Weak' })"

  $authRateLimiter = (Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer' -Name 'EnableAuthRateLimiter') -eq 1
  $checks += "AuthRateLimiter=$(if ($authRateLimiter) { 'Enabled' } else { 'Disabled' })"

  $serverSigning = (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature') -eq 1
  $checks += "ServerSigning=$(if ($serverSigning) { 'Required' } else { 'NotRequired' })"

  $smb1Disabled = (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1') -eq 0
  $checks += "SMBv1=$(if ($smb1Disabled) { 'Disabled' } else { 'Enabled' })"

  # Client checks
  $smbQuicClient = (Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'EnableSMBQUIC') -eq 1
  $checks += "ClientQUIC=$(if ($smbQuicClient) { 'Enabled' } else { 'Disabled' })"

  $ntlmBlocked = (Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'BlockNTLM') -eq 1
  $checks += "BlockNTLM=$(if ($ntlmBlocked) { 'Blocked' } else { 'Allowed' })"

  $minDialectClient = (Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'MinSmb2Dialect')
  $checks += "ClientMinDialect=$(if ($minDialectClient -eq 0x311) { 'SMB3.1.1' } else { 'Weak' })"

  $clientEncryption = (Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'RequireEncryption') -eq 1
  $checks += "ClientEncryption=$(if ($clientEncryption) { 'Required' } else { 'NotRequired' })"

  $insecureGuestDisabled = (Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'AllowInsecureGuestAuth') -eq 0
  $checks += "InsecureGuest=$(if ($insecureGuestDisabled) { 'Disabled' } else { 'Enabled' })"

  $clientSigning = (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature') -eq 1
  $checks += "ClientSigning=$(if ($clientSigning) { 'Required' } else { 'NotRequired' })"

  # Determine overall status
  $status = if ($checks -match 'Disabled|Weak|NotRequired|Allowed|Enabled' -and
                $checks -notmatch 'ServerQUIC=Enabled|ClientQUIC=Enabled|AuthRateLimiter=Enabled') {
    'NeedsAttention'
  } else {
    'Succeeded'
  }

  return (New-ModuleResult -Name $script:ModuleName -Status $status -Message ($checks -join '; '))
}

Export-ModuleMember -Function Test-Ready,Invoke-Verify,Invoke-Apply
