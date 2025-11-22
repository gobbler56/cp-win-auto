Set-StrictMode -Version Latest

if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

$script:ModuleName    = 'Defensive'
$script:FirewallUrl   = 'https://storage.googleapis.com/sigma.00.edu.ci/dextro-firewall.wfw'
$script:FirewallRoot  = 'C:\\firewall'
$script:FirewallFile  = Join-Path $script:FirewallRoot 'firewall.wfw'

function Test-Ready {
  param($Context)

  if (-not (Get-Command 'netsh.exe' -ErrorAction SilentlyContinue)) {
    Write-Warn 'netsh.exe is not available; firewall import cannot run.'
    return $false
  }
  return $true
}

function Invoke-DownloadFirewallProfile {
  if (-not (Test-Path $script:FirewallRoot)) {
    Write-Info ("Creating firewall workspace at {0}" -f $script:FirewallRoot)
    New-Item -ItemType Directory -Path $script:FirewallRoot -Force | Out-Null
  }

  Write-Info 'Downloading firewall policy definition'
  $prev = $ProgressPreference
  try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $script:FirewallUrl -OutFile $script:FirewallFile -UseBasicParsing -ErrorAction Stop
  } finally {
    $ProgressPreference = $prev
  }
}

function Invoke-ImportFirewallProfile {
  if (-not (Test-Path $script:FirewallFile)) {
    throw 'Firewall configuration file not found after download.'
  }

  Write-Info 'Importing firewall profile using netsh'
  $args = @('advfirewall', 'import', $script:FirewallFile)
  $proc = Start-Process -FilePath 'netsh.exe' -ArgumentList $args -Wait -PassThru -NoNewWindow
  if ($proc.ExitCode -ne 0) {
    throw ("netsh advfirewall import failed with exit code {0}" -f $proc.ExitCode)
  }
}

function Invoke-ConfigureASRRules {
  Write-Info 'Configuring Attack Surface Reduction rules'

  # All current ASR rule GUIDs
  $asrRules = @(
    '56a863a9-875e-4185-98a7-b882c64b5ce5', # Block abuse of exploited vulnerable signed drivers
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', # Block Adobe Reader from creating child processes
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a', # Block all Office applications from creating child processes
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', # Block credential stealing from lsass.exe
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', # Block executable content from email client and webmail
    '01443614-cd74-433a-b99e-2ecdc07bfc25', # Block executable files unless prevalence/age/trusted criteria met
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc', # Block execution of potentially obfuscated scripts
    'd3e037e1-3eb8-44c8-a917-57927947596d', # Block JS/VBScript from launching downloaded executables
    '3b576869-a4ec-4529-8536-b80a7769e899', # Block Office apps from creating executable content
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', # Block Office apps from injecting code into other processes
    '26190899-1602-49e8-8b27-eb1d0a1ce869', # Block Office comms apps from creating child processes
    'e6db77e5-3df2-4cf1-b95a-636979351e5b', # Block persistence via WMI event subscription
    'd1e49aac-8f56-4280-b9ba-993a6d77406c', # Block process creations from PSExec and WMI commands
    '33ddedf1-c6e0-47cb-833e-de6133960387', # Block rebooting into Safe Mode
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', # Block untrusted/unsigned processes from USB
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb', # Block use of copied or impersonated system tools
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b', # Block Win32 API calls from Office macros
    'c1db55ab-c21a-4637-bb3f-a12568109d35'  # Use advanced protection against ransomware
  )

  # Check if running on Windows Server
  $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
  if ($osInfo -and $osInfo.ProductType -ne 1) {
    Write-Info 'Windows Server detected, adding server-specific ASR rule'
    $asrRules += 'a8f5898e-1dc8-49a9-9878-85004b8a61e6' # Block Webshell creation for Servers
  }

  # Apply via Set-MpPreference
  try {
    $actions = @()
    foreach ($rule in $asrRules) {
      $actions += 'Enabled'
    }
    Set-MpPreference -AttackSurfaceReductionRules_Ids $asrRules -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop
    Write-Info ("Applied {0} ASR rules via Set-MpPreference" -f $asrRules.Count)
  } catch {
    Write-Warn ("Failed to apply ASR rules via Set-MpPreference: {0}" -f $_.Exception.Message)
  }

  # Also write to policy registry for persistence
  $asrRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
  try {
    if (-not (Test-Path $asrRegPath)) {
      New-Item -Path $asrRegPath -Force | Out-Null
    }

    foreach ($ruleId in $asrRules) {
      New-ItemProperty -Path $asrRegPath -Name $ruleId -PropertyType String -Value '1' -Force -ErrorAction Stop | Out-Null
    }
    Write-Info 'ASR rules written to policy registry (Block mode)'
  } catch {
    Write-Warn ("Failed to write ASR rules to registry: {0}" -f $_.Exception.Message)
  }
}

function Invoke-EnsureDefenderActive {
  Write-Info 'Ensuring Microsoft Defender is active and not in passive mode'

  $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
  try {
    if (-not (Test-Path $policyPath)) {
      New-Item -Path $policyPath -Force | Out-Null
    }

    New-ItemProperty -Path $policyPath -Name 'ForceDefenderPassiveMode' -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $policyPath -Name 'DisableAntiSpyware' -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $policyPath -Name 'DisableRealtimeMonitoring' -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
    Write-Info 'Defender policy registry keys set to keep protection active'
  } catch {
    Write-Warn ("Failed to enforce Defender active policy: {0}" -f $_.Exception.Message)
  }

  try {
    Set-MpPreference `
      -DisableRealtimeMonitoring $false `
      -DisableBehaviorMonitoring $false `
      -DisableIOAVProtection $false `
      -DisableArchiveScanning $false `
      -DisableScriptScanning $false `
      -DisableIntrusionPreventionSystem $false `
      -ErrorAction Stop
    Write-Info 'Defender realtime, behavior, IOAV, archive, script, and IPS protections enabled'
  } catch {
    Write-Warn ("Failed to enable Defender protections via Set-MpPreference: {0}" -f $_.Exception.Message)
  }
}

function Invoke-HardenDefender {
  Write-Info 'Hardening Windows Defender protections'

  try {
    # Enable advanced cloud protection and PUA blocking
    Set-MpPreference `
      -MAPSReporting Advanced `
      -SubmitSamplesConsent SendAllSamples `
      -CloudBlockLevel High `
      -DisableBlockAtFirstSeen $false `
      -DisableIOAVProtection $false `
      -PUAProtection Enabled `
      -EnableNetworkProtection Enabled `
      -EnableControlledFolderAccess Enabled `
      -ErrorAction Stop

    Write-Info 'Defender cloud protection, PUA, Network Protection, and Controlled Folder Access enabled'

    # Enable Network Protection on downlevel/server if applicable
    try {
      Set-MpPreference -AllowNetworkProtectionDownLevel $true -AllowNetworkProtectionOnWinServer $true -ErrorAction SilentlyContinue
    } catch {
      # Silently ignore if these settings aren't available
    }
  } catch {
    Write-Warn ("Failed to configure Defender preferences: {0}" -f $_.Exception.Message)
  }
}

function Invoke-ConfigureFirewallDefaults {
  Write-Info 'Ensuring firewall profiles are enabled and configured for strict inbound blocking'

  $commands = @(
    @('advfirewall', 'set', 'allprofiles', 'state', 'on'),
    @('advfirewall', 'set', 'publicprofile', 'firewallpolicy', 'blockinbound,allowoutbound'),
    @('advfirewall', 'set', 'privateprofile', 'firewallpolicy', 'blockinbound,allowoutbound'),
    @('advfirewall', 'set', 'domainprofile', 'firewallpolicy', 'blockinbound,allowoutbound'),
    @('advfirewall', 'set', 'allprofiles', 'logging', 'filename', '%systemroot%\System32\LogFiles\Firewall\pfirewall.log'),
    @('advfirewall', 'set', 'allprofiles', 'logging', 'maxsize', '32767'),
    @('advfirewall', 'set', 'allprofiles', 'logging', 'allowedconnections', 'enable'),
    @('advfirewall', 'set', 'allprofiles', 'logging', 'droppedconnections', 'enable')
  )

  foreach ($args in $commands) {
    try {
      $proc = Start-Process -FilePath 'netsh.exe' -ArgumentList $args -Wait -PassThru -NoNewWindow
      if ($proc.ExitCode -ne 0) {
        Write-Warn ("netsh {0} failed with exit code {1}" -f ($args -join ' '), $proc.ExitCode)
      }
    } catch {
      Write-Warn ("Failed to execute netsh {0}: {1}" -f ($args -join ' '), $_.Exception.Message)
    }
  }
}

function Invoke-RemoveNonDefaultAmsiProviders {
  Write-Info 'Checking for non-default AMSI providers'

  $providerRoot = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
  $defaultProvider = '{2781761E-28E0-4109-99FE-B9D127C57AFE}'

  if (-not (Test-Path $providerRoot)) {
    Write-Info 'No AMSI providers registered'
    return
  }

  try {
    $providers = Get-ChildItem -Path $providerRoot -ErrorAction Stop
    foreach ($provider in $providers) {
      if ($provider.PSChildName -ieq $defaultProvider) {
        continue
      }

      Write-Info ("Removing non-default AMSI provider {0}" -f $provider.PSChildName)
      try {
        Remove-Item -Path $provider.PSPath -Recurse -Force -ErrorAction Stop
      } catch {
        Write-Warn ("Failed to remove AMSI provider {0}: {1}" -f $provider.PSChildName, $_.Exception.Message)
      }
    }
  } catch {
    Write-Warn ("Failed to enumerate AMSI providers: {0}" -f $_.Exception.Message)
  }
}

function Invoke-ConfigureSmartScreen {
  Write-Info 'Configuring Windows SmartScreen and Edge protections'

  # Windows SmartScreen (Explorer) - Block mode, no bypass
  $systemPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
  try {
    if (-not (Test-Path $systemPolicyPath)) {
      New-Item -Path $systemPolicyPath -Force | Out-Null
    }

    New-ItemProperty -Path $systemPolicyPath -Name 'EnableSmartScreen' -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $systemPolicyPath -Name 'ShellSmartScreenLevel' -PropertyType String -Value 'Block' -Force -ErrorAction Stop | Out-Null
    Write-Info 'Windows SmartScreen set to Block (no bypass)'
  } catch {
    Write-Warn ("Failed to configure Windows SmartScreen: {0}" -f $_.Exception.Message)
  }

  # Microsoft Edge SmartScreen + PUA blocking
  $edgePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
  try {
    if (-not (Test-Path $edgePolicyPath)) {
      New-Item -Path $edgePolicyPath -Force | Out-Null
    }

    New-ItemProperty -Path $edgePolicyPath -Name 'SmartScreenEnabled' -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $edgePolicyPath -Name 'SmartScreenPuaEnabled' -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
    Write-Info 'Microsoft Edge SmartScreen and PUA blocking enabled'
  } catch {
    Write-Warn ("Failed to configure Edge SmartScreen: {0}" -f $_.Exception.Message)
  }
}

function Invoke-Verify {
  param($Context)

  $checks = @()
  $allPassed = $true

  # Check firewall status
  try {
    $output = & netsh advfirewall show currentprofile 2>$null
    $firewallEnabled = $false
    if ($output) {
      $firewallEnabled = ($output -match '(?im)^\s*State\s*ON\b')
    }

    if ($firewallEnabled) {
      $checks += 'Firewall: enabled'
    } else {
      $checks += 'Firewall: not enabled'
      $allPassed = $false
    }
  } catch {
    $checks += 'Firewall: check failed'
    $allPassed = $false
  }

  # Check Defender settings
  try {
    $mpPref = Get-MpPreference -ErrorAction Stop

    if ($mpPref.PUAProtection -eq 'Enabled' -or $mpPref.PUAProtection -eq 1) {
      $checks += 'PUA Protection: enabled'
    } else {
      $checks += 'PUA Protection: not enabled'
      $allPassed = $false
    }

    if ($mpPref.EnableNetworkProtection -eq 'Enabled' -or $mpPref.EnableNetworkProtection -eq 1) {
      $checks += 'Network Protection: enabled'
    } else {
      $checks += 'Network Protection: not enabled'
      $allPassed = $false
    }

    if ($mpPref.EnableControlledFolderAccess -eq 'Enabled' -or $mpPref.EnableControlledFolderAccess -eq 1) {
      $checks += 'Controlled Folder Access: enabled'
    } else {
      $checks += 'Controlled Folder Access: not enabled'
      $allPassed = $false
    }
  } catch {
    $checks += 'Defender: check failed'
    $allPassed = $false
  }

  # Check Defender active/passive mode and realtime protection
  try {
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $forcePassive = $null
    $disableRealtime = $null
    if (Test-Path $policyPath) {
      $policy = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue
      $forcePassive = $policy.ForceDefenderPassiveMode
      $disableRealtime = $policy.DisableRealtimeMonitoring
    }

    if (($forcePassive -eq 0 -or -not $forcePassive) -and ($disableRealtime -eq 0 -or -not $disableRealtime) -and $mpPref.DisableRealtimeMonitoring -eq $false) {
      $checks += 'Defender active mode enforced'
    } else {
      $checks += 'Defender active mode not enforced'
      $allPassed = $false
    }
  } catch {
    $checks += 'Defender active mode check failed'
    $allPassed = $false
  }

  # Check if ASR rules are configured
  try {
    $asrRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
    if (Test-Path $asrRegPath) {
      $asrProps = Get-ItemProperty -Path $asrRegPath -ErrorAction SilentlyContinue
      if ($asrProps) {
        $ruleCount = ($asrProps.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | Measure-Object).Count
        if ($ruleCount -gt 0) {
          $checks += "ASR rules: $ruleCount configured"
        } else {
          $checks += 'ASR rules: none configured'
          $allPassed = $false
        }
      } else {
        $checks += 'ASR rules: none configured'
        $allPassed = $false
      }
    } else {
      $checks += 'ASR rules: not configured'
      $allPassed = $false
    }
  } catch {
    $checks += 'ASR rules: check failed'
    $allPassed = $false
  }

  # Check SmartScreen
  try {
    $systemPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    $smartScreenEnabled = $false

    if (Test-Path $systemPolicyPath) {
      $props = Get-ItemProperty -Path $systemPolicyPath -ErrorAction SilentlyContinue
      if ($props -and $props.EnableSmartScreen -eq 1 -and $props.ShellSmartScreenLevel -eq 'Block') {
        $smartScreenEnabled = $true
      }
    }

    if ($smartScreenEnabled) {
      $checks += 'SmartScreen: enabled (Block mode)'
    } else {
      $checks += 'SmartScreen: not properly configured'
      $allPassed = $false
    }
  } catch {
    $checks += 'SmartScreen: check failed'
    $allPassed = $false
  }

  # Check firewall defaults and logging
  try {
    $output = & netsh advfirewall show publicprofile 2>$null
    $publicInboundBlock = $false
    if ($output) {
      $publicInboundBlock = ($output -match '(?im)^\s*Firewall Policy\s*BlockInbound,AllowOutbound')
    }

    $logOutput = & netsh advfirewall show allprofiles 2>$null
    $loggingEnabled = $false
    $logSizeOk = $false
    if ($logOutput) {
      $loggingEnabled = ($logOutput -match '(?im)^\s*Log dropped packets\s*YES') -and ($logOutput -match '(?im)^\s*Log successful connections\s*YES')
      $logSizeOk = ($logOutput -match '(?im)^\s*Max file size \(KB\)\s*32767')
    }

    if ($publicInboundBlock) { $checks += 'Firewall public inbound: Block' } else { $checks += 'Firewall public inbound: not Block'; $allPassed = $false }
    if ($loggingEnabled -and $logSizeOk) { $checks += 'Firewall logging: enabled with max size 32767KB' } else { $checks += 'Firewall logging: not properly configured'; $allPassed = $false }
  } catch {
    $checks += 'Firewall defaults: check failed'
    $allPassed = $false
  }

  # Check AMSI providers
  try {
    $providerRoot = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
    $defaultProvider = '{2781761E-28E0-4109-99FE-B9D127C57AFE}'
    $nonDefaultFound = $false
    if (Test-Path $providerRoot) {
      $providers = Get-ChildItem -Path $providerRoot -ErrorAction SilentlyContinue
      foreach ($provider in $providers) {
        if ($provider.PSChildName -ine $defaultProvider) {
          $nonDefaultFound = $true
          break
        }
      }
    }

    if ($nonDefaultFound) {
      $checks += 'AMSI providers: non-default entries present'
      $allPassed = $false
    } else {
      $checks += 'AMSI providers: only default entries present'
    }
  } catch {
    $checks += 'AMSI providers: check failed'
    $allPassed = $false
  }

  $message = $checks -join '; '
  $status = if ($allPassed) { 'Succeeded' } else { 'Failed' }

  return (New-ModuleResult -Name $script:ModuleName -Status $status -Message $message)
}

function Invoke-Apply {
  param($Context)

  $messages = @()
  $hadError = $false

  # Apply firewall configuration
  try {
    Invoke-DownloadFirewallProfile
    Invoke-ImportFirewallProfile
    Invoke-ConfigureFirewallDefaults
    $messages += 'Firewall configuration imported'
  } catch {
    Write-Err ("Firewall import failed: {0}" -f $_.Exception.Message)
    $messages += "Firewall import failed: $($_.Exception.Message)"
    $hadError = $true
  }

  # Apply ASR rules
  try {
    Invoke-ConfigureASRRules
    $messages += 'ASR rules configured'
  } catch {
    Write-Err ("ASR configuration failed: {0}" -f $_.Exception.Message)
    $messages += "ASR configuration failed: $($_.Exception.Message)"
    $hadError = $true
  }

  # Harden Defender
  try {
    Invoke-EnsureDefenderActive
    Invoke-HardenDefender
    $messages += 'Defender protections hardened'
  } catch {
    Write-Err ("Defender hardening failed: {0}" -f $_.Exception.Message)
    $messages += "Defender hardening failed: $($_.Exception.Message)"
    $hadError = $true
  }

  # Configure SmartScreen
  try {
    Invoke-ConfigureSmartScreen
    $messages += 'SmartScreen protections configured'
  } catch {
    Write-Err ("SmartScreen configuration failed: {0}" -f $_.Exception.Message)
    $messages += "SmartScreen configuration failed: $($_.Exception.Message)"
    $hadError = $true
  }

  # Remove non-default AMSI providers
  try {
    Invoke-RemoveNonDefaultAmsiProviders
    $messages += 'AMSI providers validated'
  } catch {
    Write-Err ("AMSI provider remediation failed: {0}" -f $_.Exception.Message)
    $messages += "AMSI provider remediation failed: $($_.Exception.Message)"
    $hadError = $true
  }

  $finalMessage = $messages -join '; '
  $status = if ($hadError) { 'Failed' } else { 'Succeeded' }

  return (New-ModuleResult -Name $script:ModuleName -Status $status -Message $finalMessage)
}

Export-ModuleMember -Function Test-Ready,Invoke-Verify,Invoke-Apply
