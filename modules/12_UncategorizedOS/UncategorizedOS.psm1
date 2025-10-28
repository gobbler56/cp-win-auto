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
$script:WriteRightsMask         = [System.Security.AccessControl.FileSystemRights]::FullControl -bor \
  [System.Security.AccessControl.FileSystemRights]::Modify -bor \
  [System.Security.AccessControl.FileSystemRights]::Write -bor \
  [System.Security.AccessControl.FileSystemRights]::WriteData -bor \
  [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor \
  [System.Security.AccessControl.FileSystemRights]::CreateDirectories -bor \
  [System.Security.AccessControl.FileSystemRights]::AppendData -bor \
  [System.Security.AccessControl.FileSystemRights]::ChangePermissions

foreach ($name in @('ADMIN$','IPC$','C$','D$','E$','F$','G$','H$','PRINT$','FAX$','SYSVOL','NETLOGON')) {
  [void]$script:DefaultShareNames.Add($name)
}

function Get-OpenRouterApiKey {
  $key = [System.Environment]::GetEnvironmentVariable($script:ApiKeyEnvVar)
  if (-not $key) { return '' }
  return $key
}

function Ensure-RegistryValue {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('String','ExpandString','MultiString','Binary','DWord','QWord')][string]$Type,
    [Parameter(Mandatory)][object]$Value
  )

  if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
  }

  $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
  if ($Type -eq 'DWord') { $Value = [int]$Value }
  elseif ($Type -eq 'QWord') { $Value = [long]$Value }

  if ($null -ne $current) {
    if ($current -is [byte[]] -and $Value -is [byte[]]) {
      if ($current.Length -eq $Value.Length) {
        $different = $false
        for ($i = 0; $i -lt $current.Length; $i++) {
          if ($current[$i] -ne $Value[$i]) { $different = $true; break }
        }
        if (-not $different) { return $false }
      } elseif ($current.Length -eq 0 -and $Value.Length -eq 0) {
        return $false
      }
    } elseif ([string]::Equals([string]$current, [string]$Value, [System.StringComparison]::OrdinalIgnoreCase)) {
      return $false
    } elseif ($current -eq $Value) {
      return $false
    }
  }

  try {
    if ($null -eq $current) {
      New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
    } else {
      Set-ItemProperty -Path $Path -Name $Name -Value $Value
    }
    return $true
  } catch {
    Write-Warn ("Failed to set {0}\{1}: {2}" -f $Path, $Name, $_.Exception.Message)
    return $false
  }
}

function Get-RegistryValueSafe {
  param([string]$Path,[string]$Name)
  try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
  catch { return $null }
}

function Disable-RemoteDesktopFeatures {
  $changed = $false
  $changed = (Ensure-RegistryValue -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Type 'DWord' -Value 1) -or $changed
  $changed = (Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Type 'DWord' -Value 0) -or $changed
  $changed = (Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowFullControl' -Type 'DWord' -Value 0) -or $changed
  $changed = (Ensure-RegistryValue -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'AllowTSConnections' -Type 'DWord' -Value 0) -or $changed
  return $changed
}

function Test-RemoteDesktopDisabled {
  $deny = (Get-RegistryValueSafe -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections') -eq 1
  $assist = (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp') -eq 0
  return ($deny -and $assist)
}

function Disable-DesktopGadgets {
  $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar'
  $changed = $false
  $changed = (Ensure-RegistryValue -Path $path -Name 'TurnOffSidebar' -Type 'DWord' -Value 1) -or $changed
  $changed = (Ensure-RegistryValue -Path $path -Name 'DisableSidebar' -Type 'DWord' -Value 1) -or $changed
  return $changed
}

function Test-DesktopGadgetsDisabled {
  $value = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar' -Name 'TurnOffSidebar'
  return ($value -eq 1)
}

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

function Set-UacAdministratorEnumeration {
  return (Ensure-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name 'EnumerateAdministrators' -Type 'DWord' -Value 0)
}

function Test-UacAdministratorEnumeration {
  return ((Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name 'EnumerateAdministrators') -eq 0)
}

function Ensure-ScreenSaverPolicy {
  $changed = $false
  $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
  $changed = (Ensure-RegistryValue -Path $policyPath -Name 'ScreenSaveActive' -Type 'String' -Value '1') -or $changed
  $changed = (Ensure-RegistryValue -Path $policyPath -Name 'ScreenSaverIsSecure' -Type 'String' -Value '1') -or $changed
  $changed = (Ensure-RegistryValue -Path $policyPath -Name 'ScreenSaveTimeOut' -Type 'String' -Value '600') -or $changed
  $changed = (Ensure-RegistryValue -Path $policyPath -Name 'SCRNSAVE.EXE' -Type 'String' -Value 'scrnsave.scr') -or $changed

  $userPaths = @('HKCU:\Control Panel\Desktop','HKU:\.DEFAULT\Control Panel\Desktop')
  try {
    foreach ($sidKey in Get-ChildItem -Path 'HKU:' -ErrorAction SilentlyContinue) {
      if ($sidKey.Name -match 'S-1-5-21-') {
        $userPaths += (Join-Path $sidKey.PSPath 'Control Panel\Desktop')
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

function Ensure-AutorunDisabled {
  $changed = $false
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
    'HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
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
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers',
    'HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'
  )

  foreach ($path in $paths) {
    $changed = (Ensure-RegistryValue -Path $path -Name 'DisableAutoplay' -Type 'DWord' -Value 1) -or $changed
  }

  return $changed
}

function Ensure-MemoryMitigations {
  $changed = $false
  $mmPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
  $changed = (Ensure-RegistryValue -Path $mmPath -Name 'MoveImages' -Type 'DWord' -Value 1) -or $changed
  $changed = (Ensure-RegistryValue -Path $mmPath -Name 'FeatureSettingsOverride' -Type 'DWord' -Value 0) -or $changed
  $changed = (Ensure-RegistryValue -Path $mmPath -Name 'FeatureSettingsOverrideMask' -Type 'DWord' -Value 3) -or $changed

  if (Get-Command Set-ProcessMitigation -ErrorAction SilentlyContinue) {
    try {
      Set-ProcessMitigation -System -Enable ForceRelocateImages,BottomUp,HighEntropy -ErrorAction Stop | Out-Null
      $changed = $true
    } catch {
      Write-Warn ("Set-ProcessMitigation ASLR failed: {0}" -f $_.Exception.Message)
    }
  }

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
  $changed = $false
  if (Get-Command Set-ProcessMitigation -ErrorAction SilentlyContinue) {
    try {
      Set-ProcessMitigation -System -Enable ValidateHeapIntegrity -ErrorAction Stop | Out-Null
      $changed = $true
    } catch {
      Write-Warn ("Set-ProcessMitigation ValidateHeapIntegrity failed: {0}" -f $_.Exception.Message)
    }
  }
  $kernelPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel'
  $changed = (Ensure-RegistryValue -Path $kernelPath -Name 'ValidateHeapIntegrity' -Type 'DWord' -Value 1) -or $changed
  return $changed
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

function Ensure-IpSourceRoutingDisabled {
  $changed = $false
  $changed = (Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableIPSourceRouting' -Type 'DWord' -Value 2) -or $changed
  $changed = (Ensure-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIPSourceRouting' -Type 'DWord' -Value 2) -or $changed
  return $changed
}

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
  if (Test-Path 'C:\\Share') {
    if (Remove-IdentityWriteAccess -Path 'C:\\Share' -Identity 'Everyone') { $changed = $true }
  }
  if (Test-Path 'C:\\inetpub') {
    if (Remove-IdentityWriteAccess -Path 'C:\\inetpub' -Identity 'Everyone') { $changed = $true }
  }
  if (Test-Path 'C:\\Windows\\NTDS') {
    if (Remove-IdentityWriteAccess -Path 'C:\\Windows\\NTDS' -Identity 'Domain Users') { $changed = $true }
  }
  return $changed
}

function Ensure-ShareRestrictions {
  $changed = $false
  $script:LastRemovedShares = @()

  try {
    $removedShares = Remove-NonDefaultSharesWithAi
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
  $candidates = @('C:\\CyberPatriot\\README.url')
  if ($env:PUBLIC) { $candidates += (Join-Path $env:PUBLIC 'Desktop\\README.url') }
  if ($env:USERPROFILE) { $candidates += (Join-Path $env:USERPROFILE 'Desktop\\README.url') }

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
      $shares = Get-SmbShare -ErrorAction Stop | Select-Object Name, Path, Description
    } catch {}
  }
  if (-not $shares -or $shares.Count -eq 0) {
    try {
      $output = & net share 2>$null
      if ($LASTEXITCODE -eq 0 -and $output) {
        foreach ($line in $output) {
          if ($line -match '^\\s*$') { continue }
          if ($line -match '^Share name') { continue }
          if ($line -match '^---') { continue }
          if ($line -match '^The command completed successfully') { break }
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
  return @($shares)
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
    response_format = @{ type = 'json_schema'; json_schema = @{ name = 'share_plan'; schema = @{ type = 'object'; required = @('allowed'); additionalProperties = $false; properties = @{ allowed = @{ type = 'array'; items = @{ type = 'string' } } } } } }
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
  $shares = Get-ShareInventory
  if (-not $shares -or $shares.Count -eq 0) { return @() }

  $nonDefault = @($shares | Where-Object { -not $script:DefaultShareNames.Contains($_.Name) })
  if ($nonDefault.Count -eq 0) { return @() }

  $readme = Get-ReadMeContent
  $allowed = @()
  if ($readme) {
    try {
      $allowed = Invoke-SharePlan -Shares $shares -ReadmeText $readme.Content
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

  return $removed
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

function Apply-AllSettings {
  $changes = @()

  if (Disable-RemoteDesktopFeatures) { $changes += 'Disabled Remote Desktop/Assistance' }
  if (Disable-DesktopGadgets) { $changes += 'Disabled desktop gadgets' }
  if (Set-DepPolicy) { $changes += 'Configured DEP for all programs' }
  if (Set-UacAdministratorEnumeration) { $changes += 'Disabled UAC administrator enumeration' }
  if (Ensure-ScreenSaverPolicy) { $changes += 'Enforced secure screen saver' }
  if (Ensure-AutorunDisabled) { $changes += 'Disabled AutoRun' }
  if (Ensure-AutoplayDisabled) { $changes += 'Disabled AutoPlay' }
  if (Ensure-MemoryMitigations) { $changes += 'Enabled ASLR mitigations' }
  if (Ensure-EarlyLaunchPolicy) { $changes += 'Restricted ELAM driver loading' }
  if (Ensure-ValidateHeapIntegrity) { $changes += 'Enabled heap integrity validation' }
  if (Ensure-HeapMitigationOptions) { $changes += 'Updated mitigation options' }
  if (Ensure-IpSourceRoutingDisabled) { $changes += 'Disabled IP source routing' }
  if (Ensure-DirectoryRestrictions) { $changes += 'Hardened directory ACLs' }
  if (Ensure-ShareRestrictions) { $changes += 'Updated share restrictions' }

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
  $status = if ($changes.Count -gt 0) { 'Succeeded' } else { 'Succeeded' }
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
  $checks += "AutoPlay=$(if ((Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -Name 'DisableAutoplay') -eq 1) { 'Disabled' } else { 'NeedsAttention' })"
  $checks += "ASLR=$(if (Test-MemoryMitigations) { 'Enabled' } else { 'NeedsAttention' })"
  $checks += "ELAM=$(if (Test-EarlyLaunchPolicy) { 'Strict' } else { 'NeedsAttention' })"
  $checks += "HeapIntegrity=$(if (Test-ValidateHeapIntegrity) { 'Enabled' } else { 'NeedsAttention' })"
  $checks += "IPSourceRouting=$(if ((Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableIPSourceRouting') -eq 2) { 'Disabled' } else { 'NeedsAttention' })"
  $checks += "Shares=$(if (Test-UnauthorizedShares) { 'Clean' } else { 'NeedsReview' })"

  $status = if ($checks -match 'Needs') { 'NeedsAttention' } else { 'Succeeded' }
  return New-ModuleResult -Name $script:ModuleName -Status $status -Message ($checks -join '; ')
}

Export-ModuleMember -Function Test-Ready,Invoke-Apply,Invoke-Verify
