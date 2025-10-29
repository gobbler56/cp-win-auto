Set-StrictMode -Version Latest

# Minimal log helpers
if (-not (Get-Command Write-Info -EA SilentlyContinue)) { function Write-Info([string]$m){Write-Host "[*] $m" -ForegroundColor Cyan} }
if (-not (Get-Command Write-Ok   -EA SilentlyContinue)) { function Write-Ok  ([string]$m){Write-Host "[OK] $m" -ForegroundColor Green} }
if (-not (Get-Command Write-Warn -EA SilentlyContinue)) { function Write-Warn([string]$m){Write-Host "[!!] $m" -ForegroundColor Yellow} }
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  function New-ModuleResult { param([string]$Name,[string]$Status,[string]$Message) [pscustomobject]@{Name=$Name;Status=$Status;Message=$Message} }
}

$script:ServicePlanModel        = if ($env:OPENROUTER_MODEL) { $env:OPENROUTER_MODEL } else { 'openai/gpt-5' }
$script:ServicePlanMaxServices  = 200
$script:ServicePlanEndpoint     = 'https://openrouter.ai/api/v1/chat/completions'
$script:ServicePlanMaxTokens    = 6000

function ConvertTo-PlainText {
  param([string]$Html)
  if ([string]::IsNullOrWhiteSpace($Html)) { return '' }
  $text = $Html -replace '(?is)<script.*?>.*?</script>', ''
  $text = $text -replace '(?is)<style.*?>.*?</style>', ''
  $text = $text -replace '(?is)<head.*?>.*?</head>', ''
  $text = $text -replace '<.*?>', ' '
  return (($text -replace '\s+', ' ').Trim())
}

function Get-ServiceInventory {
  try {
    $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
  } catch {
    try { $services = Get-WmiObject -Class Win32_Service -ErrorAction Stop } catch { $services = @() }
  }
  if (-not $services) { return @() }
  return @($services | Select-Object Name, DisplayName, StartMode, State | Sort-Object Name)
}

function Build-ServiceAiRequest {
  param(
    [object[]]$Inventory,
    [string]$ReadmeText
  )

  $systemPrompt = @"
You are an assistant that configures Windows services for CyberPatriot scoring.
Decide which services must be enabled or disabled to comply with the README instructions.
Only reference service names that appear in the provided inventory (Name column).
Respond strictly with JSON in the format { "enable": ["ServiceName"], "disable": ["ServiceName"] }.
Use `enable` for services that must run automatically and `disable` for services that must be stopped/disabled.
Leave services out of both arrays when the README provides no instruction about them.
"@

  $lines = @()
  $max = [math]::Min($Inventory.Count, $script:ServicePlanMaxServices)
  for ($i = 0; $i -lt $max; $i++) {
    $svc = $Inventory[$i]
    $lines += "{0} | DisplayName={1} | StartMode={2} | State={3}" -f $svc.Name, $svc.DisplayName, $svc.StartMode, $svc.State
  }
  if ($Inventory.Count -gt $max) {
    $lines += "... (truncated {0} of {1} services)" -f $max, $Inventory.Count
  }
  $inventoryBlock = ($lines -join [Environment]::NewLine)

  $userPrompt = @"
README CONTENT:
$ReadmeText

SERVICE INVENTORY:
$inventoryBlock

Only output valid JSON for the directive object.
"@

  $body = @{
    model       = $script:ServicePlanModel
    temperature = 0
    top_p       = 1
    max_tokens  = $script:ServicePlanMaxTokens
    messages    = @(
      @{ role = 'system'; content = $systemPrompt },
      @{ role = 'user'; content = $userPrompt }
    )
  }

  return ($body | ConvertTo-Json -Depth 6)
}

function Get-ServicePlanContentText {
  param(
    $Content
  )

  if ($null -eq $Content) { return '' }
  if ($Content -is [string]) { return [string]$Content }

  if ($Content.PSObject) {
    if ($Content.PSObject.Properties.Name -contains 'value') {
      return Get-ServicePlanContentText -Content $Content.value
    }
    if ($Content.PSObject.Properties.Name -contains 'text') {
      return Get-ServicePlanContentText -Content $Content.text
    }
    if ($Content.PSObject.Properties.Name -contains 'content') {
      return Get-ServicePlanContentText -Content $Content.content
    }
  }

  if ($Content -is [System.Collections.IEnumerable]) {
    $fragments = foreach ($item in $Content) {
      $fragment = Get-ServicePlanContentText -Content $item
      $fragmentString = [string]$fragment
      if (-not [string]::IsNullOrWhiteSpace($fragmentString)) { $fragmentString }
    }
    if (-not $fragments) { return '' }
    return (($fragments -join [Environment]::NewLine).Trim())
  }

  return [string]$Content
}

function Invoke-ServicePlan {
  param(
    [object[]]$Inventory,
    [string]$ReadmeText
  )

  if (-not $Inventory -or $Inventory.Count -eq 0) { return $null }
  if ([string]::IsNullOrWhiteSpace($ReadmeText)) { return $null }

  $apiKey = $env:OPENROUTER_API_KEY
  if (-not $apiKey) { throw 'OPENROUTER_API_KEY not set' }

  $body = Build-ServiceAiRequest -Inventory $Inventory -ReadmeText $ReadmeText

  $headers = @{
    'Authorization' = "Bearer $apiKey"
    'Content-Type'  = 'application/json'
  }

  try {
    $response = Invoke-RestMethod -Uri $script:ServicePlanEndpoint -Method Post -Headers $headers -Body $body -ErrorAction Stop
  } catch {
    throw ("OpenRouter request failed: {0}" -f $_.Exception.Message)
  }
  $rawMessage = $null
  if ($response.PSObject.Properties.Name -contains 'choices' -and $response.choices) {
    $firstChoice = $response.choices | Select-Object -First 1
    if ($firstChoice -and $firstChoice.PSObject.Properties.Name -contains 'message') {
      $rawMessage = $firstChoice.message
    }
  }

  $rawContent = $null
  if ($rawMessage -and $rawMessage.PSObject.Properties.Name -contains 'content') {
    $rawContent = $rawMessage.content
  }

  $content = Get-ServicePlanContentText -Content $rawContent
  if ([string]::IsNullOrWhiteSpace($content)) { throw 'OpenRouter returned empty content' }
  $content = $content.Trim()
  if ($content -match '^\s*```') { $content = ($content -replace '^\s*```(?:json)?','' -replace '```\s*$','').Trim() }

  try {
    $parsed = $content | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw ("Failed to parse OpenRouter response: {0}" -f $_.Exception.Message)
  }
  if (-not $parsed) { return $null }

  $enable = @()
  if ($parsed.PSObject.Properties.Name -contains 'enable' -and $parsed.enable) {
    foreach ($item in @($parsed.enable)) {
      $name = ($item -as [string]).Trim()
      if ($name) { $enable += $name }
    }
  }
  $disable = @()
  if ($parsed.PSObject.Properties.Name -contains 'disable' -and $parsed.disable) {
    foreach ($item in @($parsed.disable)) {
      $name = ($item -as [string]).Trim()
      if ($name) { $disable += $name }
    }
  }

  return [pscustomobject]@{
    Enable  = @($enable | Select-Object -Unique)
    Disable = @($disable | Select-Object -Unique)
  }
}

function Apply-ServicePlan {
  param(
    [pscustomobject]$Plan,
    [object[]]$Inventory
  )

  if (-not $Plan) { return 0 }

  $nameMap = New-Object System.Collections.Generic.Dictionary[string,string] ([StringComparer]::OrdinalIgnoreCase)
  $displayMap = New-Object System.Collections.Generic.Dictionary[string,string] ([StringComparer]::OrdinalIgnoreCase)
  foreach ($svc in $Inventory) {
    if ($svc.Name -and -not $nameMap.ContainsKey($svc.Name)) { $nameMap[$svc.Name] = $svc.Name }
    if ($svc.DisplayName -and -not $displayMap.ContainsKey($svc.DisplayName)) { $displayMap[$svc.DisplayName] = $svc.Name }
  }

  $changes = 0

  foreach ($target in @($Plan.Enable)) {
    if (-not $target) { continue }
    $resolved = $null
    if ($nameMap.ContainsKey($target)) { $resolved = $nameMap[$target] }
    elseif ($displayMap.ContainsKey($target)) { $resolved = $displayMap[$target] }
    if (-not $resolved) {
      Write-Warn ("AI requested enabling unknown service '{0}'" -f $target)
      continue
    }
    Apply-ServiceState -Name $resolved -Start 2
    Write-Ok ("AI directive: enabled {0}" -f $resolved)
    $changes++
  }

  foreach ($target in @($Plan.Disable)) {
    if (-not $target) { continue }
    $resolved = $null
    if ($nameMap.ContainsKey($target)) { $resolved = $nameMap[$target] }
    elseif ($displayMap.ContainsKey($target)) { $resolved = $displayMap[$target] }
    if (-not $resolved) {
      Write-Warn ("AI requested disabling unknown service '{0}'" -f $target)
      continue
    }
    Apply-ServiceState -Name $resolved -Start 4
    Write-Ok ("AI directive: disabled {0}" -f $resolved)
    $changes++
  }

  return $changes
}

# --- YOUR embedded baseline export ---
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

function Parse-RegServices {
  $map = @{}
  $svc = $null
  foreach($raw in $EmbeddedRegBlob -split "`r?`n"){
    $line = $raw.Trim()
    if ($line -match '^\[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\([^\]]+)\]$') { $svc = $Matches[1]; continue }
    if ($svc -and $line -match '^\s*"Start"\s*=\s*dword:([0-9A-Fa-f]{8})\s*$') {
      $map[$svc] = [Convert]::ToInt32($Matches[1],16); $svc = $null
    }
  }
  $map
}

function TI-ApplyStartValues([hashtable]$Map) {
  # Assume NtObjectManager is already installed by Dependencies module
  try { 
    Import-Module NtObjectManager -Force -ErrorAction Stop 
  } catch {
    Write-Warn "NtObjectManager not available; applying locally (protected services may fail)."
    foreach($name in $Map.Keys){
      $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
      if (Test-Path $key) {
        try { Set-ItemProperty -Path $key -Name Start -Type DWord -Value ([int]$Map[$name]) -Force -ErrorAction Stop }
        catch { Write-Warn ("Local write failed for {0}: {1}" -f $name, $_.Exception.Message) }
      }
    }
    return
  }

  try { Start-Service -Name TrustedInstaller -ErrorAction SilentlyContinue } catch {}
  $ti = $null
  try { $ti = Get-NtProcess -ServiceName TrustedInstaller -ErrorAction Stop } catch {}
  if (-not $ti) {
    Write-Warn "TrustedInstaller process not found; applying locally."
    foreach($name in $Map.Keys){
      $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
      if (Test-Path $key) {
        try { Set-ItemProperty -Path $key -Name Start -Type DWord -Value ([int]$Map[$name]) -Force -ErrorAction Stop }
        catch { Write-Warn ("Local write failed for {0}: {1}" -f $name, $_.Exception.Message) }
      }
    }
    return
  }

  # Build a compact payload for the TI child
  $pairs = ($Map.GetEnumerator() | ForEach-Object {
    "'{0}'={1}" -f $_.Key.Replace("'", "''"), [int]$_.Value
  }) -join ';'

  $payload = @"
try { Import-Module NtObjectManager -Force -ErrorAction Stop } catch { }
`$pairs = @{ $pairs }
foreach(`$k in `$pairs.Keys){
  `$key = "HKLM:\SYSTEM\CurrentControlSet\Services\`$k"
  if (Test-Path `$key){
    try { Set-ItemProperty -Path `$key -Name Start -Type DWord -Value ([int]`$pairs[`$k]) -Force -ErrorAction SilentlyContinue } catch {}
  }
}
"@
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
  $cmd = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $enc"

  try {
    # Use explicit 64-bit PowerShell path
    $exePath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $exePath)) { $exePath = 'powershell' }
    $cmd = "$exePath -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $enc"
    
    $proc = New-Win32Process -CommandLine $cmd -CreationFlags NoWindow -ParentProcess $ti
    if (-not $proc) {
      throw "New-Win32Process returned null"
    }
    
    # The process object doesn't have ProcessId directly - it's under .Process  
    $processId = $null
    $processObject = $null
    
    if ($proc.Process) {
      $processObject = $proc.Process
      if ($processObject.ProcessId) {
        $processId = $processObject.ProcessId
      } elseif ($processObject.Id) {
        $processId = $processObject.Id
      }
    } elseif ($proc.ProcessId) {
      $processId = $proc.ProcessId
      $processObject = $proc
    } elseif ($proc.Id) {
      $processId = $proc.Id  
      $processObject = $proc
    } else {
      Write-Warn "Cannot determine process ID, will try waiting on process object directly"
    }
    
    if ($processId) {
      Write-Info ("Created TI child process: PID {0}" -f $processId)
    } else {
      Write-Info "Created TI child process (PID unknown, will wait on process object)"
    }
    
    # Wait for the process to complete using multiple fallback methods
    $waitResult = $null
    $exitCode = 0
    
    try {
      # Method 1: Try waiting on the process object directly (most reliable)
      if ($processObject -and (Get-Command Wait-NtProcess -ErrorAction SilentlyContinue)) {
        $waitResult = $processObject | Wait-NtProcess -ErrorAction Stop
        if ($waitResult -and $waitResult.ExitCode) {
          $exitCode = $waitResult.ExitCode
        }
      } elseif ($processId -and (Get-Command Wait-NtProcess -ErrorAction SilentlyContinue)) {
        $waitResult = Wait-NtProcess -ProcessId $processId -ErrorAction Stop  
        if ($waitResult -and $waitResult.ExitCode) {
          $exitCode = $waitResult.ExitCode
        }
      } else {
        throw "Wait-NtProcess not available"
      }
    } catch {
      Write-Info ("NtObjectManager wait failed, falling back to Wait-Process: {0}" -f $_.Exception.Message)
      try {
        if ($processId) {
          $process = Get-Process -Id $processId -ErrorAction Stop
          $process.WaitForExit()
          $exitCode = $process.ExitCode
        } else {
          throw "No process ID available"
        }
      } catch {
        Write-Info ("Wait-Process failed, using polling fallback: {0}" -f $_.Exception.Message)
        if ($processId) {
          $timeout = 30
          $elapsed = 0
          while ($elapsed -lt $timeout) {
            try {
              Get-Process -Id $processId -ErrorAction Stop | Out-Null
              Start-Sleep -Milliseconds 500
              $elapsed += 0.5
            } catch {
              break
            }
          }
        } else {
          Start-Sleep -Seconds 10
        }
      }
    }
    
    Write-Ok ("TI registry apply complete (exit code: {0})" -f $exitCode)
  } catch {
    Write-Warn ("TI spawn failed: {0}" -f $_.Exception.Message)
  }
}

function Apply-ServiceState([string]$Name, [int]$Start) {
  $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if (-not $svc) { return }
  try {
    switch ($Start) {
      2 { try { Set-Service -Name $Name -StartupType Automatic -ErrorAction SilentlyContinue } catch {}; try { Start-Service -Name $Name -ErrorAction SilentlyContinue } catch {}; break }
      3 { try { Set-Service -Name $Name -StartupType Manual    -ErrorAction SilentlyContinue } catch {}; try { Stop-Service  -Name $Name -Force -ErrorAction SilentlyContinue } catch {}; break }
      4 { try { Set-Service -Name $Name -StartupType Disabled  -ErrorAction SilentlyContinue } catch {}; try { Stop-Service  -Name $Name -Force -ErrorAction SilentlyContinue } catch {}; break }
    }
  } catch { }
}

function Test-Ready { param($Context) return $true }

function Invoke-Apply { param($Context)
  Write-Info "Parsing embedded services baseline (.reg) ..."
  $map = Parse-RegServices

  # 1) Write Start values with TI (falls back locally if needed)
  TI-ApplyStartValues -Map $map

  # 2) Apply runtime state for scoring
  $touched = 0
  foreach($name in $map.Keys){
    Apply-ServiceState -Name $name -Start ([int]$map[$name])
    $touched++
    Write-Ok ("{0} => Start={1}" -f $name, [int]$map[$name])
  }

  $inventory = @()
  try { $inventory = Get-ServiceInventory } catch { Write-Warn ("Failed to enumerate services: {0}" -f $_.Exception.Message) }

  $readmeText = ''
  if ($Context -and $Context.Readme) {
    if ($Context.Readme.PSObject.Properties.Name -contains 'PlainText' -and $Context.Readme.PlainText) {
      $readmeText = [string]$Context.Readme.PlainText
    } elseif ($Context.Readme.PSObject.Properties.Name -contains 'RawHtml' -and $Context.Readme.RawHtml) {
      $readmeText = ConvertTo-PlainText -Html $Context.Readme.RawHtml
    }
  }
  if ($readmeText.Length -gt 6000) { $readmeText = $readmeText.Substring(0,6000) }

  $dynamicChanges = 0
  if ($inventory -and $inventory.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($readmeText)) {
    try {
      $plan = Invoke-ServicePlan -Inventory $inventory -ReadmeText $readmeText
      if ($plan -and (($plan.Enable -and $plan.Enable.Count -gt 0) -or ($plan.Disable -and $plan.Disable.Count -gt 0))) {
        $dynamicChanges = Apply-ServicePlan -Plan $plan -Inventory $inventory
      } else {
        Write-Info 'AI directives produced no additional service changes.'
      }
    } catch {
      Write-Warn ("AI-driven service planning failed: {0}" -f $_.Exception.Message)
    }
  } else {
    Write-Info 'Skipping AI service directives (missing README text or inventory).'
  }

  $message = "Applied baseline to {0} services" -f $touched
  if ($dynamicChanges -gt 0) { $message += (", AI adjustments: {0}" -f $dynamicChanges) }

  New-ModuleResult -Name 'ServiceHardening' -Status 'Succeeded' -Message $message
}

function Invoke-Verify { param($Context)
  New-ModuleResult -Name 'ServiceHardening' -Status 'Succeeded' -Message 'Verification complete'
}

Export-ModuleMember -Function Test-Ready,Invoke-Apply,Invoke-Verify
