Set-StrictMode -Version Latest

if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

$script:ModuleName          = 'UnwantedSoftware'
$script:ApiUrl              = 'https://openrouter.ai/api/v1/chat/completions'
$script:ApiKeyEnvVar        = 'OPENROUTER_API_KEY'
$script:ScanDirectories     = @('C:\\Program Files', 'C:\\Program Files (x86)', 'C:\\ProgramData', 'C:\\Users')
$script:FileExtensions      = @('*.exe','*.msi','*.zip','*.bat','*.cmd','*.ps1','*.sh','*.vbs','*.py')
$script:StaticBaseline      = @()
$script:MaxReadmeCharacters = 5000
$script:MaxScanEntries      = 100

function Normalize-InventoryPath {
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return '' }

  $normalized = $Path -replace '[\\/]+', '\\'
  $normalized = $normalized.Trim()
  $normalized = $normalized.TrimEnd('\\')
  return $normalized
}

function Test-IsSubPath {
  param(
    [string]$Ancestor,
    [string]$Candidate
  )

  $ancestorNorm = Normalize-InventoryPath -Path $Ancestor
  $candidateNorm = Normalize-InventoryPath -Path $Candidate

  if (-not $ancestorNorm -or -not $candidateNorm) { return $false }

  if ([string]::Equals($ancestorNorm, $candidateNorm, [System.StringComparison]::OrdinalIgnoreCase)) {
    return $true
  }

  $prefix = $ancestorNorm + '\\'
  return $candidateNorm.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-CondensedPaths {
  param([string[]]$Paths)

  $ordered = $Paths | Where-Object { $_ } | Sort-Object { (Normalize-InventoryPath -Path $_).Length }
  $condensed = New-Object 'System.Collections.Generic.List[string]'

  foreach ($path in $ordered) {
    $normalized = Normalize-InventoryPath -Path $path
    if (-not $normalized) { continue }

    $isSubPath = $false
    foreach ($existing in $condensed) {
      if (Test-IsSubPath -Ancestor $existing -Candidate $normalized) {
        $isSubPath = $true
        break
      }
    }

    if (-not $isSubPath) {
      $condensed.Add($normalized) | Out-Null
    }
  }

  return @($condensed)
}

function Get-OpenRouterApiKey {
  $key = [System.Environment]::GetEnvironmentVariable($script:ApiKeyEnvVar)
  if (-not $key) { return '' }
  return $key
}

function Test-Ready {
  param($Context)

  if (-not (Get-OpenRouterApiKey)) {
    Write-Warn "OpenRouter API key is missing (set `$env:$($script:ApiKeyEnvVar)); cannot classify software inventory."
    return $false
  }

  return $true
}

function Remove-HTMLTags {
  param([string]$content)

  if (-not $content) { return '' }
  $content = [regex]::Replace($content, '<head.*?>.*?</head>', '', [System.Text.RegularExpressions.RegexOptions]::Singleline)
  $content = [regex]::Replace($content, '<script.*?>.*?</script>', '', [System.Text.RegularExpressions.RegexOptions]::Singleline)
  $content = [regex]::Replace($content, '<style.*?>.*?</style>', '', [System.Text.RegularExpressions.RegexOptions]::Singleline)
  $content = [regex]::Replace($content, '<.*?>', '')
  $content = $content -replace '\s+', ' '
  return $content.Trim()
}

function Get-ReadMeContent {
  $candidates = @('C:\CyberPatriot\README.url')
  if ($env:PUBLIC) { $candidates += (Join-Path $env:PUBLIC 'Desktop\README.url') }
  if ($env:USERPROFILE) { $candidates += (Join-Path $env:USERPROFILE 'Desktop\README.url') }

  foreach ($candidate in $candidates) {
    if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
    if (-not (Test-Path $candidate)) { continue }

    $lines = Get-Content -LiteralPath $candidate -ErrorAction Stop
    $urlLine = $lines | Where-Object { $_ -match '^\s*URL=' } | Select-Object -First 1
    if (-not $urlLine) {
      throw ("Could not extract URL from {0}" -f $candidate)
    }

    $url = ($urlLine -replace '^\s*URL=', '').Trim()
    if (-not $url) {
      throw ("README URL entry was empty in {0}" -f $candidate)
    }

    $response = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
    return [pscustomobject]@{ Url = $url; Content = $response.Content }
  }

  throw 'README.url file not found in expected locations.'
}

function Get-DynamicUserBaseline {
  $baseline = @()
  if (-not (Test-Path 'C:\\Users')) { return $baseline }

  foreach ($userDir in Get-ChildItem -Path 'C:\\Users' -Directory -ErrorAction SilentlyContinue) {
    $userName = $userDir.Name
    if ($userName -in @('Default','Public')) { continue }
    $baseline += @(
      "C:\\Users\\$userName\\AppData\\Local\\Comms",
      "C:\\Users\\$userName\\AppData\\Local\\ConnectedDevicesPlatform",
      "C:\\Users\\$userName\\AppData\\Local\\D3DSCache",
      "C:\\Users\\$userName\\AppData\\Local\\Microsoft",
      "C:\\Users\\$userName\\AppData\\Local\\Microsoft_Corporation",
      "C:\\Users\\$userName\\AppData\\Local\\Packages",
      "C:\\Users\\$userName\\AppData\\Local\\PeerDistRepub",
      "C:\\Users\\$userName\\AppData\\Local\\PlaceholderTileLogoFolder",
      "C:\\Users\\$userName\\AppData\\Local\\Publishers",
      "C:\\Users\\$userName\\AppData\\Local\\Temp",
      "C:\\Users\\$userName\\AppData\\Local\\VirtualStore",
      "C:\\Users\\$userName\\AppData\\LocalLow\\Microsoft",
      "C:\\Users\\$userName\\AppData\\LocalLow\\Pong",
      "C:\\Users\\$userName\\AppData\\Roaming\\Adobe",
      "C:\\Users\\$userName\\AppData\\Roaming\\Microsoft"
    )
  }

  return $baseline
}

function Get-BaselineSet {
  $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($item in $script:StaticBaseline) {
    if ($item) { [void]$set.Add($item) }
  }
  foreach ($item in (Get-DynamicUserBaseline)) {
    if ($item) { [void]$set.Add($item) }
  }
  return $set
}

function Add-ScanResult {
  param(
    [System.Collections.Generic.List[string]]$Accumulator,
    [System.Collections.Generic.HashSet[string]]$Baseline,
    [string]$Path
  )

  if (-not $Path) { return }
  if ($Baseline.Contains($Path)) { return }
  if (-not $Accumulator.Contains($Path)) {
    $Accumulator.Add($Path)
  }
}

function Scan-DirectoryRoot {
  param(
    [string]$Path,
    [System.Collections.Generic.List[string]]$Accumulator,
    [System.Collections.Generic.HashSet[string]]$Baseline
  )

  if (-not (Test-Path $Path)) { return }

  foreach ($entry in Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue) {
    Add-ScanResult -Accumulator $Accumulator -Baseline $Baseline -Path $entry.FullName
  }

  foreach ($ext in $script:FileExtensions) {
    foreach ($file in Get-ChildItem -Path $Path -File -Filter $ext -ErrorAction SilentlyContinue) {
      Add-ScanResult -Accumulator $Accumulator -Baseline $Baseline -Path $file.FullName
    }
  }
}

function Scan-UserProfiles {
  param(
    [System.Collections.Generic.List[string]]$Accumulator,
    [System.Collections.Generic.HashSet[string]]$Baseline
  )

  if (-not (Test-Path 'C:\\Users')) { return }

  foreach ($userDir in Get-ChildItem -Path 'C:\\Users' -Directory -ErrorAction SilentlyContinue) {
    if ($userDir.Name -in @('Default','Public')) { continue }
    foreach ($sub in @('AppData\\Local','AppData\\LocalLow','AppData\\Roaming')) {
      $candidate = Join-Path $userDir.FullName $sub
      Scan-DirectoryRoot -Path $candidate -Accumulator $Accumulator -Baseline $Baseline
    }
  }
}

function Get-Inventory {
  $baseline = Get-BaselineSet
  $results = New-Object 'System.Collections.Generic.List[string]'

  foreach ($dir in $script:ScanDirectories) {
    if ($dir -eq 'C:\\Users') {
      Scan-UserProfiles -Accumulator $results -Baseline $baseline
    } else {
      Scan-DirectoryRoot -Path $dir -Accumulator $results -Baseline $baseline
    }
  }

  $unique = $results | Sort-Object -Unique
  $originalCount = $unique.Count
  if ($originalCount -gt $script:MaxScanEntries) {
    $unique = $unique | Select-Object -First $script:MaxScanEntries
  }

  return [pscustomobject]@{ Items = @($unique); OriginalCount = $originalCount }
}

function Build-AiRequest {
  param(
    [string[]]$Inventory,
    [string]$ReadmeText
  )

  $systemPrompt = @"
You are a Windows system-hardening assistant for CyberPatriot scoring.
Return ONLY a raw JSON array (no code fences) of absolute filesystem paths for unauthorized, non-system applications that should be removed immediately.
If you are unsure about a path, err on the side of marking it for removal.
Never include Windows components, device drivers, virtualization/VMware tooling, or standard VM guest utilities.
Always exclude items related to CCS, CyberPatriot, Java, or UNP.
If nothing should be removed, respond with [].
"@

  $inventoryBlock = ($Inventory -join [Environment]::NewLine)
  $userPrompt = @"
You are analyzing installed software on a Windows system.

README CONTENT:
$ReadmeText

SOFTWARE INVENTORY (first $($Inventory.Count) entries):
$inventoryBlock

List any paths that should be deleted to comply with the README. Output ONLY a JSON array.
"@

  $body = @{
    model       = 'openai/gpt-5'
    temperature = 0
    max_tokens  = 2000
    messages    = @(
      @{ role = 'system'; content = $systemPrompt },
      @{ role = 'user'; content = $userPrompt }
    )
  }

  return $body | ConvertTo-Json -Depth 6
}

function Invoke-Classification {
  param(
    [string[]]$Inventory,
    [string]$ReadmeText
  )

  if (-not $Inventory -or $Inventory.Count -eq 0) {
    return @()
  }

  $bodyJson = Build-AiRequest -Inventory $Inventory -ReadmeText $ReadmeText

  $apiKey = Get-OpenRouterApiKey
  if (-not $apiKey) {
    throw 'OpenRouter API key was not available when classification was attempted.'
  }

  $headers = @{
    'Authorization' = "Bearer $apiKey"
    'Content-Type'  = 'application/json'
  }

  try {
    $response = Invoke-RestMethod -Uri $script:ApiUrl -Method Post -Headers $headers -Body $bodyJson -ErrorAction Stop
  } catch {
    throw ("OpenRouter API call failed: {0}" -f $_.Exception.Message)
  }

  $content = $response.choices[0].message.content
  if (-not $content) {
    throw 'OpenRouter returned an empty response.'
  }

  $content = $content -replace '^```json\s*', '' -replace '\s*```$', ''

  try {
    $parsed = $content | ConvertFrom-Json
  } catch {
    throw ("Failed to parse OpenRouter response: {0}" -f $_.Exception.Message)
  }

  if ($parsed -isnot [System.Collections.IEnumerable]) {
    throw 'OpenRouter response was not an array.'
  }

  $paths = @()
  foreach ($item in $parsed) {
    if ($item -is [string]) {
      $value = $item.Trim()
      if ($value) { $paths += $value }
    }
  }

  return @($paths | Sort-Object -Unique)
}

function Invoke-UnwantedSoftwareAssessment {
  param([switch]$Remove)

  Write-Info 'Collecting installed software inventory'
  $inventoryInfo = Get-Inventory
  $inventory = $inventoryInfo.Items

  if (-not $inventory -or $inventory.Count -eq 0) {
    return [pscustomobject]@{ Flagged=@(); Condensed=@(); Removed=@(); OriginalCount=0; UserDeclined=$false }
  }

  $truncNote = if ($inventoryInfo.OriginalCount -gt $inventory.Count) {
    " (truncated from {0})" -f $inventoryInfo.OriginalCount
  } else {
    ''
  }
  Write-Info ("Inventory collected ({0} entries{1})" -f $inventory.Count, $truncNote)

  $readmeText = ''
  try {
    $readme = Get-ReadMeContent
    $cleaned = Remove-HTMLTags -content $readme.Content
    if ($cleaned.Length -gt $script:MaxReadmeCharacters) {
      $cleaned = $cleaned.Substring(0, $script:MaxReadmeCharacters)
    }
    $readmeText = $cleaned
  } catch {
    Write-Warn ("Failed to retrieve README: {0}" -f $_.Exception.Message)
  }

  Write-Info 'Requesting AI classification of software inventory'
  $flagged = Invoke-Classification -Inventory $inventory -ReadmeText $readmeText

  if (-not $flagged -or $flagged.Count -eq 0) {
    return [pscustomobject]@{ Flagged=@(); Condensed=@(); Removed=@(); OriginalCount=$inventoryInfo.OriginalCount; UserDeclined=$false }
  }

  $condensed = Get-CondensedPaths -Paths $flagged
  Write-Info 'AI flagged the following paths for removal:'
  foreach ($entry in $condensed) {
    Write-Host ("  - {0}" -f $entry)
  }

  $removed = @()
  $userDeclined = $false
  if ($Remove) {
    $confirmation = Read-Host 'Remove the listed paths now? (Y/N, default Y)'
    if ([string]::IsNullOrWhiteSpace($confirmation)) { $confirmation = 'Y' }

    if ($confirmation.Trim().StartsWith('Y', [System.StringComparison]::OrdinalIgnoreCase)) {
      foreach ($path in $condensed) {
        try {
          if (Test-Path -LiteralPath $path) {
            Write-Info ("Removing unauthorized software at {0}" -f $path)
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
            $removed += $path
          } else {
            Write-Warn ("Path not found during removal: {0}" -f $path)
          }
        } catch {
          Write-Warn ("Failed to remove {0}: {1}" -f $path, $_.Exception.Message)
        }
      }
    } else {
      $userDeclined = $true
      Write-Info 'User declined removal; no changes were made to flagged paths.'
    }
  }

  return [pscustomobject]@{ Flagged=@($flagged); Condensed=@($condensed); Removed=@($removed); OriginalCount=$inventoryInfo.OriginalCount; UserDeclined=$userDeclined }
}

function Invoke-Verify {
  param($Context)

  try {
    $result = Invoke-UnwantedSoftwareAssessment
  } catch {
    Write-Err ("UnwantedSoftware verification failed: {0}" -f $_.Exception.Message)
    return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message ('Verification error: ' + $_.Exception.Message))
  }

  if ($result.Flagged.Count -eq 0) {
    return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message 'No unauthorized software detected by AI review.')
  }

  $preview = ($result.Condensed | Select-Object -First 5)
  $previewText = if ($preview) { $preview -join ', ' } else { ($result.Flagged | Select-Object -First 5) -join ', ' }
  return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message ('Potential removals: ' + $previewText))
}

function Invoke-Apply {
  param($Context)

  try {
    $result = Invoke-UnwantedSoftwareAssessment -Remove
  } catch {
    Write-Err ("UnwantedSoftware apply failed: {0}" -f $_.Exception.Message)
    return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message ('Apply error: ' + $_.Exception.Message))
  }

  if ($result.Flagged.Count -eq 0) {
    return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message 'No unauthorized software identified.')
  }

  $summary = if ($result.UserDeclined) {
    'User declined removal of AI-flagged paths.'
  } elseif ($result.Removed.Count -gt 0) {
    ('Removed {0} path(s).' -f $result.Removed.Count)
  } else {
    'AI flagged items but none were removed (missing paths or errors).'
  }

  return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message $summary)
}

Export-ModuleMember -Function Test-Ready,Invoke-Verify,Invoke-Apply
