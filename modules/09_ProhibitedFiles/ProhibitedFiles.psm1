Set-StrictMode -Version Latest

if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

$script:ModuleName               = 'ProhibitedFiles'
$script:ApiUrl                   = 'https://openrouter.ai/api/v1/chat/completions'
$script:ApiKeyEnvVar             = 'OPENROUTER_API_KEY'
$script:BaselineUrl              = 'https://drive.google.com/uc?export=download&id=1P68-lGZZKj16OISrVURcH-NOO861ArSs'
$script:BaselineRoot             = 'C:\\CyberPatriot\\ProhibitedFilesBaseline'
$script:BaselineZipName          = 'files.zip'
$script:BaselineFolderName       = 'files'
$script:BaselineListFiles        = @('exe_files.txt','audio_files.txt','video_files.txt','script_files.txt','txt_files.txt')
$script:UserContentFolders       = @('Desktop','Documents','Downloads','Music','Pictures','Videos','OneDrive','OneDrive\\Documents','OneDrive\\Desktop','OneDrive\\Pictures','OneDrive\\Videos')
$script:PublicContentFolders     = @('C:\Users\Public\Desktop','C:\Users\Public\Documents','C:\Users\Public\Downloads','C:\Users\Public\Music','C:\Users\Public\Pictures','C:\Users\Public\Videos')
$script:AdditionalRoots          = @('C:\temp','C:\tmp')
$script:ExcludedRootPrefixes     = @('C:\Windows','C:\Program Files','C:\Program Files (x86)','C:\ProgramData','C:\Recovery','C:\$Recycle.Bin','C:\System Volume Information','C:\CyberPatriot\ProhibitedFilesBaseline')
$script:ScanExtensions           = @('*.mp3','*.wav','*.wma','*.flac','*.aac','*.ogg','*.m4a','*.mp4','*.mkv','*.mov','*.avi','*.wmv','*.m4v','*.jpg','*.jpeg','*.png','*.gif','*.bmp','*.tif','*.tiff','*.svg','*.webp','*.txt','*.csv','*.tsv','*.pdf','*.doc','*.docx','*.xls','*.xlsx')
$script:MaxCandidates            = 200
$script:MaxReadmeCharacters      = 5000
$script:BaselineCache            = $null

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
    Write-Warn "OpenRouter API key is missing (set `$env:$($script:ApiKeyEnvVar)); cannot classify prohibited files."
    return $false
  }

  return $true
}

function Ensure-BaselineData {
  if (-not (Test-Path -LiteralPath $script:BaselineRoot)) {
    [void](New-Item -ItemType Directory -Path $script:BaselineRoot -Force)
  }

  $filesRoot = Join-Path $script:BaselineRoot $script:BaselineFolderName
  $needsDownload = $true

  if (Test-Path -LiteralPath $filesRoot) {
    $missing = $false
    foreach ($file in $script:BaselineListFiles) {
      $candidate = Join-Path $filesRoot $file
      if (-not (Test-Path -LiteralPath $candidate)) {
        $missing = $true
        break
      }
    }
    $needsDownload = $missing
  }

  if (-not $needsDownload) {
    return $filesRoot
  }

  $zipPath = Join-Path $script:BaselineRoot $script:BaselineZipName
  Write-Info 'Downloading prohibited file baseline inventory'

  try {
    Invoke-WebRequest -Uri $script:BaselineUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
  } catch {
    throw ("Failed to download prohibited file baseline: {0}" -f $_.Exception.Message)
  }

  if (Test-Path -LiteralPath $filesRoot) {
    try {
      Remove-Item -LiteralPath $filesRoot -Recurse -Force -ErrorAction Stop
    } catch {
      throw ("Failed to clear existing baseline directory: {0}" -f $_.Exception.Message)
    }
  }

  try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue | Out-Null
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $script:BaselineRoot)
  } catch {
    throw ("Failed to extract prohibited baseline archive: {0}" -f $_.Exception.Message)
  }

  return (Join-Path $script:BaselineRoot $script:BaselineFolderName)
}

function Get-BaselineSet {
  if ($script:BaselineCache) { return $script:BaselineCache }

  $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

  try {
    $filesRoot = Ensure-BaselineData
    foreach ($fileName in $script:BaselineListFiles) {
      $path = Join-Path $filesRoot $fileName
      if (-not (Test-Path -LiteralPath $path)) { continue }
      $raw = Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue
      if (-not $raw) { continue }
      $entries = $raw -split ',\s*'
      foreach ($entry in $entries) {
        $normalized = Normalize-InventoryPath -Path $entry
        if ($normalized) { [void]$set.Add($normalized) }
      }
    }
  } catch {
    Write-Warn ("Unable to load prohibited file baseline: {0}" -f $_.Exception.Message)
  }

  $script:BaselineCache = $set
  return $script:BaselineCache
}

function Should-ExcludePath {
  param([string]$Path)

  $normalized = Normalize-InventoryPath -Path $Path
  if (-not $normalized) { return $true }

  foreach ($prefix in $script:ExcludedRootPrefixes) {
    if (Test-IsSubPath -Ancestor $prefix -Candidate $normalized) {
      return $true
    }
  }

  if ($normalized -match '\\AppData\\') { return $true }
  if ($normalized -match '\\Microsoft\\Edge\\User Data\\Default\\Media Cache') { return $true }
  if ($normalized -match '\\Microsoft\\Windows\\INetCache') { return $true }
  if ($normalized -match '\\Google\\Chrome\\User Data\\Default\\Media Cache') { return $true }

  return $false
}

function Get-UserContentRoots {
  $roots = New-Object 'System.Collections.Generic.List[string]'

  if (Test-Path -LiteralPath 'C:\\Users') {
    foreach ($userDir in Get-ChildItem -LiteralPath 'C:\\Users' -Directory -ErrorAction SilentlyContinue) {
      if ($userDir.Name -in @('Default','Default User','Public','All Users')) { continue }
      foreach ($sub in $script:UserContentFolders) {
        if (-not $sub) { continue }
        $candidate = Join-Path $userDir.FullName $sub
        if (Test-Path -LiteralPath $candidate) {
          $roots.Add($candidate) | Out-Null
        }
      }
    }
  }

  foreach ($path in $script:PublicContentFolders) {
    if (Test-Path -LiteralPath $path) {
      $roots.Add($path) | Out-Null
    }
  }

  foreach ($path in $script:AdditionalRoots) {
    if (Test-Path -LiteralPath $path) {
      $roots.Add($path) | Out-Null
    }
  }

  return @($roots | Sort-Object -Unique)
}

function Collect-CandidatesFromRoot {
  param(
    [string]$Root,
    [System.Collections.Generic.HashSet[string]]$Baseline,
    [System.Collections.Generic.HashSet[string]]$Seen,
    [System.Collections.Generic.List[pscustomobject]]$Accumulator,
    [ref]$LimitHit
  )

  if (-not (Test-Path -LiteralPath $Root)) { return }

  foreach ($ext in $script:ScanExtensions) {
    foreach ($file in Get-ChildItem -LiteralPath $Root -Filter $ext -File -Recurse -ErrorAction SilentlyContinue) {
      $normalized = Normalize-InventoryPath -Path $file.FullName
      if (-not $normalized) { continue }
      if ($Baseline.Contains($normalized)) { continue }
      if (Should-ExcludePath -Path $file.FullName) { continue }
      if ($Seen.Contains($normalized)) { continue }
      $Seen.Add($normalized) | Out-Null

      $sizeKb = if ($file.Length -gt 0) { [Math]::Round($file.Length / 1kb, 2) } else { 0 }
      $entry = [pscustomobject]@{
        Path    = $file.FullName
        Summary = "{0} | SizeKB={1} | ModifiedUTC={2}" -f $file.FullName, $sizeKb, ($file.LastWriteTimeUtc.ToString('s') + 'Z')
      }
      $Accumulator.Add($entry) | Out-Null

      if ($Accumulator.Count -ge $script:MaxCandidates) {
        $LimitHit.Value = $true
        return
      }
    }

    if ($Accumulator.Count -ge $script:MaxCandidates) {
      $LimitHit.Value = $true
      return
    }
  }
}

function Get-ProhibitedFileCandidates {
  $baseline = Get-BaselineSet
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $results = New-Object 'System.Collections.Generic.List[pscustomobject]'
  $limitHit = $false

  $roots = Get-UserContentRoots
  foreach ($root in $roots) {
    Collect-CandidatesFromRoot -Root $root -Baseline $baseline -Seen $seen -Accumulator $results -LimitHit ([ref]$limitHit)
    if ($results.Count -ge $script:MaxCandidates -or $limitHit) { break }
  }

  $unique = @($results | Sort-Object Path)
  $originalCount = if ($limitHit) { $script:MaxCandidates } else { $unique.Count }
  return [pscustomobject]@{ Items = $unique; OriginalCount = $originalCount; Truncated = $limitHit }
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
  $candidates = @('C:\\CyberPatriot\\README.url')
  if ($env:PUBLIC) { $candidates += (Join-Path $env:PUBLIC 'Desktop\\README.url') }
  if ($env:USERPROFILE) { $candidates += (Join-Path $env:USERPROFILE 'Desktop\\README.url') }

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

function Build-AiRequest {
  param(
    [string[]]$Summaries,
    [string]$ReadmeText
  )

  $systemPrompt = @"
You are a Windows system-hardening assistant for CyberPatriot scoring.
Return ONLY a raw JSON array (no code fences) of absolute file paths from the provided list that must be deleted because they contai
n prohibited content (media, leaked credentials, sensitive PII, etc.).
If uncertain about a file, err on the side of removing it.
Do not invent file paths; only choose from the provided list.
Never flag Windows system files, standard application resources, or anything required by CyberPatriot operations.
If nothing should be removed, respond with [].
"@

  $inventoryBlock = ($Summaries -join [Environment]::NewLine)
  $userPrompt = @"
You are reviewing potential prohibited files on a Windows host.

README CONTENT:
$ReadmeText

PROHIBITED FILE CANDIDATES (first $($Summaries.Count) entries):
$inventoryBlock

Return ONLY a JSON array of the exact file paths that must be removed.
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
    [pscustomobject[]]$Candidates,
    [string]$ReadmeText
  )

  if (-not $Candidates -or $Candidates.Count -eq 0) {
    return @()
  }

  $summaries = @($Candidates | ForEach-Object { $_.Summary })
  $bodyJson = Build-AiRequest -Summaries $summaries -ReadmeText $ReadmeText

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

function Invoke-ProhibitedFilesAssessment {
  param([switch]$Remove)

  Write-Info 'Collecting potential prohibited files'
  $candidatesInfo = Get-ProhibitedFileCandidates
  $candidates = $candidatesInfo.Items

  if (-not $candidates -or $candidates.Count -eq 0) {
    return [pscustomobject]@{
      Candidates    = @()
      Flagged       = @()
      Condensed     = @()
      Removed       = @()
      OriginalCount = 0
      UserDeclined  = $false
      Truncated     = $false
    }
  }

  $truncNote = if ($candidatesInfo.Truncated) {
    " (truncated at limit {0})" -f $script:MaxCandidates
  } else {
    ''
  }
  Write-Info ("Identified {0} candidate files{1}" -f $candidates.Count, $truncNote)
  if ($candidatesInfo.Truncated) {
    Write-Warn ("Candidate list truncated at {0} entries; review remaining directories manually if time permits." -f $script:MaxCandidates)
  }

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

  Write-Info 'Requesting AI classification of prohibited files'
  $flagged = Invoke-Classification -Candidates $candidates -ReadmeText $readmeText

  if (-not $flagged -or $flagged.Count -eq 0) {
    return [pscustomobject]@{
      Candidates    = @($candidates)
      Flagged       = @()
      Condensed     = @()
      Removed       = @()
      OriginalCount = $candidatesInfo.OriginalCount
      UserDeclined  = $false
      Truncated     = $candidatesInfo.Truncated
    }
  }

  $condensed = Get-CondensedPaths -Paths $flagged
  Write-Info 'AI flagged the following items for removal:'
  foreach ($entry in $flagged) {
    Write-Host ("  - {0}" -f $entry)
  }

  $removed = @()
  $userDeclined = $false
  if ($Remove) {
    $confirmation = Read-Host 'Remove the listed files now? (Y/N, default Y)'
    if ([string]::IsNullOrWhiteSpace($confirmation)) { $confirmation = 'Y' }

    if ($confirmation.Trim().StartsWith('Y', [System.StringComparison]::OrdinalIgnoreCase)) {
      foreach ($path in $flagged) {
        try {
          if (Test-Path -LiteralPath $path -PathType Leaf) {
            Write-Info ("Removing prohibited file {0}" -f $path)
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            $removed += $path
          } elseif (Test-Path -LiteralPath $path -PathType Container) {
            Write-Info ("Removing prohibited directory {0}" -f $path)
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
      Write-Info 'User declined removal; no changes were made to flagged files.'
    }
  }

  return [pscustomobject]@{
    Candidates    = @($candidates)
    Flagged       = @($flagged)
    Condensed     = @($condensed)
    Removed       = @($removed)
    OriginalCount = $candidatesInfo.OriginalCount
    UserDeclined  = $userDeclined
    Truncated     = $candidatesInfo.Truncated
  }
}

function Invoke-Verify {
  param($Context)

  try {
    $result = Invoke-ProhibitedFilesAssessment
  } catch {
    Write-Err ("ProhibitedFiles verification failed: {0}" -f $_.Exception.Message)
    return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message ('Verification error: ' + $_.Exception.Message))
  }

  if ($result.Flagged.Count -eq 0) {
    return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message 'No prohibited files detected by AI review.')
  }

  $preview = ($result.Flagged | Select-Object -First 5)
  $previewText = if ($preview) { $preview -join ', ' } else { 'AI flagged prohibited files.' }
  return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message ('Flagged files: ' + $previewText))
}

function Invoke-Apply {
  param($Context)

  try {
    $result = Invoke-ProhibitedFilesAssessment -Remove
  } catch {
    Write-Err ("ProhibitedFiles apply failed: {0}" -f $_.Exception.Message)
    return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message ('Apply error: ' + $_.Exception.Message))
  }

  if ($result.Flagged.Count -eq 0) {
    return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message 'No prohibited files identified.')
  }

  $summary = if ($result.UserDeclined) {
    'User declined removal of AI-flagged files.'
  } elseif ($result.Removed.Count -gt 0) {
    ('Removed {0} item(s).' -f $result.Removed.Count)
  } else {
    'AI flagged items but none were removed (missing paths or errors).'
  }

  return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message $summary)
}

Export-ModuleMember -Function Test-Ready,Invoke-Verify,Invoke-Apply
