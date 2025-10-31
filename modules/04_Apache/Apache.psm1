Set-StrictMode -Version Latest

if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

$script:ModuleName      = 'Apache'
$script:DownloadUri     = 'https://storage.googleapis.com/sigma.00.edu.ci/httpd.conf'
$script:TempFileName    = 'cp-httpd.conf'
$script:PathPatterns    = @(
  'C:\Apache24\conf\httpd.conf',
  'C:\xampp\apache\conf\httpd.conf',
  'C:\wamp64\bin\apache\apache2.4.*\conf\httpd.conf',
  'C:\Bitnami\wampstack-*\apache2\conf\httpd.conf'
)

function Test-Ready {
  param($Context)

  $icacls = Get-Command 'icacls.exe' -EA SilentlyContinue
  if (-not $icacls) {
    Write-Warn 'icacls.exe not found; unable to reset permissions.'
    return $false
  }

  if (-not (Get-Command Invoke-WebRequest -EA SilentlyContinue)) {
    Write-Warn 'Invoke-WebRequest is unavailable; cannot download Apache configuration.'
    return $false
  }

  return $true
}

function Get-HttpdCandidates {
  $resolved = @()
  foreach ($pattern in $script:PathPatterns) {
    if ($pattern -match '[*?]') {
      $matches = @(Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue)
      if ($matches) {
        $resolved += ($matches | ForEach-Object { $_.FullName })
      }
    }
    else {
      if (Test-Path -LiteralPath $pattern) {
        try {
          $resolved += [System.IO.Path]::GetFullPath($pattern)
        } catch {
          $resolved += $pattern
        }
      }
    }
  }

  return @($resolved | Sort-Object -Unique)
}

function Select-HttpdPath {
  $candidates = Get-HttpdCandidates

  Write-Host ''
  Write-Host 'Select the Apache httpd.conf file to replace:' -ForegroundColor Cyan
  $index = 1
  foreach ($candidate in $candidates) {
    Write-Host ("  {0}. {1}" -f $index, $candidate)
    $index++
  }
  Write-Host '  C. Enter a custom path'
  Write-Host ''

  while ($true) {
    $choice = Read-Host 'Enter the option number or provide a full path'
    if (-not $choice) {
      Write-Warn 'Selection cannot be empty.'
      continue
    }

    if ($choice -match '^(?i)c$') {
      $custom = Read-Host 'Enter the full path to httpd.conf'
      if (Test-Path -LiteralPath $custom) {
        return [System.IO.Path]::GetFullPath($custom)
      }
      Write-Warn 'Provided path does not exist. Please try again.'
      continue
    }

    if ($choice -match '^\d+$') {
      $idx = [int]$choice
      if ($idx -ge 1 -and $idx -le $candidates.Count) {
        return $candidates[$idx - 1]
      }
      Write-Warn 'Invalid selection number.'
      continue
    }

    if (Test-Path -LiteralPath $choice) {
      return [System.IO.Path]::GetFullPath($choice)
    }

    Write-Warn 'Input was not recognized. Enter a listed number or an existing path.'
  }
}

function Invoke-DownloadHttpdConfig {
  $temp = Join-Path ([System.IO.Path]::GetTempPath()) $script:TempFileName
  $prev = $ProgressPreference
  try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $script:DownloadUri -OutFile $temp -UseBasicParsing -ErrorAction Stop | Out-Null
  }
  finally {
    $ProgressPreference = $prev
  }

  if (-not (Test-Path -LiteralPath $temp)) {
    throw 'Failed to download Apache configuration file.'
  }

  return $temp
}

function Invoke-BackupFile {
  param([Parameter(Mandatory)][string]$Path)

  $backup = "$Path.bak"
  try {
    Copy-Item -LiteralPath $Path -Destination $backup -Force -ErrorAction Stop | Out-Null
    Write-Info ("Created backup at {0}" -f $backup)
  }
  catch {
    Write-Warn ("Unable to create backup of {0}: {1}" -f $Path, $_.Exception.Message)
  }
}

function Invoke-ReplaceHttpdConfig {
  param(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Destination
  )

  $destDir = Split-Path -Parent $Destination
  if (-not (Test-Path -LiteralPath $destDir)) {
    throw ("Destination directory {0} does not exist." -f $destDir)
  }

  if (Test-Path -LiteralPath $Destination) {
    Invoke-BackupFile -Path $Destination
  }

  Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop
}

function Set-HttpdPermissions {
  param([Parameter(Mandatory)][string]$FilePath)

  $dir = Split-Path -Parent $FilePath
  $icacls = Get-Command 'icacls.exe' -EA Stop

  $dirArgs = @(
    $dir,
    '/inheritance:e',
    '/grant:r',
    'BUILTIN\Administrators:(OI)(CI)(F)',
    'NT AUTHORITY\SYSTEM:(OI)(CI)(F)',
    'NT AUTHORITY\Authenticated Users:(OI)(CI)(M)',
    'BUILTIN\Users:(OI)(CI)(RX)'
  )
  $proc1 = Start-Process -FilePath $icacls.Source -ArgumentList $dirArgs -Wait -PassThru -NoNewWindow
  if ($proc1.ExitCode -ne 0) {
    throw ("icacls failed for directory {0} (exit code {1})." -f $dir, $proc1.ExitCode)
  }

  $fileArgs = @(
    $FilePath,
    '/inheritance:e',
    '/reset'
  )
  $proc2 = Start-Process -FilePath $icacls.Source -ArgumentList $fileArgs -Wait -PassThru -NoNewWindow
  if ($proc2.ExitCode -ne 0) {
    throw ("icacls failed for file {0} (exit code {1})." -f $FilePath, $proc2.ExitCode)
  }
}

function Get-FileHashText {
  param([Parameter(Mandatory)][string]$Path)
  $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop
  return $hash.Hash
}

function Invoke-Verify {
  param($Context)

  try {
    $target = Select-HttpdPath
    if (-not $target) {
      return (New-ModuleResult -Name $script:ModuleName -Status 'Skipped' -Message 'No Apache configuration path selected.')
    }

    if (-not (Test-Path -LiteralPath $target)) {
      return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message 'Selected Apache configuration file is missing.')
    }

    $downloaded = Invoke-DownloadHttpdConfig
    try {
      $targetHash = Get-FileHashText -Path $target
      $sourceHash = Get-FileHashText -Path $downloaded
    }
    finally {
      Remove-Item -LiteralPath $downloaded -ErrorAction SilentlyContinue
    }

    if ($targetHash -eq $sourceHash) {
      return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message 'Apache configuration matches expected policy.')
    }

    return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message 'Apache configuration does not match expected policy.')
  }
  catch {
    Write-Err ("Apache verification failed: {0}" -f $_.Exception.Message)
    return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message ('Verification error: ' + $_.Exception.Message))
  }
}

function Invoke-Apply {
  param($Context)

  try {
    $target = Select-HttpdPath
    if (-not $target) {
      return (New-ModuleResult -Name $script:ModuleName -Status 'Skipped' -Message 'No Apache configuration path selected.')
    }

    $downloaded = Invoke-DownloadHttpdConfig
    try {
      Invoke-ReplaceHttpdConfig -Source $downloaded -Destination $target
    }
    finally {
      Remove-Item -LiteralPath $downloaded -ErrorAction SilentlyContinue
    }

    Set-HttpdPermissions -FilePath $target

    return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message 'Replaced Apache configuration and reset permissions.')
  }
  catch {
    Write-Err ("Apache module failed: {0}" -f $_.Exception.Message)
    return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message ('Apply error: ' + $_.Exception.Message))
  }
}

Export-ModuleMember -Function Test-Ready,Invoke-Verify,Invoke-Apply
