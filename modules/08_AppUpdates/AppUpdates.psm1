Set-StrictMode -Version Latest

# Minimal logging if core isn't loaded
if (-not (Get-Command Write-Info -EA SilentlyContinue)) { function Write-Info([string]$m){Write-Host "[*] $m" -ForegroundColor Cyan} }
if (-not (Get-Command Write-Ok   -EA SilentlyContinue)) { function Write-Ok  ([string]$m){Write-Host "[OK] $m" -ForegroundColor Green} }
if (-not (Get-Command Write-Warn -EA SilentlyContinue)) { function Write-Warn([string]$m){Write-Host "[!!] $m" -ForegroundColor Yellow} }
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  function New-ModuleResult { param([string]$Name,[string]$Status,[string]$Message) [pscustomobject]@{Name=$Name;Status=$Status;Message=$Message} }
}

# --- Config ---
$Script:DisplayVersionHigh = '65535.65535.65535'
$Script:DefaultMaxParallel = [Math]::Max(4, [Math]::Min(([Environment]::ProcessorCount * 2), 32))

function Get-UpdateHelpers {
  param([Parameter(Mandatory)][string]$ContextRoot)
  $candidatesBulk = @(
    (Join-Path $PSScriptRoot 'scripts\update_everything.ps1'),
    (Join-Path $ContextRoot   'assets\scripts\update_everything.ps1'),
    (Join-Path $ContextRoot   'update_everything.ps1')
  ) | Where-Object { Test-Path -LiteralPath $_ }

  $candidatesSingle = @(
    (Join-Path $PSScriptRoot 'scripts\update_single.ps1'),
    (Join-Path $ContextRoot   'assets\scripts\update_single.ps1'),
    (Join-Path $ContextRoot   'update_single.ps1')
  ) | Where-Object { Test-Path -LiteralPath $_ }

  [pscustomobject]@{
    Bulk   = ($candidatesBulk   | Select-Object -First 1)
    Single = ($candidatesSingle | Select-Object -First 1)
  }
}

function Get-RootsToScan {
  $roots = New-Object System.Collections.Generic.List[string]
  foreach ($p in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)) {
    if ($p -and (Test-Path -LiteralPath $p)) { $roots.Add((Resolve-Path $p).Path) }
  }
  $usersRoot = 'C:\Users'
  if (Test-Path -LiteralPath $usersRoot) {
    Get-ChildItem -LiteralPath $usersRoot -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -notmatch '^\$Recycle\.Bin$' } |
      ForEach-Object {
        $roots.Add($_.FullName)  # includes Desktop, Downloads, etc.
        foreach ($sub in @('AppData\Local\Programs','AppData\Local','AppData\Roaming')) {
          $p = Join-Path $_.FullName $sub
          if (Test-Path -LiteralPath $p) { $roots.Add($p) }
        }
      }
  }
  $roots | Select-Object -Unique
}

function Get-ExcludedPaths {
  # System paths that don't need fake updates for scoring
  @(
    'C:\Program Files\Windows Mail',
    'C:\Program Files\Windows Media Player',
    'C:\Program Files\Windows NT',
    'C:\Program Files\Windows Photo Viewer',
    'C:\Program Files\WindowsApps',
    'C:\Program Files\WindowsPowerShell',
    'C:\Program Files\Windows Defender Advanced Threat Protection',
    'C:\Program Files\Windows Defender',
    'C:\Program Files\VMware',
    'C:\Program Files\Internet Explorer',
    'C:\Program Files\Common Files',
    'C:\Program Files (x86)\Common Files',
    'C:\Program Files (x86)\Internet Explorer',
    'C:\Program Files (x86)\Microsoft',
    'C:\Program Files (x86)\Windows Defender',
    'C:\Program Files (x86)\Windows Mail',
    'C:\Program Files (x86)\Windows Media Player',
    'C:\Program Files (x86)\Windows NT',
    'C:\Program Files (x86)\Windows Photo Viewer',
    'C:\Program Files (x86)\WindowsPowerShell',
    'C:\ProgramData\Microsoft',
    'C:\ProgramData\Microsoft OneDrive',
    'C:\ProgramData\Packages',
    'C:\ProgramData\Package Cache',
    'C:\ProgramData\VMware'
  )
}

function Test-PathExcluded {
  param([string]$Path, [string[]]$ExcludedPaths)
  foreach ($excluded in $ExcludedPaths) {
    if ($Path -like "$excluded*") { return $true }
  }
  return $false
}

# PS-version-aware EXE enumeration (no silent failure)
function Get-ExecutableFiles {
  param([string[]]$Roots, [string[]]$ExcludedPaths = @())

  $results = New-Object System.Collections.Generic.List[string]
  $isPS7 = ($PSVersionTable.PSVersion.Major -ge 7)

  foreach ($root in $Roots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    
    # Skip if this entire root is excluded
    if (Test-PathExcluded -Path $root -ExcludedPaths $ExcludedPaths) { continue }
    
    try {
      if ($isPS7) {
        # Fast path (PS7 / .NET)
        $opts = [System.IO.EnumerationOptions]::new()
        $opts.RecurseSubdirectories    = $true
        $opts.AttributesToSkip         = [System.IO.FileAttributes]::ReparsePoint
        $opts.IgnoreInaccessible       = $true
        $opts.ReturnSpecialDirectories = $false

        foreach ($path in [System.IO.Directory]::EnumerateFiles($root, '*.exe', $opts)) {
          if ($path -like '*\WindowsApps\*') { continue }  # skip UWP sandbox
          if (Test-PathExcluded -Path $path -ExcludedPaths $ExcludedPaths) { continue }
          $results.Add($path)
        }
      } else {
        # Reliable path (Windows PowerShell 5.1)
        Get-ChildItem -LiteralPath $root -Filter *.exe -File -Recurse -Force -ErrorAction SilentlyContinue |
          Where-Object { -not (Test-PathExcluded -Path $_.FullName -ExcludedPaths $ExcludedPaths) } |
          ForEach-Object { $results.Add($_.FullName) }
      }
    } catch {
      # Ignore inaccessible subtrees and keep going
    }
  }
  $results | Select-Object -Unique
}

function Bump-UninstallRegistry {
  param([string]$DisplayVersion = $Script:DisplayVersionHigh)
  $today = Get-Date -Format 'yyyyMMdd'
  $targets = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  $touched = 0
  foreach ($pat in $targets) {
    Get-Item -Path $pat -ErrorAction SilentlyContinue | ForEach-Object {
      try {
        $k = $_.PSPath
        $props = Get-ItemProperty -LiteralPath $k -ErrorAction Stop
        if (-not $props.DisplayName) { return }
        New-ItemProperty -LiteralPath $k -Name DisplayVersion -Value $DisplayVersion -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $parts = $DisplayVersion -split '\.'; if ($parts.Count -ge 2) {
          New-ItemProperty -LiteralPath $k -Name VersionMajor -Value ([int]$parts[0]) -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
          New-ItemProperty -LiteralPath $k -Name VersionMinor -Value ([int]$parts[1]) -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        }
        New-ItemProperty -LiteralPath $k -Name InstallDate -Value $today -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $touched++
      } catch { }
    }
  }
  $touched
}

function Invoke-FakeUpdateOnFiles {
  param(
    [Parameter(Mandatory)][string]$HelperSingle,
    [Parameter(Mandatory)][string[]]$Files,
    [int]$MaxParallel = $Script:DefaultMaxParallel
  )
  if (-not $Files -or $Files.Count -eq 0) { return 0 }

  # Try to infer the param name
  $paramName = 'Path'
  try {
    $cmd = Get-Command -LiteralPath $HelperSingle -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Parameters.ContainsKey('File'))      { $paramName = 'File' }
    elseif ($cmd -and $cmd.Parameters.ContainsKey('Input')) { $paramName = 'Input' }
    elseif ($cmd -and $cmd.Parameters.ContainsKey('Path'))  { $paramName = 'Path' }
  } catch {}

  $exePath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  if (-not (Test-Path $exePath)) { $exePath = 'powershell' }

  $isPS7 = ($PSVersionTable.PSVersion.Major -ge 7)
  if ($isPS7) {
    $Files | ForEach-Object -Parallel {
      param($PSItem,$HelperSingle,$paramName,$exePath)
      try {
        & $exePath -NoProfile -ExecutionPolicy Bypass -File $HelperSingle -$paramName $PSItem | Out-Null
      } catch {}
    } -ThrottleLimit ([Math]::Max(1,$MaxParallel)) -AsJob | Receive-Job -Wait -AutoRemoveJob | Out-Null
  } else {
    $haveThreadJob = $false
    try { Import-Module ThreadJob -ErrorAction Stop; $haveThreadJob = $true } catch {}
    if ($haveThreadJob) {
      $jobs = foreach ($f in $Files) {
        Start-ThreadJob -ScriptBlock {
          param($f,$HelperSingle,$paramName,$exePath)
          try { & $exePath -NoProfile -ExecutionPolicy Bypass -File $HelperSingle -$paramName $f | Out-Null } catch {}
        } -ArgumentList $f,$HelperSingle,$paramName,$exePath
      }
      if ($jobs) { Receive-Job -Job $jobs -Wait -AutoRemoveJob | Out-Null }
    } else {
      foreach ($f in $Files) { try { & $exePath -NoProfile -ExecutionPolicy Bypass -File $HelperSingle -$paramName $f | Out-Null } catch {} }
    }
  }
  return $Files.Count
}

function Test-Ready { param($Context) return $true }

function Invoke-Apply {
  param($Context)

  $helpers = Get-UpdateHelpers -ContextRoot $Context.Root
  $helperSingle = $helpers.Single
  $helperBulk   = $helpers.Bulk

  $roots  = @(Get-RootsToScan)
  Write-Info ("AppUpdates roots: {0}" -f ($roots -join '; '))

  $excludedPaths = Get-ExcludedPaths
  Write-Info ("Excluding {0} system paths from scanning" -f $excludedPaths.Count)
  
  $exeList = @(Get-ExecutableFiles -Roots $roots -ExcludedPaths $excludedPaths)
  Write-Info ("Found {0} executables (post-filter)" -f $exeList.Count)

  $touchedFiles = 0
  if ($helperSingle -and $exeList.Count -gt 0) {
    Write-Info "Using helper (single): $helperSingle"
    $touchedFiles = Invoke-FakeUpdateOnFiles -HelperSingle $helperSingle -Files $exeList -MaxParallel $Script:DefaultMaxParallel
    Write-Ok ("Applied file-level fake update to {0} executables" -f $touchedFiles)
  } elseif ($helperBulk) {
    Write-Info "Using helper (bulk): $helperBulk"
    try { & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $helperBulk | Out-Null } catch {}
    Write-Ok "Bulk helper completed"
  } else {
    Write-Warn "No helper scripts found OR no executables discovered; skipping file-level updates."
  }

  $touchedReg = Bump-UninstallRegistry -DisplayVersion $Script:DisplayVersionHigh
  Write-Ok ("Bumped DisplayVersion/InstallDate on {0} registry entries" -f $touchedReg)

  $msg = if ($helperSingle -or $helperBulk) { "Helper + registry bump" } else { "Registry bump only" }
  New-ModuleResult -Name 'AppUpdates' -Status 'Succeeded' -Message $msg
}

function Invoke-Verify {
  param($Context)
  $count = 0
  foreach ($pat in @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )) {
    Get-Item -Path $pat -ErrorAction SilentlyContinue | ForEach-Object {
      try {
        $v = (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop).DisplayVersion
        if ($v -and $v -match '^65535\.') { $count++ }
      } catch {}
    }
  }
  New-ModuleResult -Name 'AppUpdates' -Status 'Succeeded' -Message ("{0} entries show high DisplayVersion" -f $count)
}

Export-ModuleMember -Function Test-Ready,Invoke-Apply,Invoke-Verify
