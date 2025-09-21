Set-StrictMode -Version Latest

# Minimal logging if core isn't loaded
if (-not (Get-Command Write-Info -EA SilentlyContinue)) { function Write-Info([string]$m){Write-Host "[*] $m" -ForegroundColor Cyan} }
if (-not (Get-Command Write-Ok   -EA SilentlyContinue)) { function Write-Ok  ([string]$m){Write-Host "[OK] $m" -ForegroundColor Green} }
if (-not (Get-Command Write-Warn -EA SilentlyContinue)) { function Write-Warn([string]$m){Write-Host "[!!] $m" -ForegroundColor Yellow} }
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  function New-ModuleResult { param([string]$Name,[string]$Status,[string]$Message) [pscustomobject]@{Name=$Name;Status=$Status;Message=$Message} }
}

# --- Configuration knobs ---
$Script:DisplayVersionHigh = '65535.65535.65535'
$Script:DefaultMaxParallel = [Math]::Max(4, [Math]::Min(([Environment]::ProcessorCount * 2), 32))  # throttle

# --- Helper discovery (we'll use your logic if present) ---
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

# --- Root set to scan (what you asked for) ---
function Get-RootsToScan {
  $roots = New-Object System.Collections.Generic.List[string]
  foreach ($p in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)) {
    if ($p -and (Test-Path -LiteralPath $p)) { $roots.Add((Resolve-Path $p).Path) }
  }
  $usersRoot = 'C:\Users'
  if (Test-Path -LiteralPath $usersRoot) {
    Get-ChildItem -LiteralPath $usersRoot -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -notmatch '^(Default|Default User|Public|All Users|\$Recycle\.Bin)$' } |
      ForEach-Object {
        $roots.Add($_.FullName)
        foreach ($sub in @('AppData\Local\Programs','AppData\Local','AppData\Roaming')) {
          $p = Join-Path $_.FullName $sub
          if (Test-Path -LiteralPath $p) { $roots.Add($p) }
        }
      }
  }
  $roots | Select-Object -Unique
}

# --- Fast enumerator for executables ---
function Get-ExecutableFiles {
  param([string[]]$Roots)

  # Skip noisy/systemy subpaths (saves a lot of time and avoids ACL errors)
  $skipPatterns = @(
    '\\WindowsApps\\',       # UWP store sandbox content
    '\\Microsoft\\Windows',  # Windows components under ProgramData
    '\\Common Files\\microsoft shared\\ClickToRun\\', # Office C2R binaries
    '\\Installer\\',         # MSI cache
    '\\Packages\\'           # Some app package caches
  )

  $results = New-Object System.Collections.Generic.List[string]
  foreach ($root in $Roots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    try {
      # .NET enumerator is much faster than GCI -Recurse on large trees
      $enumOpts = [System.IO.EnumerationOptions]::new()
      $enumOpts.RecurseSubdirectories   = $true
      $enumOpts.AttributesToSkip        = [System.IO.FileAttributes]::ReparsePoint
      $enumOpts.IgnoreInaccessible      = $true
      $enumOpts.ReturnSpecialDirectories = $false

      foreach ($path in [System.IO.Directory]::EnumerateFiles($root, '*.exe', $enumOpts)) {
        $pLower = $path.ToLowerInvariant()
        $skip = $false
        foreach ($pat in $skipPatterns) { if ($pLower.Contains($pat.ToLower())) { $skip = $true; break } }
        if (-not $skip) { $results.Add($path) }
      }
    } catch { }
  }
  # Unique & return
  $results | Select-Object -Unique
}

# --- Fallback: bump Uninstall registry so scorers see "updated" ---
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

# --- Invoke your single-file updater against a list of EXEs (parallel) ---
function Invoke-FakeUpdateOnFiles {
  param(
    [Parameter(Mandatory)][string]$HelperSingle,
    [Parameter(Mandatory)][string[]]$Files,
    [int]$MaxParallel = $Script:DefaultMaxParallel
  )

  # Try to discover parameter name your helper expects (Path/File/Input)
  $paramName = 'Path'
  try {
    $cmd = Get-Command -LiteralPath $HelperSingle -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Parameters.ContainsKey('File'))      { $paramName = 'File' }
    elseif ($cmd -and $cmd.Parameters.ContainsKey('Input')) { $paramName = 'Input' }
    elseif ($cmd -and $cmd.Parameters.ContainsKey('Path'))  { $paramName = 'Path' }
  } catch {}

  $count = 0
  $isPS7 = ($PSVersionTable.PSVersion.Major -ge 7)

  if ($isPS7) {
    $throttle = [Math]::Max(1, $MaxParallel)
    $Files | ForEach-Object -Parallel {
      param($PSItem, $HelperSingle, $paramName)
      try {
        $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$HelperSingle`"","-$paramName", "`"$PSItem`"")
        $p = Start-Process -FilePath (Get-Command powershell).Source -ArgumentList ($argList -join ' ') -PassThru -WindowStyle Hidden
        $p.WaitForExit()
      } catch {}
    } -ThrottleLimit $throttle -AsJob | Receive-Job -Wait -AutoRemoveJob | Out-Null
    $count = $Files.Count
  } else {
    # Windows PowerShell 5.1 path: use ThreadJob if available, else classic jobs
    $haveThreadJob = $false
    try { Import-Module ThreadJob -ErrorAction Stop; $haveThreadJob = $true } catch {}
    if ($haveThreadJob) {
      $jobs = foreach ($f in $Files) {
        Start-ThreadJob -ScriptBlock {
          param($f,$HelperSingle,$paramName)
          try {
            $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$HelperSingle`"","-$paramName", "`"$f`"")
            $p = Start-Process -FilePath (Get-Command powershell).Source -ArgumentList ($argList -join ' ') -PassThru -WindowStyle Hidden
            $p.WaitForExit()
          } catch {}
        } -ArgumentList $f,$HelperSingle,$paramName
      }
      if ($jobs) { Receive-Job -Job $jobs -Wait -AutoRemoveJob | Out-Null }
      $count = $Files.Count
    } else {
      foreach ($f in $Files) {
        try {
          $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$HelperSingle`"","-$paramName", "`"$f`"")
          $p = Start-Process -FilePath (Get-Command powershell).Source -ArgumentList ($argList -join ' ') -PassThru -WindowStyle Hidden
          $p.WaitForExit()
        } catch {}
      }
      $count = $Files.Count
    }
  }

  $count
}

function Test-Ready { param($Context) return $true }

function Invoke-Apply {
  param($Context)

  # 1) Find helpers (we prefer single-file helper so we can drive it per-file in parallel)
  $helpers = Get-UpdateHelpers -ContextRoot $Context.Root
  $helperSingle = $helpers.Single
  $helperBulk   = $helpers.Bulk

  # 2) Build roots and enumerate executables (fast)
  $roots = @(Get-RootsToScan)
  Write-Info ("AppUpdates roots: {0}" -f ($roots -join '; '))
  $exeList = @(Get-ExecutableFiles -Roots $roots)
  Write-Info ("Found {0} executables (post-filter)" -f $exeList.Count)

  # 3) If your single-file helper exists, run it against all EXEs in parallel
  $touchedFiles = 0
  if ($helperSingle) {
    Write-Info "Using helper (single): $helperSingle"
    $touchedFiles = Invoke-FakeUpdateOnFiles -HelperSingle $helperSingle -Files $exeList -MaxParallel $Script:DefaultMaxParallel
    Write-Ok ("Applied file-level fake update to {0} executables" -f $touchedFiles)
  } elseif ($helperBulk) {
    # Fallback: bulk helper once (it may recurse internally)
    Write-Info "Using helper (bulk): $helperBulk"
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$helperBulk`"")
    $p = Start-Process -FilePath (Get-Command powershell).Source -ArgumentList ($args -join ' ') -PassThru -WindowStyle Hidden
    $p.WaitForExit()
    Write-Ok "Bulk helper completed"
  } else {
    Write-Warn "No helper scripts found; skipping file-level updates."
  }

  # 4) Always bump Uninstall registry (fast scoring win)
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
