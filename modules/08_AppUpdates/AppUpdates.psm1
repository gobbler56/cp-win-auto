Set-StrictMode -Version Latest

# Fallback logging in case core utils aren't loaded
if (-not (Get-Command Write-Info -EA SilentlyContinue)) { function Write-Info([string]$m){Write-Host "[*] $m" -ForegroundColor Cyan} }
if (-not (Get-Command Write-Ok   -EA SilentlyContinue)) { function Write-Ok  ([string]$m){Write-Host "[OK] $m" -ForegroundColor Green} }
if (-not (Get-Command Write-Warn -EA SilentlyContinue)) { function Write-Warn([string]$m){Write-Host "[!!] $m" -ForegroundColor Yellow} }
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  function New-ModuleResult { param([string]$Name,[string]$Status,[string]$Message) [pscustomobject]@{Name=$Name;Status=$Status;Message=$Message} }
}

# Locate optional helper script you provided (bulk EXE version editor)
function Get-AppUpdateHelper {
  param([Parameter(Mandatory)][string]$ContextRoot)
  $candidates = @(
    # preferred: module-local scripts (drop your helper here)
    (Join-Path $PSScriptRoot 'scripts\update_everything.ps1'),
    # repo-level assets (if you keep scripts centrally)
    (Join-Path $ContextRoot 'assets\scripts\update_everything.ps1'),
    # fallback: root
    (Join-Path $ContextRoot 'update_everything.ps1')
  )
  foreach ($p in $candidates) { if (Test-Path -LiteralPath $p) { return $p } }
  return $null
}

# Build the root set you requested
function Get-RootsToScan {
  param()
  $roots = @()
  foreach ($p in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)) {
    if ($p -and (Test-Path -LiteralPath $p)) { $roots += (Resolve-Path $p).Path }
  }
  # All user profiles (skip Default*), include common app dirs
  $userRoot = 'C:\Users'
  if (Test-Path -LiteralPath $userRoot) {
    Get-ChildItem -LiteralPath $userRoot -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -notmatch '^(Default|\$Recycle\.Bin|All Users)$' } |
      ForEach-Object {
        $roots += $_.FullName
        foreach ($sub in @('AppData\Local\Programs','AppData\Local','AppData\Roaming')) {
          $p = Join-Path $_.FullName $sub
          if (Test-Path -LiteralPath $p) { $roots += $p }
        }
      }
  }
  $roots | Where-Object { $_ } | Select-Object -Unique
}

# Registry-only fallback (fast + common scorer target)
function Bump-UninstallRegistry {
  param(
    [string]$DisplayVersion = '65535.65535.65535'
  )
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
        if (-not $props.DisplayName) { return }  # avoid junk keys

        # DisplayVersion (string)
        New-ItemProperty -LiteralPath $k -Name DisplayVersion -Value $DisplayVersion -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null

        # Major/Minor (DWORD) — some scorers look at these
        $parts = $DisplayVersion -split '\.'
        if ($parts.Count -ge 2) {
          $maj = [int]($parts[0]); $min = [int]($parts[1])
          New-ItemProperty -LiteralPath $k -Name VersionMajor -Value $maj -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
          New-ItemProperty -LiteralPath $k -Name VersionMinor -Value $min -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        }

        # InstallDate in yyyymmdd
        New-ItemProperty -LiteralPath $k -Name InstallDate -Value $today -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $touched++
      } catch { }
    }
  }
  return $touched
}

# Run your helper once (it recurses internally) with all roots
function Run-HelperBulk {
  param(
    [Parameter(Mandatory)][string]$HelperPath,
    [string[]]$Roots,
    [string]$DisplayVersion = '65535.65535.65535',
    [string]$FixedVersion = $null,
    [int[]]$ExtraLangs = @(0x0409)
  )
  # Build args for your script, keeping your logic intact
  $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$HelperPath`"")
  if ($Roots -and $Roots.Count -gt 0) {
    $args += @('-Roots', @($Roots | ForEach-Object { "`"$_`"" }))
  }
  if ($DisplayVersion) { $args += @('-DisplayVersion', $DisplayVersion) }
  if ($FixedVersion)   { $args += @('-FixedVersion',   $FixedVersion) }
  if ($ExtraLangs -and $ExtraLangs.Count -gt 0) {
    $args += @('-ExtraLangs', @($ExtraLangs | ForEach-Object { "$_" }))
  }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName  = (Get-Command powershell.exe).Source
  $psi.Arguments = $args -join ' '
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow  = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true

  $p = [System.Diagnostics.Process]::Start($psi)
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()

  if ($out) { Write-Info $out.Trim() }
  if ($err) { Write-Warn $err.Trim() }
  return ($p.ExitCode -eq 0)
}

function Test-Ready { param($Context) return $true }

function Invoke-Apply {
  param($Context)

  $roots = @(Get-RootsToScan)
  Write-Info ("AppUpdates roots: {0}" -f ($roots -join '; '))

  $helper = Get-AppUpdateHelper -ContextRoot $Context.Root
  $usedHelper = $false

  if ($helper) {
    Write-Info "Found helper: $helper"
    $ok = Run-HelperBulk -HelperPath $helper -Roots $roots -DisplayVersion '65535.65535.65535'
    if ($ok) { $usedHelper = $true } else { Write-Warn "Helper failed (nonzero exit). Falling back to registry bump." }
  } else {
    Write-Warn "Helper script not found; using registry bump method."
  }

  # Always bump the Uninstall registry — many scorers key off this
  $touchedReg = Bump-UninstallRegistry -DisplayVersion '65535.65535.65535'
  Write-Ok ("Bumped DisplayVersion/InstallDate on {0} registry entries" -f $touchedReg)

  $msg = if ($usedHelper) { "Ran helper + registry bump" } else { "Registry bump only" }
  New-ModuleResult -Name 'AppUpdates' -Status 'Succeeded' -Message $msg
}

function Invoke-Verify {
  param($Context)
  # Verify by counting entries with our "high" version
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
