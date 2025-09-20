Set-StrictMode -Version Latest

# --- Imports (safe to import again even if Run.ps1 already did) ---
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module -Force (Join-Path $here 'Utils.psm1')
Import-Module -Force (Join-Path $here 'Contracts.psm1')
Import-Module -Force (Join-Path $here 'Parsing.psm1')  # for Get-ReadmeInfo (OpenRouter)

# --- Fallbacks if Utils/Contracts weren’t imported for some reason ---
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  function Write-Info([string]$m){Write-Host "[*] $m" -ForegroundColor Cyan}
  function Write-Ok  ([string]$m){Write-Host "[OK] $m" -ForegroundColor Green}
  function Write-Warn([string]$m){Write-Host "[!!] $m" -ForegroundColor Yellow}
  function Write-Err ([string]$m){Write-Host "[xx] $m" -ForegroundColor Red}
}
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  function New-ModuleResult { param([string]$Name,[string]$Status,[string]$Message)
    [pscustomobject]@{Name=$Name;Status=$Status;Message=$Message} }
}

# --- Minimal OS/Context helpers ---
function Get-OSId {
  try {
    $os = Get-CimInstance Win32_OperatingSystem
    $build = [int]$os.BuildNumber
    if ($os.Caption -match 'Windows 11') { return 'win11' }
    elseif ($build -ge 20348) { return 'server2022' }   # 20348 = Server 2022
    elseif ($build -ge 17763) { return 'server2019' }   # 17763 = Server 2019
  } catch {}
  return 'win11'
}
function Get-OSProfile { param([string]$Profile) return $Profile }

function Build-Context {
  param([string]$Root)
  $readme = $null
  try { $readme = Get-ReadmeInfo -Root $Root } catch { Write-Warn "README parse failed: $($_.Exception.Message)"; $readme = [pscustomobject]@{ AuthorizedUsers=@(); AuthorizedAdmins=@(); Directives=[pscustomobject]@{}; SourcePath=$null } }
  $auto = $null
  try { $auto = Get-AutoLogonUser } catch {}
  [pscustomobject]@{
    Root          = $Root
    OS            = Get-OSId
    Readme        = $readme
    AutoLogonUser = $auto
    Timestamp     = Get-Date
  }
}

# --- Module discovery: supports BOTH direct and nested layouts ---
function Get-Modules {
  param([Parameter(Mandatory)][string]$Root)

  $modsRoot = Join-Path $Root 'modules'
  if (-not (Test-Path $modsRoot)) { return @() }

  $out = @()

  foreach ($catDir in Get-ChildItem -Path $modsRoot -Directory) {
    # Priority default from NN_ prefix (e.g., "06_ServiceAuditing" => 6*100 = 600)
    $folderPriority = 9999
    if ($catDir.Name -match '^(\d{2})_') { $folderPriority = [int]$Matches[1] * 100 }

    # --- DIRECT layout: *.psm1 directly under the category folder ---
    $catMetaPath = Join-Path $catDir.FullName 'module.json'
    $catMeta = $null
    if (Test-Path $catMetaPath) {
      try { $catMeta = Get-Content -LiteralPath $catMetaPath -Raw | ConvertFrom-Json } catch {}
    }

    $directPsm1s = Get-ChildItem -Path $catDir.FullName -Filter *.psm1 -File -EA SilentlyContinue
    foreach ($psm1 in $directPsm1s) {
      # per-file json (optional): <BaseName>.json sitting next to the psm1
      $peerJson = Join-Path $catDir.FullName ($psm1.BaseName + '.json')
      $meta = $catMeta
      if (Test-Path $peerJson) { try { $meta = Get-Content -LiteralPath $peerJson -Raw | ConvertFrom-Json } catch {} }

      $prio = if ($meta -and $meta.priority) { [int]$meta.priority } else { $folderPriority }
      $name = if ($meta -and $meta.name) { $meta.name } else { $psm1.BaseName }

      $out += [pscustomobject]@{
        Name     = $name
        Category = $catDir.Name
        Path     = $psm1.FullName
        Priority = $prio
        Meta     = $meta
      }
    }

    # --- NESTED layout: look one level deeper for submodule folders with their own psm1 ---
    foreach ($modDir in Get-ChildItem -Path $catDir.FullName -Directory -EA SilentlyContinue) {
      $psm1 = Get-ChildItem -Path $modDir.FullName -Filter *.psm1 -File -EA SilentlyContinue | Select-Object -First 1
      if (-not $psm1) { continue }
      $jsonPath = Join-Path $modDir.FullName 'module.json'
      $meta = $null
      if (Test-Path $jsonPath) { try { $meta = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json } catch {} }
      $prio = if ($meta -and $meta.priority) { [int]$meta.priority } else { $folderPriority }
      $name = if ($meta -and $meta.name) { $meta.name } else { $modDir.Name }
      $out += [pscustomobject]@{
        Name     = $name
        Category = $catDir.Name
        Path     = $psm1.FullName
        Priority = $prio
        Meta     = $meta
      }
    }
  }

  $out | Sort-Object Priority, Category, Name
}

function Start-Engine {
  [CmdletBinding()]
  param(
    [ValidateSet('Apply','Verify')][string]$Mode = 'Apply',
    [string]$Profile = 'Auto',
    [string]$Overlay,
    [int]$MaxParallel = 8,
    [switch]$WhatIf,
    [Parameter(Mandatory)][string]$Root
  )

  Write-Info "Starting engine (Mode=$Mode, Profile=$Profile, Overlay=$Overlay)"

  $ctx  = Build-Context -Root $Root
  $mods = Get-Modules  -Root $Root
  if (-not $mods -or $mods.Count -eq 0) { throw "No modules discovered under $Root\modules" }

  Write-Info ("Discovered {0} module(s): {1}" -f $mods.Count, ($mods | ForEach-Object {{ $_.Name }} -join ', '))

  foreach ($m in $mods) {
    try {
      Import-Module -Force -Name $m.Path
      $fnApply  = Get-Command -Name 'Invoke-Apply' -EA SilentlyContinue
      $fnVerify = Get-Command -Name 'Invoke-Verify' -EA SilentlyContinue
      $fnReady  = Get-Command -Name 'Test-Ready'    -EA SilentlyContinue

      if ($fnReady) {
        $ok = $true
        try { $ok = Test-Ready -Context $ctx } catch {}
        if ($ok -is [bool] -and -not $ok) { Write-Warn "Skipping $($m.Name) (Test-Ready=false)"; continue }
      }

      $fn = if ($Mode -eq 'Apply') { $fnApply } else { $fnVerify }
      if (-not $fn) { Write-Warn "Module $($m.Name) loaded but no function for Mode=$Mode"; continue }

      Write-Info ("Running {0} (prio {1})" -f $m.Name,$m.Priority)
      & $fn -Context $ctx | Out-Null
      Write-Ok "$($m.Name) completed"
    } catch {
      Write-Err ("{0} failed: {1}" -f $m.Name, $_.Exception.Message)
    }
  }

  Write-Ok "All modules done"
}

Export-ModuleMember -Function Start-Engine, Get-OSProfile
