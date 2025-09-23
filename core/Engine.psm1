Set-StrictMode -Version Latest

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module -Force -DisableNameChecking (Join-Path $here 'Utils.psm1')
Import-Module -Force -DisableNameChecking (Join-Path $here 'Contracts.psm1')
Import-Module -Force -DisableNameChecking (Join-Path $here 'Parsing.psm1') -ErrorAction SilentlyContinue  # optional

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

function Get-OSId {
  try {
    $os = Get-CimInstance Win32_OperatingSystem
    $build = [int]$os.BuildNumber
    if ($os.Caption -match 'Windows 11') { return 'win11' }
    elseif ($build -ge 20348) { return 'server2022' }
    elseif ($build -ge 17763) { return 'server2019' }
  } catch {}
  return 'win11'
}
function Get-OSProfile { param([string]$Profile) return $Profile }

function Build-Context {
  param([string]$Root)
  $readme = $null
  try { $readme = Get-ReadmeInfo -Root $Root } catch { Write-Warn ("README parse failed: {0}" -f $_.Exception.Message) }
  if (-not $readme) { $readme = [pscustomobject]@{ AuthorizedUsers=@(); AuthorizedAdmins=@(); Directives=[pscustomobject]@{}; SourcePath=$null } }
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

# Discover both direct (NN_Category\*.psm1) and nested (NN_Category\Module\*.psm1)
function Get-Modules {
  param([Parameter(Mandatory)][string]$Root)
  $modsRoot = Join-Path $Root 'modules'
  if (-not (Test-Path $modsRoot)) { return @() }
  $out = @()
  foreach ($catDir in Get-ChildItem -Path $modsRoot -Directory) {
    $folderPriority = 9999
    if ($catDir.Name -match '^(\d{2})_') { $folderPriority = [int]$Matches[1] * 100 }

    $catMeta = $null
    $catMetaPath = Join-Path $catDir.FullName 'module.json'
    if (Test-Path $catMetaPath) { try { $catMeta = Get-Content -LiteralPath $catMetaPath -Raw | ConvertFrom-Json } catch {} }

    # direct
    foreach ($psm1 in (Get-ChildItem -Path $catDir.FullName -Filter *.psm1 -File -EA SilentlyContinue)) {
      $peerJson = Join-Path $catDir.FullName ($psm1.BaseName + '.json')
      $meta = $catMeta; if (Test-Path $peerJson) { try { $meta = Get-Content -LiteralPath $peerJson -Raw | ConvertFrom-Json } catch {} }
      $prio = if ($meta -and $meta.priority) { [int]$meta.priority } else { $folderPriority }
      $name = if ($meta -and $meta.name) { $meta.name } else { $psm1.BaseName }
      $out += [pscustomobject]@{ Name=$name; Category=$catDir.Name; Path=$psm1.FullName; Priority=$prio; Meta=$meta }
    }

    # nested
    foreach ($modDir in Get-ChildItem -Path $catDir.FullName -Directory -EA SilentlyContinue) {
      $psm1 = Get-ChildItem -Path $modDir.FullName -Filter *.psm1 -File -EA SilentlyContinue | Select-Object -First 1
      if (-not $psm1) { continue }
      $jsonPath = Join-Path $modDir.FullName 'module.json'
      $meta = $null; if (Test-Path $jsonPath) { try { $meta = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json } catch {} }
      $prio = if ($meta -and $meta.priority) { [int]$meta.priority } else { $folderPriority }
      $name = if ($meta -and $meta.name) { $meta.name } else { $modDir.Name }
      $out += [pscustomobject]@{ Name=$name; Category=$catDir.Name; Path=$psm1.FullName; Priority=$prio; Meta=$meta }
    }
  }
  $out | Sort-Object Priority, Category, Name
}

function Select-ModulesByName {
  param([object[]]$Modules, [string[]]$Include, [string[]]$Exclude)
  if ($Include) { $Include = @($Include) } else { $Include = @() }
  if ($Exclude) { $Exclude = @($Exclude) } else { $Exclude = @() }
  if ($Include.Count -gt 0) {
    $wanted = @()
    foreach ($pat in $Include) {
      $rx = [regex]::Escape($pat).Replace('\*','.*').Replace('\?','.')
      $wanted += $Modules | Where-Object { $_.Name -match $rx -or $_.Category -match $rx }
    }
    $Modules = $wanted | Select-Object -Unique
  }
  if ($Exclude.Count -gt 0) {
    foreach ($pat in $Exclude) {
      $rx = [regex]::Escape($pat).Replace('\*','.*').Replace('\?','.')
      $Modules = $Modules | Where-Object { $_.Name -notmatch $rx -and $_.Category -notmatch $rx }
    }
  }
  $Modules
}

function Start-CpEngine {
  [CmdletBinding()]
  param(
    [ValidateSet('Apply','Verify')][string]$Mode = 'Apply',
    [string]$Profile = 'Auto',
    [string]$Overlay,
    [int]$MaxParallel = 8,
    [switch]$WhatIf,
    [Parameter(Mandatory)][string]$Root,
    [string[]]$IncludeModules,
    [string[]]$ExcludeModules,
    [switch]$Interactive
  )

  Write-Info "Starting engine (Mode=$Mode, Profile=$Profile, Overlay=$Overlay)"

  $ctx  = Build-Context -Root $Root
  $mods = Get-Modules  -Root $Root
  if (-not $mods -or $mods.Count -eq 0) { throw "No modules discovered under $Root\modules" }

  if ($Interactive) {
    Write-Host ""
    Write-Host "Select modules to run (comma-separated indexes or names; 'all' for everything):" -ForegroundColor Cyan
    $i = 1
    foreach ($m in $mods) { Write-Host ("  {0,2}. {1}  [{2}]" -f $i,$m.Name,$m.Category) ; $i++ }
    $choice = Read-Host "Your selection"
    if ($choice -and $choice.ToLower() -ne 'all') {
      $tokens = $choice -split '[\s,]+' | Where-Object { $_ }
      $include = @()
      foreach ($t in $tokens) {
        if ($t -match '^\d+$') {
          $idx = [int]$t
          if ($idx -ge 1 -and $idx -le $mods.Count) { $include += $mods[$idx-1].Name }
        } else {
          $include += $t
        }
      }
      $mods = Select-ModulesByName -Modules $mods -Include $include
    }
  } else {
    $mods = Select-ModulesByName -Modules $mods -Include $IncludeModules -Exclude $ExcludeModules
  }

  if (-not $mods -or $mods.Count -eq 0) { Write-Warn "No modules selected. Exiting."; return }

  Write-Info ("Running {0} module(s): {1}" -f $mods.Count, ($mods | ForEach-Object { $_.Name } -join ', '))

  foreach ($m in $mods) {
    try {
      Import-Module -Force -DisableNameChecking -Name $m.Path
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

  Write-Ok "All selected modules done"
}

Export-ModuleMember -Function Start-CpEngine, Get-OSProfile
