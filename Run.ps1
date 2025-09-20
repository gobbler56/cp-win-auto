#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [ValidateSet('Apply','Verify')][string]$Mode = 'Apply',
  [string]$Profile = 'Auto',
  [string]$Overlay,
  [int]$MaxParallel = 8,
  [switch]$Interactive,
  [string[]]$Modules,
  [string[]]$ExcludeModules
)

$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- Preflight: neutralize .psm1 "Open" association that sometimes launches Notepad ---
try {
  $assoc = (cmd /c assoc .psm1) 2>$null
  if ($assoc -notmatch 'Microsoft.PowerShellModule.1') {
    cmd /c assoc .psm1=Microsoft.PowerShellModule.1 | Out-Null
  }
  # Make the default "open" just import & exit (no Notepad)
  cmd /c ftype Microsoft.PowerShellModule.1="%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Import-Module `"%1`";exit" | Out-Null
} catch { }

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module -Force -DisableNameChecking -Name (Join-Path $Root 'core/Utils.psm1')
Import-Module -Force -DisableNameChecking -Name (Join-Path $Root 'core/Contracts.psm1')
Import-Module -Force -DisableNameChecking -Name (Join-Path $Root 'core/CpCore.psm1')

$params = @{
  Mode           = $Mode
  Profile        = $Profile
  Overlay        = $Overlay
  MaxParallel    = $MaxParallel
  Root           = $Root
  Interactive    = [bool]$Interactive
  IncludeModules = $Modules
  ExcludeModules = $ExcludeModules
}

Invoke-CpAutoCore @params
