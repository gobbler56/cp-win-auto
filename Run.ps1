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
