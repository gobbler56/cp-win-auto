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

# --- LaunchGuard v2: block "shell-open" of .ps1/.psm1/.psd1 during this run ---
$global:__cp_launchlog = 'C:\cp-output\launchlog.txt'
New-Item -ItemType Directory -Path (Split-Path $global:__cp_launchlog) -Force | Out-Null
"=== LaunchGuard v2 started $(Get-Date) ===" | Out-File $global:__cp_launchlog -Encoding utf8 -Append
function global:__cp_Log([string]$msg){
  $line = "[{0}] {1} :: {2}" -f (Get-Date), $MyInvocation.ScriptName, $msg
  $line | Out-File $global:__cp_launchlog -Encoding utf8 -Append
  Write-Host $line -ForegroundColor Yellow
}

# 1) Wrap Invoke-Item (ii)
function global:Invoke-Item {
  [CmdletBinding()] param(
    [Parameter(Mandatory, Position=0)][string]$Path,
    [Parameter(ValueFromRemainingArguments=$true)]$Remaining
  )
  if ($Path -match '\.(psm1|ps1|psd1)$') { __cp_Log "BLOCKED Invoke-Item $Path"; return }
  Microsoft.PowerShell.Management\Invoke-Item @PSBoundParameters
}

# 2) Wrap Start-Process (covers 'start' alias)
function global:Start-Process {
  [CmdletBinding(DefaultParameterSetName='Default')]
  param([Parameter(ValueFromRemainingArguments=$true)] $Args)
  $fp = $null
  if ($PSBoundParameters.ContainsKey('FilePath')) { $fp = $PSBoundParameters['FilePath'] }
  elseif ($Args -and $Args[0] -is [string]) { $fp = $Args[0] }
  if ($fp -and ($fp -match '\.(psm1|ps1|psd1)$' -or (Split-Path $fp -Leaf) -match '^(?i)notepad(\.exe)?$')) {
    __cp_Log "BLOCKED Start-Process $fp"
    return
  }
  Microsoft.PowerShell.Management\Start-Process @PSBoundParameters @Args
}

# 3) Wrap direct 'cmd /c start ...'
function global:cmd {
  param([Parameter(ValueFromRemainingArguments=$true)]$Args)
  if ($Args -and $Args.Count -ge 2 -and ($Args[0] -eq '/c') -and ($Args[1] -match '^(?i)start$')) {
    $joined = ($Args -join ' ')
    if ($joined -match '\.(psm1|ps1|psd1)\b' -or $joined -match '(?i)\bnotepad(\.exe)?\b') {
      __cp_Log "BLOCKED cmd $joined"
      return
    }
  }
  & $env:ComSpec @Args
}

# 4) Wrap 'notepad' verb itself so we see who calls it
function global:notepad { param([string]$Path)
  __cp_Log "Intercepted notepad $Path"
  & (Join-Path $env:WINDIR 'System32\notepad.exe') $Path
}

# (optional) normalize .psm1 association so an accidental open won’t hit Notepad
try {
  $assoc = (cmd /c assoc .psm1) 2>$null
  if ($assoc -notmatch 'Microsoft.PowerShellModule.1') { cmd /c assoc .psm1=Microsoft.PowerShellModule.1 | Out-Null }
} catch {}

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
