Set-StrictMode -Version Latest

# Import required modules if not already loaded
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

function Test-Ready { param($Context) return $true }
function Invoke-Verify { param($Context) return (New-ModuleResult -Name 'AccountPolicy' -Status 'Succeeded' -Message 'Verified (stub)') }
function Invoke-Apply  { param($Context) return (New-ModuleResult -Name 'AccountPolicy' -Status 'Succeeded' -Message 'Applied (stub)') }

Export-ModuleMember -Function Test-Ready,Invoke-Verify,Invoke-Apply
