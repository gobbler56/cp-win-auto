Set-StrictMode -Version Latest
function New-ModuleResult {
  param([string]$Name,[string]$Status,[string]$Message)
  [pscustomobject]@{ Name = $Name; Status = $Status; Message = $Message }
}
Export-ModuleMember -Function New-ModuleResult
