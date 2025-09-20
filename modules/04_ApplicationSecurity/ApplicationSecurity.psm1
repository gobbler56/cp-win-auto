
    Set-StrictMode -Version Latest
    . $PSScriptRoot/../../core/Contracts.psm1
    . $PSScriptRoot/../../core/Utils.psm1

    function Test-Ready { param($Context) return $true }
    function Invoke-Verify { param($Context) return (New-ModuleResult -Name 'ApplicationSecurity' -Status 'Succeeded' -Message 'Verified umbrella (stub)') }
    function Invoke-Apply  { param($Context) return (New-ModuleResult -Name 'ApplicationSecurity' -Status 'Succeeded' -Message 'Applied umbrella (stub)') }

    Export-ModuleMember -Function Test-Ready,Invoke-Verify,Invoke-Apply

