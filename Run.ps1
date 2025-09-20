\
    [CmdletBinding()]
    param(
      [ValidateSet('Apply','Verify')][string]$Mode = 'Apply',
      [string]$Profile = 'Auto',
      [string]$Overlay,
      [int]$MaxParallel = 8,
      [switch]$WhatIf
    )

    $PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $Root = Split-Path -Parent $MyInvocation.MyCommand.Path
    Import-Module -Force -Name (Join-Path $Root 'core/Engine.psm1')

    $params = @{
      Mode        = $Mode
      Profile     = $Profile
      Overlay     = $Overlay
      MaxParallel = $MaxParallel
      WhatIf      = [bool]$WhatIf
      Root        = $Root
    }

    Start-Engine @params
