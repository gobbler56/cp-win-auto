
    Set-StrictMode -Version Latest

# Import required modules if not already loaded
if (-not (Get-Command Import-Json -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot 'Utils.psm1')
}

      param(
        [Parameter(Mandatory)][string]$OS,
        [string]$Overlay,
        [string]$Root
      )
      $base  = Import-Json (Join-Path $Root "profiles/$OS.json")
      $order = Import-Json (Join-Path $Root "profiles/order.json")
      if ($Overlay) {
        $ov = Import-Json (Join-Path $Root "profiles/overlays/$Overlay.json")
        if ($ov) { $base = $base + $ov } # hashtable merge (shallow)
      }
      [pscustomobject]@{
        CategoryOrder  = $base.categoryOrder  ?? $order.order
        ModuleToggles  = $base.moduleToggles  ?? @{}
        Args           = $base.args           ?? @{}
      }
    }

    Export-ModuleMember -Function Load-Profile

