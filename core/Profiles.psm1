
    Set-StrictMode -Version Latest
    . $PSScriptRoot/Utils.psm1

    function Load-Profile {
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

