
    Set-StrictMode -Version Latest
    . $PSScriptRoot/Utils.psm1

    function Get-Baseline {
      param([ValidateSet('Services','Tasks','RunKeys')]$Kind, [Parameter(Mandatory)][string]$OS, [string]$Root)
      $p = Join-Path $Root "assets/baselines/$OS/$($Kind.ToLower()).json"
      Import-Json -Path $p
    }

    function Compare-WithBaseline {
      param(
        [Parameter(Mandatory)][ValidateSet('Services','Tasks','RunKeys')]$Kind,
        [Parameter(Mandatory)][string]$OS,
        [Parameter(Mandatory)][string]$Root
      )
      $baseline = Get-Baseline -Kind $Kind -OS $OS -Root $Root
      if (-not $baseline) { return @{ Added=@(); Removed=@(); Changed=@() } }

      switch ($Kind) {
        'Services' {
          $curr = Get-Service | ForEach-Object { @{ Name=$_.Name; StartType=$_.StartType.ToString() } }
          $currIdx = @{}; $curr | ForEach-Object { $currIdx[$_.Name] = $_ }
          $baseIdx = @{}; $baseline | ForEach-Object { $baseIdx[$_.Name] = $_ }
          $added   = @(); $removed = @(); $changed = @()
          foreach ($name in $currIdx.Keys) { if (-not $baseIdx.ContainsKey($name)) { $added += $currIdx[$name] } }
          foreach ($name in $baseIdx.Keys) { if (-not $currIdx.ContainsKey($name)) { $removed += $baseIdx[$name] } }
          foreach ($name in $baseIdx.Keys) {
            if ($currIdx.ContainsKey($name)) {
              if ($currIdx[$name].StartType -ne $baseIdx[$name].StartType) {
                $changed += @{ Name=$name; From=$baseIdx[$name].StartType; To=$currIdx[$name].StartType }
              }
            }
          }
          return @{ Added=$added; Removed=$removed; Changed=$changed }
        }
        Default { return @{ Added=@(); Removed=@(); Changed=@() } }
      }
    }

    Export-ModuleMember -Function Get-Baseline,Compare-WithBaseline

