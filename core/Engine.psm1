\
    Set-StrictMode -Version Latest
    . $PSScriptRoot/Utils.psm1
    . $PSScriptRoot/Contracts.psm1
    . $PSScriptRoot/Parsing.psm1
    . $PSScriptRoot/Detection.psm1
    . $PSScriptRoot/Profiles.psm1

    function Get-ModuleDescriptors {
      param([string]$Root)
      $mods = @()
      $glob = Get-ChildItem -Path (Join-Path $Root 'modules') -Recurse -Filter module.json -File -ErrorAction SilentlyContinue
      foreach ($m in $glob) {
        $meta = Get-Content -LiteralPath $m.FullName -Raw | ConvertFrom-Json
        $psm1 = Get-ChildItem -Path $m.DirectoryName -Filter *.psm1 | Select-Object -First 1
        if ($null -eq $psm1) { continue }
        $mods += [pscustomobject]@{
          Name = $meta.name
          Category = $meta.category
          Priority = $meta.priority
          Path = $psm1.FullName
          Dir  = $m.DirectoryName
          AppliesTo = $meta.appliesTo
          DependsOn = $meta.dependsOn
          Parallelizable = $meta.parallelizable
        }
      }
      $mods
    }

    function Start-Engine {
      param(
        [ValidateSet('Apply','Verify')][string]$Mode,
        [string]$Profile,
        [string]$Overlay,
        [int]$MaxParallel = 8,
        [bool]$WhatIf = $false,
        [Parameter(Mandatory)][string]$Root
      )

      Write-Info "Starting engine (Mode=$Mode, Profile=$Profile, Overlay=$Overlay)"
      $os  = if ($Profile -eq 'Auto') { Get-OSProfile } else { $Profile }
      $role= Get-Role
      Write-Info "Detected OS: $os; Role: $role"

      $profile = Load-Profile -OS $os -Overlay $Overlay -Root $Root
      $detections = Detect-Stacks
      $readme = Get-ReadmeInfo -Root $Root

      $ctx = [pscustomobject]@{
        Root        = $Root
        OS          = $os
        Role        = $role
        Profile     = $profile
        Detections  = $detections
        Readme      = $readme
        Mode        = $Mode
        MaxParallel = $MaxParallel
        WhatIf      = $WhatIf
      }

      $mods = Get-ModuleDescriptors -Root $Root
      # filter by appliesTo
      $mods = $mods | Where-Object {
        $okOs = -not $_.AppliesTo.os -or ($_.AppliesTo.os -contains $os)
        $okRole = -not $_.AppliesTo.role -or ($_.AppliesTo.role -contains $role)
        $okOs -and $okRole
      }

      # Order modules
      $order = @()
      foreach ($cat in $profile.CategoryOrder) {
        $order += $mods | Where-Object Category -eq $cat | Sort-Object Priority
      }
      $remaining = $mods | Where-Object { $order -notcontains $_ }
      $plan = @($order + $remaining)

      foreach ($m in $plan) {
        $toggleKey = if ($m.Name -and $m.Category) { "$($m.Category)/$($m.Name)" } else { $m.Name }
        if ($profile.ModuleToggles.ContainsKey($toggleKey) -and -not $profile.ModuleToggles[$toggleKey]) {
          Write-Warn "Skipping $toggleKey (disabled by profile)"
          continue
        }
        Write-Info "Loading module: $($m.Name) ($($m.Category))"
        $mod = Import-Module -PassThru -Force -Name $m.Path
        $fReady  = Get-Command -Module $mod -Name Test-Ready -ErrorAction SilentlyContinue
        $fApply  = Get-Command -Module $mod -Name Invoke-Apply -ErrorAction SilentlyContinue
        $fVerify = Get-Command -Module $mod -Name Invoke-Verify -ErrorAction SilentlyContinue
        if (-not $fApply) { Write-Warn "Module $($m.Name) has no Invoke-Apply; skipping"; continue }

        $ready = $true
        if ($fReady) { $ready = Test-Ready -Context $ctx }

        if (-not $ready) {
          Write-Warn "Module $($m.Name) not ready; skipping"
          continue
        }

        try {
          $res = if ($ctx.Mode -eq 'Verify' -and $fVerify) {
            Invoke-Verify -Context $ctx
          } else {
            Invoke-Apply -Context $ctx
          }
          if ($res -and $res.Status -eq 'Succeeded') {
            Write-Ok "$($m.Name): $($res.Message)"
          } elseif ($res -and $res.Status -eq 'Skipped') {
            Write-Warn "$($m.Name): $($res.Message)"
          } else {
            Write-Err "$($m.Name): $($res.Message)"
          }
        } catch {
          Write-Err "$($m.Name): $_"
        }
      }

      Write-Ok "Engine complete."
    }

    Export-ModuleMember -Function Start-Engine
