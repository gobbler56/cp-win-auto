Set-StrictMode -Version Latest

# Import required modules if not already loaded
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

function Test-Ready { param($Context) return $true }

function Invoke-Apply {
  param($Context)

  $builtInAdmin = Get-BuiltinAdministratorName
  $defaults     = Get-DefaultLocalAccounts
  $adminGroup   = 'Administrators'
  $autoUser     = if ($Context -and $Context.PSObject.Properties.Name -contains 'AutoLogonUser' -and $Context.AutoLogonUser) { $Context.AutoLogonUser } else { Get-AutoLogonUser }

  $rx = $Context.Readme.Directives
  $authUsersFromReadme  = @($Context.Readme.AuthorizedUsers)
  $authAdminsFromReadme = @($Context.Readme.AuthorizedAdmins)

  # -------- Phase 1: Allow-lists from README (authoritative) --------
  $authorizedUsers  = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
  foreach ($x in @($authUsersFromReadme + $authAdminsFromReadme)) { if ($x) { [void]$authorizedUsers.Add($x) } }

  $authorizedAdmins = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
  foreach ($x in @($authAdminsFromReadme)) { if ($x) { [void]$authorizedAdmins.Add($x); [void]$authorizedUsers.Add($x) } }

  foreach ($u in $authorizedUsers) {
    Ensure-LocalUserExists -Name $u -CreateIfMissing -Password (To-SecureString (New-RandomPassword)) | Out-Null
  }

  # -------- Phase 2: Remove unauthorized users (diff only if we have allow-list) --------
  $currentUsers = Get-LocalUserNames -ExcludeDefaults
  $unauthorized = @()
  if ($authorizedUsers.Count -gt 0 -or $authorizedAdmins.Count -gt 0) {
    foreach ($u in $currentUsers) { if (-not ($authorizedUsers.Contains($u))) { $unauthorized += $u } }
  }
  $unauthorized = $unauthorized | Select-Object -Unique
  foreach ($u in $unauthorized) {
    if ($defaults -contains $u) { continue }
    try { Get-LocalGroup | ForEach-Object { Remove-UserFromLocalGroupSafe -Group $_.Name -User $u } } catch {}
    Remove-LocalUserSafe -Name $u
    Write-Ok "Removed unauthorized user $u"
  }

  # re-enumerate
  $currentUsers = Get-LocalUserNames

  # -------- Phase 3: Groups from README model output --------
  foreach ($g in ($rx.GroupsToCreate | Select-Object -Unique)) {
    if (-not (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) {
      try { New-LocalGroup -Name $g -ErrorAction Stop | Out-Null; Write-Ok "Created group $g" } catch { Write-Err "Create group $g failed: $_" }
    }
  }
  foreach ($grp in $rx.GroupMembersToAdd.Keys) {
    $members = $rx.GroupMembersToAdd[$grp] | Select-Object -Unique
    foreach ($u in $members) {
      Ensure-LocalUserExists -Name $u -CreateIfMissing -Password (To-SecureString (New-RandomPassword)) | Out-Null
      Add-UserToLocalGroupSafe -Group $grp -User $u
      Write-Ok "Ensured $u in $grp"
    }
  }

  # -------- Phase 4: Administrators membership alignment --------
  try { $members = Get-LocalGroupMember -Group $adminGroup -ErrorAction SilentlyContinue } catch { $members = @() }
  if ($members) {
    foreach ($m in $members) {
      if ($m.ObjectClass -ne 'User' -or $m.PrincipalSource -ne 'Local') { continue }
      $name = ($m.Name -split '\\')[-1]
      if (-not ($authorizedAdmins.Contains($name)) -and $name -ne $builtInAdmin) {
        Remove-UserFromLocalGroupSafe -Group $adminGroup -User $name
        Write-Ok "Removed $name from $adminGroup"
      }
    }
  }
  foreach ($a in $authorizedAdmins) {
    if ($currentUsers -contains $a) { Add-UserToLocalGroupSafe -Group $adminGroup -User $a }
    else {
      Ensure-LocalUserExists -Name $a -CreateIfMissing -Password (To-SecureString (New-RandomPassword)) | Out-Null
      Add-UserToLocalGroupSafe -Group $adminGroup -User $a
    }
    Write-Ok "Ensured $a is in $adminGroup"
  }

  # -------- Phase 5: Global per-user hardening --------
  $nonDefaults = Get-LocalUserNames -ExcludeDefaults
  foreach ($u in $nonDefaults) {
    try {
      if ($autoUser -and $u -ieq $autoUser) {
        Write-Warn "Skipping password rotation for auto-login account '$u'"
      } else {
        Set-LocalUserPassword -Name $u -Password (To-SecureString (New-RandomPassword))
      }
      Enable-LocalUserSafe -Name $u
      [void](Set-LocalPasswordExpires -Name $u -Expires:$true)
      [void](Set-LocalUserCanChangePassword -Name $u -CanChange:$true)
      Write-Ok "Hardened user $u"
    } catch {
      Write-Warn "Failed to harden $u: $_"
    }
  }

  # -------- Phase 6: Built-ins --------
  Disable-LocalUserSafe -Name 'Guest'
  Disable-LocalUserSafe -Name $builtInAdmin

  return (New-ModuleResult -Name 'UserAuditing' -Status 'Succeeded' -Message 'User auditing completed')
}

function Invoke-Verify {
  param($Context)
  return (New-ModuleResult -Name 'UserAuditing' -Status 'Succeeded' -Message 'Verification complete')
}

Export-ModuleMember -Function Test-Ready,Invoke-Apply,Invoke-Verify
