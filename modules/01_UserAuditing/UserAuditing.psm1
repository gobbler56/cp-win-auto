Set-StrictMode -Version Latest

# Import required modules if not already loaded
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

function Test-Ready { param($Context) return $true }

function Align-PrivilegedGroupMembership {
  param(
    [string]$GroupName,
    [System.Collections.Generic.HashSet[string]]$AuthorizedAdmins,
    [string]$BuiltInAdmin,
    [bool]$ForceRemovalWhenEmpty = $false
  )

  if (-not $GroupName) { return }
  $group = Get-LocalGroup -Name $GroupName -ErrorAction SilentlyContinue
  if (-not $group) { return }

  $members = @()
  try { $members = Get-LocalGroupMember -Group $GroupName -ErrorAction Stop } catch { return }

  foreach ($member in $members) {
    if ($member.ObjectClass -ne 'User') { continue }
    $name = ($member.Name -split '\\')[-1]
    if (-not $name) { continue }
    if ($GroupName -eq 'Administrators' -and $name -eq $BuiltInAdmin) { continue }
    $shouldRemove = $ForceRemovalWhenEmpty -or $AuthorizedAdmins.Count -gt 0
    if ($shouldRemove -and -not $AuthorizedAdmins.Contains($name)) {
      Remove-UserFromLocalGroupSafe -Group $GroupName -User $name
      Write-Ok "Removed $name from $GroupName"
    }
  }

  foreach ($admin in $AuthorizedAdmins) {
    if (-not $admin) { continue }
    Ensure-LocalUserExists -Name $admin -CreateIfMissing -Password (To-SecureString (New-RandomPassword)) | Out-Null
    if (-not (Test-LocalGroupMember -Group $GroupName -User $admin)) {
      Add-UserToLocalGroupSafe -Group $GroupName -User $admin
      Write-Ok "Ensured $admin is in $GroupName"
    }
  }
}

function Invoke-Apply {
  param($Context)

  $builtInAdmin = Get-BuiltinAdministratorName
  $defaults     = Get-DefaultLocalAccounts
  $adminGroup   = 'Administrators'
  $autoUser     = if ($Context -and $Context.PSObject.Properties.Name -contains 'AutoLogonUser' -and $Context.AutoLogonUser) { $Context.AutoLogonUser } else { Get-AutoLogonUser }

  $rx = $Context.Readme.Directives
  $authUsersFromReadme  = @($Context.Readme.AuthorizedUsers)
  $authAdminsFromReadme = @($Context.Readme.AuthorizedAdmins)
  $recentHires = @()
  $terminatedSet = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
  if ($rx -and $rx.PSObject.Properties.Name -contains 'UsersToCreate' -and $rx.UsersToCreate) {
    foreach ($entry in @($rx.UsersToCreate)) {
      if (-not $entry) { continue }
      $name = $entry.Name
      if (-not $name) { continue }
      $recentHires += [pscustomobject]@{
        Name        = $name
        AccountType = $entry.AccountType
        Groups      = @($entry.Groups)
      }
    }
  }
  $terminatedUsers = @()
  if ($rx -and $rx.PSObject.Properties.Name -contains 'TerminatedUsers' -and $rx.TerminatedUsers) {
    foreach ($term in @($rx.TerminatedUsers)) {
      $name = ($term -as [string]).Trim()
      if (-not $name) { continue }
      if ($terminatedSet.Add($name)) { $terminatedUsers += $name }
    }
  }

  # -------- Phase 1: Allow-lists from README (authoritative) --------
  $authorizedUsers  = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
  foreach ($x in @($authUsersFromReadme + $authAdminsFromReadme)) { if ($x) { [void]$authorizedUsers.Add($x) } }

  $authorizedAdmins = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
  foreach ($x in @($authAdminsFromReadme)) { if ($x) { [void]$authorizedAdmins.Add($x); [void]$authorizedUsers.Add($x) } }

  foreach ($hire in $recentHires) {
    if (-not $hire.Name) { continue }
    [void]$authorizedUsers.Add($hire.Name)
    if ($hire.AccountType -eq 'admin') { [void]$authorizedAdmins.Add($hire.Name) }
  }

  foreach ($term in $terminatedUsers) {
    [void]$authorizedUsers.Remove($term)
    [void]$authorizedAdmins.Remove($term)
  }

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

  # -------- Phase 3b: Explicit terminations --------
  foreach ($term in $terminatedUsers) {
    if ($defaults -contains $term) { continue }
    $user = Get-LocalUser -Name $term -ErrorAction SilentlyContinue
    if (-not $user) { continue }
    try { Get-LocalGroup | ForEach-Object { Remove-UserFromLocalGroupSafe -Group $_.Name -User $term } } catch {}
    Remove-LocalUserSafe -Name $term
    Write-Ok "Removed terminated user $term"
  }

  # Refresh after deletions
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

  # -------- Phase 4: Privileged group alignment --------
  $privilegedGroups = @(
    'Administrators',
    'DnsAdmins',
    'Enterprise Admins',
    'Schema Admins',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
    'Print Operators',
    'Network Configuration Operators',
    'Hyper-V Administrators'
  )
  foreach ($grpName in ($privilegedGroups | Select-Object -Unique)) {
    $force = ($grpName -ieq $adminGroup)
    Align-PrivilegedGroupMembership -GroupName $grpName -AuthorizedAdmins $authorizedAdmins -BuiltInAdmin $builtInAdmin -ForceRemovalWhenEmpty:$force
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
      Write-Warn "Failed to harden $u: $($_.Exception.Message)"
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
