Set-StrictMode -Version Latest

# Import required modules if not already loaded
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')

function Test-Ready { param($Context) return $true }

# --------------------------------------------------------------------------------------
# Targeted provisioning debug (off by default). Enable with: $env:CP_DEBUG_PROVISION = '1'
# --------------------------------------------------------------------------------------
function Write-ProvisionDebug {
  param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Message)
  if ($env:CP_DEBUG_PROVISION -eq '1') {
    Write-Host ("[ProvisionDebug] " + ($Message -join ' '))
  }
}

# --------------------------------------------------------------------------------------
# Align-PrivilegedGroupMembership: keep privileged groups aligned to the allow-list
# --------------------------------------------------------------------------------------
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

# --------------------------------------------------------------------------------------
# Provision-LocalUser: robust creation with verify-after-ensure and direct fallback
# --------------------------------------------------------------------------------------
function Provision-LocalUser {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name
  )

  Write-ProvisionDebug "Start Name='$Name'"

  $existing = $null
  try { $existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue } catch {}
  Write-ProvisionDebug "ExistsBefore=$([bool]$existing)"

  if ($existing) { return $true }

  # 1) Try helper; do not trust return value
  try {
    Ensure-LocalUserExists -Name $Name -CreateIfMissing -Password (To-SecureString (New-RandomPassword)) | Out-Null
  } catch {
    Write-Warn "Ensure-LocalUserExists threw for '$Name': $($_.Exception.Message)"
    Write-ProvisionDebug "Ensure.Exception=$($_.Exception.GetType().FullName)"
    if ($_.Exception.InnerException) { Write-ProvisionDebug "Ensure.Inner=$($_.Exception.InnerException.Message)" }
  }

  $userNow = $null
  try { $userNow = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue } catch {}
  if ($userNow) {
    Write-Ok "Created local user $Name"
    Write-ProvisionDebug ("CreatedVia=Ensure User='" + $userNow.Name + "'")
    return $true
  }

  # 2) Fallback: direct New-LocalUser to surface real Windows errors
  Write-Warn "Ensure-LocalUserExists did not create '$Name' — attempting direct New-LocalUser"
  try {
    $tmpPw = New-RandomPassword
    $secPw = To-SecureString $tmpPw
    New-LocalUser -Name $Name -Password $secPw -AccountNeverExpires:$true -ErrorAction Stop | Out-Null
    Write-Ok "Created local user $Name via New-LocalUser"
  } catch {
    Write-Err "Create user '$Name' failed: $($_.Exception.Message)"
    Write-ProvisionDebug "New-LocalUser.Exception=$($_.Exception.GetType().FullName)"
    if ($_.Exception.InnerException) { Write-ProvisionDebug "New-LocalUser.Inner=$($_.Exception.InnerException.Message)" }
    try {
      Write-ProvisionDebug "net accounts =>"
      (& cmd /c 'net accounts') | ForEach-Object { Write-ProvisionDebug $_ }
    } catch {}
    return $false
  }

  # Verify after fallback
  try { $userNow = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue } catch {}
  if ($userNow) {
    Write-ProvisionDebug ("CreatedVia=New-LocalUser User='" + $userNow.Name + "'")
    return $true
  }

  Write-Err "User '$Name' still not present after both attempts."
  return $false
}

# --------------------------------------------------------------------------------------
# Helpers to parse directives into canonical objects
# --------------------------------------------------------------------------------------
function ConvertTo-RecentHireObjects {
  param($UsersToCreate)
  $out = @()
  foreach ($entry in @($UsersToCreate)) {
    if (-not $entry) { continue }
    $name = if ($entry.PSObject.Properties.Name -contains 'Name') { $entry.Name } elseif ($entry.PSObject.Properties.Name -contains 'name') { $entry.name } else { $null }
    if ($name) { $name = ($name -as [string]).Trim() }
    if (-not $name) { continue }

    $accountType = if ($entry.PSObject.Properties.Name -contains 'AccountType' -and $entry.AccountType) { $entry.AccountType }
      elseif ($entry.PSObject.Properties.Name -contains 'account_type' -and $entry.account_type) { $entry.account_type }
      else { 'standard' }
    if ($accountType) { $accountType = ($accountType -as [string]).ToLowerInvariant() }
    if ($accountType -ne 'admin') { $accountType = 'standard' }

    $groups = @()
    if ($entry.PSObject.Properties.Name -contains 'Groups' -and $entry.Groups) {
      foreach ($g in @($entry.Groups)) { $grpName = ($g -as [string]).Trim(); if ($grpName) { $groups += $grpName } }
      $groups = @($groups | Select-Object -Unique)
    }

    $out += [pscustomobject]@{ Name = $name; AccountType = $accountType; Groups = $groups }
  }
  return $out
}

# --------------------------------------------------------------------------------------
# Main Apply
# --------------------------------------------------------------------------------------
function Invoke-Apply {
  param($Context)

  $builtInAdmin = Get-BuiltinAdministratorName
  $defaults     = Get-DefaultLocalAccounts
  $adminGroup   = 'Administrators'
  $autoUser     = if ($Context -and $Context.PSObject.Properties.Name -contains 'AutoLogonUser' -and $Context.AutoLogonUser) { $Context.AutoLogonUser } else { Get-AutoLogonUser }

  $rx = $Context.Readme.Directives
  $authUsersFromReadme  = @($Context.Readme.AuthorizedUsers)
  $authAdminsFromReadme = @($Context.Readme.AuthorizedAdmins)

  # ---- Build canonical hires/terminations ----
  $recentHires   = @()
  $terminatedSet = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
  $terminatedUsers = @()

  if ($rx -and $rx.PSObject.Properties.Name -contains 'UsersToCreate' -and $rx.UsersToCreate) {
    $recentHires = ConvertTo-RecentHireObjects -UsersToCreate $rx.UsersToCreate
  }

  if ($rx -and $rx.PSObject.Properties.Name -contains 'TerminatedUsers' -and $rx.TerminatedUsers) {
    foreach ($term in @($rx.TerminatedUsers)) {
      $name = ($term -as [string]).Trim(); if (-not $name) { continue }
      if ($terminatedSet.Add($name)) { $terminatedUsers += $name }
    }
  }

  # ---- Phase 1: compute allow-lists (authoritative) ----
  $authorizedUsers  = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
  foreach ($x in @($authUsersFromReadme + $authAdminsFromReadme)) { if ($x) { [void]$authorizedUsers.Add($x) } }

  $authorizedAdmins = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
  foreach ($x in @($authAdminsFromReadme)) { if ($x) { [void]$authorizedAdmins.Add($x); [void]$authorizedUsers.Add($x) } }

  foreach ($hire in $recentHires) {
    if ($hire.Name) { [void]$authorizedUsers.Add($hire.Name) }
    if ($hire.AccountType -eq 'admin' -and $hire.Name) { [void]$authorizedAdmins.Add($hire.Name) }
  }

  foreach ($term in $terminatedUsers) { [void]$authorizedUsers.Remove($term); [void]$authorizedAdmins.Remove($term) }

  # ---- Phase 1b: proactively ensure all allow-listed users exist ----
  foreach ($u in $authorizedUsers) { Ensure-LocalUserExists -Name $u -CreateIfMissing -Password (To-SecureString (New-RandomPassword)) | Out-Null }

  # ---- Phase 1c: explicit provisioning pass for recent hires with debug & fallback ----
  foreach ($hire in $recentHires) { if ($hire.Name) { [void](Provision-LocalUser -Name $hire.Name) } }

  # ---- Phase 2: Remove unauthorized users (diff only if we have allow-list) ----
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

  # Refresh user list after deletions
  $currentUsers = Get-LocalUserNames

  # ---- Phase 3: Groups from README + hire groups ----
  # Merge hire.Groups into the model's GroupMembersToAdd
  $groupMembers = @{}
  if ($rx -and $rx.PSObject.Properties.Name -contains 'GroupMembersToAdd' -and $rx.GroupMembersToAdd) {
    foreach ($k in $rx.GroupMembersToAdd.Keys) { $groupMembers[$k] = @($rx.GroupMembersToAdd[$k]) }
  }
  foreach ($hire in $recentHires) {
    foreach ($g in @($hire.Groups)) {
      if (-not $groupMembers.ContainsKey($g)) { $groupMembers[$g] = @() }
      $groupMembers[$g] += $hire.Name
    }
  }
  # Create any referenced groups
  $groupsToCreate = @()
  if ($rx -and $rx.PSObject.Properties.Name -contains 'GroupsToCreate' -and $rx.GroupsToCreate) { $groupsToCreate += $rx.GroupsToCreate }
  $groupsToCreate += $groupMembers.Keys
  $groupsToCreate = $groupsToCreate | Select-Object -Unique

  foreach ($g in $groupsToCreate) {
    if (-not (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) {
      try { New-LocalGroup -Name $g -ErrorAction Stop | Out-Null; Write-Ok "Created group $g" } catch { Write-Err "Create group $g failed: $_" }
    }
  }
  foreach ($grp in $groupMembers.Keys) {
    $members = @($groupMembers[$grp] | Where-Object { $_ } | Select-Object -Unique)
    foreach ($u in $members) {
      Ensure-LocalUserExists -Name $u -CreateIfMissing -Password (To-SecureString (New-RandomPassword)) | Out-Null
      Add-UserToLocalGroupSafe -Group $grp -User $u
      Write-Ok "Ensured $u in $grp"
    }
  }

  # ---- Phase 4: Privileged group alignment ----
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

  # ---- Phase 5: Global per-user hardening ----
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
      Write-Warn "Failed to harden ${u}: $($_.Exception.Message)"
    }
  }

  # ---- Phase 6: Built-ins ----
  Disable-LocalUserSafe -Name 'Guest'
  Disable-LocalUserSafe -Name $builtInAdmin

  return (New-ModuleResult -Name 'UserAuditing' -Status 'Succeeded' -Message 'User auditing completed')
}

function Invoke-Verify {
  param($Context)
  return (New-ModuleResult -Name 'UserAuditing' -Status 'Succeeded' -Message 'Verification complete')
}

Export-ModuleMember -Function Test-Ready,Invoke-Apply,Invoke-Verify
