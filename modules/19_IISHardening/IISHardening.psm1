Set-StrictMode -Version Latest

if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

$script:ModuleName           = 'IISHardening'
$script:DefaultSiteName      = 'Default Web Site'
$script:AppCmdDefaultPath    = Join-Path $env:SystemRoot 'System32/inetsrv/appcmd.exe'
$script:AppCmdAltPath        = Join-Path $env:windir 'Sysnative/inetsrv/appcmd.exe'
$script:RestrictedIdentities = @('Everyone', 'BUILTIN\Users')
$script:WriteRightsMask      = [System.Security.AccessControl.FileSystemRights]::FullControl `
  -bor [System.Security.AccessControl.FileSystemRights]::Modify `
  -bor [System.Security.AccessControl.FileSystemRights]::Write `
  -bor [System.Security.AccessControl.FileSystemRights]::WriteData `
  -bor [System.Security.AccessControl.FileSystemRights]::CreateFiles `
  -bor [System.Security.AccessControl.FileSystemRights]::CreateDirectories `
  -bor [System.Security.AccessControl.FileSystemRights]::AppendData `
  -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions

function Get-AppCmdPath {
  if (Test-Path -LiteralPath $script:AppCmdDefaultPath) { return $script:AppCmdDefaultPath }
  if (Test-Path -LiteralPath $script:AppCmdAltPath)     { return $script:AppCmdAltPath }
  return $null
}

function Test-Ready {
  param($Context)

  $appcmd = Get-AppCmdPath
  if (-not $appcmd) {
    Write-Warn 'IIS appcmd.exe not found; skipping IIS hardening.'
    return $false
  }

  return $true
}

function Invoke-AppCmdCommand {
  param(
    [Parameter(Mandatory)][string[]]$Arguments,
    [string]$Description
  )

  $appcmd = Get-AppCmdPath
  if (-not $appcmd) { return $false }

  try {
    $output = & $appcmd @Arguments 2>&1
    $exit   = $LASTEXITCODE

    if ($exit -ne 0) {
      Write-Warn ("[IIS] {0} failed: {1}" -f ($Description ?? ($Arguments -join ' ')), ($output -join '; '))
      return $false
    }

    if ($Description) { Write-Info ("[IIS] {0}" -f $Description) }
    return $true
  }
  catch {
    Write-Warn ("[IIS] {0} threw: {1}" -f ($Description ?? ($Arguments -join ' ')), $_.Exception.Message)
    return $false
  }
}

function Test-FeatureEnabled {
  param([Parameter(Mandatory)][string]$Name)
  try {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction Stop
    return ($feature.State -eq 'Enabled')
  }
  catch {
    return $false
  }
}

function Remove-IdentityWriteAccessRecursive {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Identity
  )

  if (-not (Test-Path -LiteralPath $Path)) { return $false }

  $changed = $false
  $targets = @()
  try {
    $targets = @(Get-Item -LiteralPath $Path -ErrorAction Stop) + @(Get-ChildItem -LiteralPath $Path -Directory -Recurse -ErrorAction SilentlyContinue)
  } catch {
    Write-Warn ("[IIS] Unable to enumerate {0}: {1}" -f $Path, $_.Exception.Message)
    return $false
  }

  foreach ($item in $targets) {
    $acl = $null
    try { $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop } catch { continue }

    $dirChanged = $false
    if ($acl.AreAccessRulesProtected) {
      $acl.SetAccessRuleProtection($false, $true)
      $dirChanged = $true
    }

    foreach ($rule in @($acl.Access)) {
      $match = [string]::Equals($rule.IdentityReference.Value, $Identity, [System.StringComparison]::OrdinalIgnoreCase)
      if (-not $match) { continue }
      if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
      if (($rule.FileSystemRights -band $script:WriteRightsMask) -eq 0) { continue }

      if ($acl.RemoveAccessRule($rule)) { $dirChanged = $true }
    }

    if ($dirChanged) {
      try {
        Set-Acl -LiteralPath $item.FullName -AclObject $acl
        $changed = $true
      } catch {
        Write-Warn ("[IIS] Failed to update ACL for {0}: {1}" -f $item.FullName, $_.Exception.Message)
      }
    }
  }

  return $changed
}

function Protect-IISDirectories {
  $paths = @('C:\\inetpub', 'C:\\inetpub\\wwwroot', 'C:\\inetpub\\logs', 'C:\\inetpub\\temp')
  $changed = $false

  foreach ($path in $paths) {
    foreach ($identity in $script:RestrictedIdentities) {
      if (Remove-IdentityWriteAccessRecursive -Path $path -Identity $identity) {
        $changed = $true
      }
    }
  }

  return $changed
}

function Test-IdentityHasWriteAccess {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Identity
  )

  if (-not (Test-Path -LiteralPath $Path)) { return $false }

  try {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    foreach ($rule in @($acl.Access)) {
      $match = [string]::Equals($rule.IdentityReference.Value, $Identity, [System.StringComparison]::OrdinalIgnoreCase)
      if (-not $match) { continue }
      if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
      if (($rule.FileSystemRights -band $script:WriteRightsMask) -eq 0) { continue }
      return $true
    }
  } catch {
    return $false
  }

  return $false
}

function Test-AppCmdSetting {
  param(
    [Parameter(Mandatory)][string[]]$Arguments,
    [Parameter(Mandatory)][string]$Pattern,
    [switch]$Negate
  )

  $appcmd = Get-AppCmdPath
  if (-not $appcmd) { return $null }

  try {
    $output = & $appcmd @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { return $false }
    if ($Negate) { return ($output -notmatch $Pattern) }
    return ($output -match $Pattern)
  }
  catch {
    return $false
  }
}

function Invoke-Apply {
  param($Context)

  try {
    $changes = @()

    $operations = @(
      @{ Description = 'Disabled directory browsing for Default Web Site'; Arguments = @('set','config',"$($script:DefaultSiteName)",'-section:system.webServer/directoryBrowse','/enabled:false','/commit:apphost') },
      @{ Description = 'Disabled directory browsing server-wide'; Arguments = @('set','config','/section:system.webServer/directoryBrowse','/enabled:false','/commit:apphost') },
      @{ Description = 'Set HTTP error responses to DetailedLocalOnly'; Arguments = @('set','config',"$($script:DefaultSiteName)",'-section:httpErrors','/errorMode:DetailedLocalOnly','/commit:apphost') },
      @{ Description = 'Removed Server header'; Arguments = @('set','config','/section:system.webServer/security/requestFiltering','/removeServerHeader:true','/commit:apphost') },
      @{ Description = 'Removed X-Powered-By header'; Arguments = @('set','config','/section:system.webServer/httpProtocol','/-customHeaders.[name=\"X-Powered-By\"]','/commit:apphost') },
      @{ Description = 'Required SSL for Default Web Site'; Arguments = @('set','config',"$($script:DefaultSiteName)",'/section:access','/sslFlags:Ssl','/commit:apphost') },
      @{ Description = 'HSTS header enabled'; Arguments = @('set','config',"$($script:DefaultSiteName)",'-section:system.webServer/httpProtocol','/-customHeaders.[name=\"Strict-Transport-Security\"]','/commit:apphost') },
      @{ Description = 'Added HSTS header'; Arguments = @('set','config',"$($script:DefaultSiteName)",'-section:system.webServer/httpProtocol','/+customHeaders.[name=\"Strict-Transport-Security\",value=\"max-age=31536000; includeSubDomains\"]','/commit:apphost') },
      @{ Description = 'Disabled anonymous authentication'; Arguments = @('set','config',"$($script:DefaultSiteName)",'-section:system.webServer/security/authentication/anonymousAuthentication','/enabled:false','/commit:apphost') },
      @{ Description = 'Enabled Windows authentication'; Arguments = @('set','config',"$($script:DefaultSiteName)",'-section:system.webServer/security/authentication/windowsAuthentication','/enabled:true','/commit:apphost') },
      @{ Description = 'Disabled Basic authentication'; Arguments = @('set','config',"$($script:DefaultSiteName)",'-section:system.webServer/security/authentication/basicAuthentication','/enabled:false','/commit:apphost') },
      @{ Description = 'Disabled WebDAV authoring'; Arguments = @('set','config',"$($script:DefaultSiteName)/",'/section:system.webServer/webdav/authoring','/enabled:false','/commit:apphost') },
      @{ Description = 'Hardened request filtering (no double-escaping, no unlisted extensions)'; Arguments = @('set','config',"$($script:DefaultSiteName)",'/section:system.webServer/security/requestFiltering','/allowDoubleEscaping:false','/fileExtensions.allowUnlisted:false','/fileExtensions.applyToWebDAV:false','/commit:apphost') },
      @{ Description = 'Removed existing TRACE allowance'; Arguments = @('set','config',"$($script:DefaultSiteName)",'/section:system.webServer/security/requestFiltering','/-verbs.[verb=\"TRACE\"]','/commit:apphost') },
      @{ Description = 'Explicitly denied TRACE verb'; Arguments = @('set','config',"$($script:DefaultSiteName)",'/section:system.webServer/security/requestFiltering','/+verbs.[verb=\"TRACE\",allowed=\"false\"]','/commit:apphost') },
      @{ Description = 'Ensured default documents feature is enabled'; Arguments = @('set','config','/section:defaultDocument','/enabled:true','/commit:apphost') },
      @{ Description = 'Enabled HTTP logging'; Arguments = @('set','config',"$($script:DefaultSiteName)",'-section:system.webServer/httpLogging','/dontLog:false','/commit:apphost') }
    )

    $windowsAuthAvailable = Test-FeatureEnabled -Name 'IIS-WindowsAuthentication'
    $basicAuthAvailable   = Test-FeatureEnabled -Name 'IIS-BasicAuthentication'
    $webDavAvailable      = Test-FeatureEnabled -Name 'IIS-WebDAV'

    if (-not $windowsAuthAvailable) {
      $operations = $operations | Where-Object { $_.Description -ne 'Enabled Windows authentication' }
      Write-Warn '[IIS] Windows Authentication feature is not enabled; skipping enablement.'
    }
    if (-not $basicAuthAvailable) {
      $operations = $operations | Where-Object { $_.Description -ne 'Disabled Basic authentication' }
    }
    if (-not $webDavAvailable) {
      $operations = $operations | Where-Object { $_.Description -ne 'Disabled WebDAV authoring' }
    }

    foreach ($op in $operations) {
      if (Invoke-AppCmdCommand -Arguments $op.Arguments -Description $op.Description) {
        $changes += $op.Description
      }
    }

    if (Protect-IISDirectories) {
      $changes += 'Removed write access for broad principals on inetpub'
    }

    $message = if ($changes.Count -gt 0) {
      'IIS hardening applied: ' + ($changes -join '; ')
    }
    else {
      'No IIS changes were necessary.'
    }

    return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message $message)
  }
  catch {
    Write-Err ("IIS hardening failed: {0}" -f $_.Exception.Message)
    return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message ('IIS hardening error: ' + $_.Exception.Message))
  }
}

function Invoke-Verify {
  param($Context)

  $checks = @()
  $failed = @()

  $windowsAuthAvailable = Test-FeatureEnabled -Name 'IIS-WindowsAuthentication'
  $basicAuthAvailable   = Test-FeatureEnabled -Name 'IIS-BasicAuthentication'
  $webDavAvailable      = Test-FeatureEnabled -Name 'IIS-WebDAV'

  $verifications = @(
    @{ Name = 'DirBrowseSite';   Result = Test-AppCmdSetting -Arguments @('list','config',"$($script:DefaultSiteName)",'-section:system.webServer/directoryBrowse') -Pattern 'enabled:"false"' },
    @{ Name = 'DirBrowseServer'; Result = Test-AppCmdSetting -Arguments @('list','config','/section:system.webServer/directoryBrowse') -Pattern 'enabled:"false"' },
    @{ Name = 'HttpErrors';      Result = Test-AppCmdSetting -Arguments @('list','config',"$($script:DefaultSiteName)",'-section:httpErrors') -Pattern 'errorMode:"(DetailedLocalOnly|Custom)"' },
    @{ Name = 'RemoveServerHdr'; Result = Test-AppCmdSetting -Arguments @('list','config','/section:system.webServer/security/requestFiltering') -Pattern 'removeServerHeader:"true"' },
    @{ Name = 'RemovePoweredBy'; Result = Test-AppCmdSetting -Arguments @('list','config','/section:system.webServer/httpProtocol') -Pattern 'X-Powered-By' -Negate },
    @{ Name = 'RequireSSL';      Result = Test-AppCmdSetting -Arguments @('list','config',"$($script:DefaultSiteName)",'-section:access') -Pattern 'sslFlags:"Ssl' },
    @{ Name = 'RequestFilter';   Result = Test-AppCmdSetting -Arguments @('list','config',"$($script:DefaultSiteName)",'/section:system.webServer/security/requestFiltering') -Pattern 'allowDoubleEscaping:"false"' },
    @{ Name = 'TraceBlocked';    Result = Test-AppCmdSetting -Arguments @('list','config',"$($script:DefaultSiteName)",'/section:system.webServer/security/requestFiltering') -Pattern "verb='TRACE',allowed='false'" },
    @{ Name = 'Logging';         Result = Test-AppCmdSetting -Arguments @('list','config',"$($script:DefaultSiteName)",'-section:system.webServer/httpLogging') -Pattern 'dontLog:"false"' },
    @{ Name = 'HstsHeader';      Result = Test-AppCmdSetting -Arguments @('list','config',"$($script:DefaultSiteName)",'-section:system.webServer/httpProtocol') -Pattern 'Strict-Transport-Security' },
    @{ Name = 'DefaultDocs';     Result = Test-AppCmdSetting -Arguments @('list','config','/section:defaultDocument') -Pattern 'enabled:"true"' },
    @{ Name = 'AnonymousAuth';   Result = Test-AppCmdSetting -Arguments @('list','config',"$($script:DefaultSiteName)",'-section:system.webServer/security/authentication/anonymousAuthentication') -Pattern 'enabled:"false"' },
    @{ Name = 'WindowsAuth';     Result = Test-AppCmdSetting -Arguments @('list','config',"$($script:DefaultSiteName)",'-section:system.webServer/security/authentication/windowsAuthentication') -Pattern 'enabled:"true"' },
    @{ Name = 'BasicAuth';       Result = Test-AppCmdSetting -Arguments @('list','config',"$($script:DefaultSiteName)",'-section:system.webServer/security/authentication/basicAuthentication') -Pattern 'enabled:"false"' },
    @{ Name = 'WebDAV';          Result = Test-AppCmdSetting -Arguments @('list','config',"$($script:DefaultSiteName)/",'/section:system.webServer/webdav/authoring') -Pattern 'enabled:"false"' }
  )

  if (-not $windowsAuthAvailable) {
    $verifications = $verifications | Where-Object { $_.Name -ne 'WindowsAuth' }
    $checks += 'WindowsAuth=Skipped'
  }
  if (-not $basicAuthAvailable) {
    $verifications = $verifications | Where-Object { $_.Name -ne 'BasicAuth' }
    $checks += 'BasicAuth=Skipped'
  }
  if (-not $webDavAvailable) {
    $verifications = $verifications | Where-Object { $_.Name -ne 'WebDAV' }
    $checks += 'WebDAV=Skipped'
  }

  foreach ($v in $verifications) {
    $state = $v.Result
    if ($state -eq $true) {
      $checks += "${($v.Name)}=OK"
    }
    elseif ($state -eq $false) {
      $checks += "${($v.Name)}=NeedsAttention"
      $failed += $v.Name
    }
    else {
      $checks += "${($v.Name)}=Skipped"
    }
  }

  foreach ($path in @('C:\\inetpub','C:\\inetpub\\wwwroot')) {
    $writeIssues = @()
    foreach ($identity in $script:RestrictedIdentities) {
      if (Test-IdentityHasWriteAccess -Path $path -Identity $identity) {
        $writeIssues += $identity
      }
    }

    if ($writeIssues.Count -gt 0) {
      $checks += "ACL($path)=NeedsAttention(${($writeIssues -join ',')})"
      $failed += "ACL_$path"
    }
    else {
      $checks += "ACL($path)=OK"
    }
  }

  $status = if ($failed.Count -gt 0) { 'NeedsAttention' } else { 'Succeeded' }
  return (New-ModuleResult -Name $script:ModuleName -Status $status -Message ($checks -join '; '))
}

Export-ModuleMember -Function Test-Ready,Invoke-Verify,Invoke-Apply
