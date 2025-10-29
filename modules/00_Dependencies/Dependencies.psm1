Set-StrictMode -Version Latest

# Minimal logging if core isn't loaded
if (-not (Get-Command Write-Info -EA SilentlyContinue)) { function Write-Info([string]$m){Write-Host "[*] $m" -ForegroundColor Cyan} }
if (-not (Get-Command Write-Ok   -EA SilentlyContinue)) { function Write-Ok  ([string]$m){Write-Host "[OK] $m" -ForegroundColor Green} }
if (-not (Get-Command Write-Warn -EA SilentlyContinue)) { function Write-Warn([string]$m){Write-Host "[!!] $m" -ForegroundColor Yellow} }
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  function New-ModuleResult { param([string]$Name,[string]$Status,[string]$Message) [pscustomobject]@{Name=$Name;Status=$Status;Message=$Message} }
}

function Set-PSGalleryTrusted {
  param(
    [switch]$ForceReRegister
  )

  $registered = $false

  if ($ForceReRegister) {
    Write-Info "Re-registering PSGallery from scratch..."
    try {
      Unregister-PSRepository -Name PSGallery -ErrorAction SilentlyContinue | Out-Null
    } catch {
      Write-Warn ("Failed to unregister PSGallery: {0}" -f $_.Exception.Message)
    }
  }

  $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
  if (-not $repo) {
    Register-PSRepository -Name PSGallery -SourceLocation 'https://www.powershellgallery.com/api/v2/' -ScriptSourceLocation 'https://www.powershellgallery.com/api/v2/' -PackageManagementProvider 'NuGet' -InstallationPolicy Trusted -ErrorAction Stop
    $registered = $true
    $repo = Get-PSRepository -Name PSGallery -ErrorAction Stop
    Write-Ok "Registered PSGallery repository"
  }

  try {
    if ($repo.InstallationPolicy -ne 'Trusted') {
      Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
      $repo = Get-PSRepository -Name PSGallery -ErrorAction Stop
    }
    Write-Ok "PSGallery configured as trusted"
    if ($registered -or $ForceReRegister) {
      return 'Success (registered)'
    }
    return 'Success'
  } catch {
    if (-not $ForceReRegister -and $_.Exception.Message -match 'PowerShell Gallery is currently unavailable') {
      Write-Warn "Initial PSGallery configuration failed due to availability; attempting fallback..."
      return Set-PSGalleryTrusted -ForceReRegister
    }
    throw
  }
}

function Ensure-ModuleFromGallery {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [switch]$ImportAfterInstall
  )

  $installed = $false
  $attempt = 0

  while (-not $installed -and $attempt -lt 2) {
    try {
      Install-Module -Name $Name -Repository PSGallery -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
      $installed = $true
    } catch {
      if ($attempt -eq 0 -and $_.Exception.Message -match 'PowerShell Gallery is currently unavailable') {
        Write-Warn ("Install-Module for {0} failed: {1}" -f $Name, $_.Exception.Message)
        $null = Set-PSGalleryTrusted -ForceReRegister
        $attempt++
        continue
      }
      throw
    }
  }

  if (-not $installed) {
    throw "Failed to install module $Name"
  }

  if ($ImportAfterInstall) {
    Import-Module $Name -Force -ErrorAction Stop
  }

  Write-Ok ("{0} installed successfully" -f $Name)
}

function Install-PowerShellDependencies {
  Write-Info "Installing required PowerShell dependencies..."

  $results = [ordered]@{}
  
  # 1. Install/Update NuGet PackageProvider (required for Install-Module)
  Write-Info "Ensuring NuGet PackageProvider is installed..."
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    # Force install NuGet provider without prompts
    $nugetProvider = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -ErrorAction Stop
    Write-Ok "NuGet PackageProvider installed successfully"
    $results['NuGet'] = 'Success'
  } catch {
    Write-Warn ("Failed to install NuGet PackageProvider: {0}" -f $_.Exception.Message)
    $results['NuGet'] = "Failed: $($_.Exception.Message)"
  }
  
  # 2. Configure PSGallery as trusted (eliminates prompts)
  Write-Info "Configuring PSGallery as trusted repository..."
  try {
    $results['PSGallery'] = Set-PSGalleryTrusted
  } catch {
    Write-Warn ("Failed to configure PSGallery: {0}" -f $_.Exception.Message)
    $results['PSGallery'] = "Failed: $($_.Exception.Message)"
  }
  
  # 3. Install NtObjectManager (required for TrustedInstaller operations)
  Write-Info "Installing NtObjectManager module..."
  try {
    # Check if already installed
    $existing = Get-Module -ListAvailable -Name NtObjectManager -ErrorAction SilentlyContinue
    if ($existing) {
      Write-Info ("NtObjectManager already installed (version {0})" -f $existing.Version)
      Import-Module NtObjectManager -Force -ErrorAction Stop
      Write-Ok "NtObjectManager imported successfully"
      $results['NtObjectManager'] = 'Already installed'
    } else {
      # Install fresh
      Ensure-ModuleFromGallery -Name NtObjectManager -ImportAfterInstall
      $results['NtObjectManager'] = 'Success'
    }
  } catch {
    Write-Warn ("Failed to install/import NtObjectManager: {0}" -f $_.Exception.Message)
    $results['NtObjectManager'] = "Failed: $($_.Exception.Message)"
  }
  
  # 4. Install ThreadJob if needed (for better parallel processing on PS 5.1)
  Write-Info "Installing ThreadJob module (optional)..."
  try {
    $existing = Get-Module -ListAvailable -Name ThreadJob -ErrorAction SilentlyContinue
    if ($existing) {
      Write-Info ("ThreadJob already installed (version {0})" -f $existing.Version)
      $results['ThreadJob'] = 'Already installed'
    } else {
      Ensure-ModuleFromGallery -Name ThreadJob
      $results['ThreadJob'] = 'Success'
    }
  } catch {
    Write-Warn ("Failed to install ThreadJob: {0}" -f $_.Exception.Message)
    $results['ThreadJob'] = "Failed: $($_.Exception.Message)"
  }
  
  return $results
}

function Test-Ready { param($Context) return $true }

function Invoke-Apply { 
  param($Context)
  
  $results = Install-PowerShellDependencies
  
  # Count successes
  $successful = 0
  $total = $results.Count
  foreach ($key in $results.Keys) {
    if ($results[$key] -match '^(Success|Already installed)') {
      $successful++
    }
  }
  
  $message = "Installed $successful/$total dependencies successfully"
  $status = if ($successful -eq $total) { 'Succeeded' } else { 'PartialSuccess' }
  
  return New-ModuleResult -Name 'Dependencies' -Status $status -Message $message
}

function Invoke-Verify { 
  param($Context)
  
  $checks = [ordered]@{}
  
  # Verify NuGet provider
  try {
    $nuget = Get-PackageProvider -Name NuGet -ErrorAction Stop
    $checks['NuGet'] = "OK (v$($nuget.Version))"
  } catch {
    $checks['NuGet'] = 'Missing'
  }
  
  # Verify PSGallery trusted
  try {
    $repo = Get-PSRepository -Name PSGallery -ErrorAction Stop
    $checks['PSGallery'] = if ($repo.InstallationPolicy -eq 'Trusted') { 'Trusted' } else { 'Untrusted' }
  } catch {
    $checks['PSGallery'] = 'Missing'
  }
  
  # Verify NtObjectManager
  try {
    Import-Module NtObjectManager -Force -ErrorAction Stop
    $mod = Get-Module NtObjectManager -ErrorAction Stop
    $checks['NtObjectManager'] = "OK (v$($mod.Version))"
  } catch {
    $checks['NtObjectManager'] = 'Missing'
  }
  
  # Verify ThreadJob
  try {
    $mod = Get-Module -ListAvailable -Name ThreadJob -ErrorAction Stop
    $checks['ThreadJob'] = "Available (v$($mod.Version))"
  } catch {
    $checks['ThreadJob'] = 'Missing'
  }
  
  $summary = ($checks.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
  return New-ModuleResult -Name 'Dependencies' -Status 'Succeeded' -Message $summary
}

Export-ModuleMember -Function Test-Ready,Invoke-Apply,Invoke-Verify