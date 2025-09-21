Set-StrictMode -Version Latest

# Minimal logging if core isn't loaded
if (-not (Get-Command Write-Info -EA SilentlyContinue)) { function Write-Info([string]$m){Write-Host "[*] $m" -ForegroundColor Cyan} }
if (-not (Get-Command Write-Ok   -EA SilentlyContinue)) { function Write-Ok  ([string]$m){Write-Host "[OK] $m" -ForegroundColor Green} }
if (-not (Get-Command Write-Warn -EA SilentlyContinue)) { function Write-Warn([string]$m){Write-Host "[!!] $m" -ForegroundColor Yellow} }
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  function New-ModuleResult { param([string]$Name,[string]$Status,[string]$Message) [pscustomobject]@{Name=$Name;Status=$Status;Message=$Message} }
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
    $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if (-not $repo) {
      Register-PSRepository -Default -ErrorAction Stop
      Write-Ok "Registered default PSGallery repository"
    }
    
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
    Write-Ok "PSGallery configured as trusted"
    $results['PSGallery'] = 'Success'
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
      Install-Module -Name NtObjectManager -Repository PSGallery -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
      Import-Module NtObjectManager -Force -ErrorAction Stop
      Write-Ok "NtObjectManager installed and imported successfully"
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
      Install-Module -Name ThreadJob -Repository PSGallery -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
      Write-Ok "ThreadJob installed successfully"
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