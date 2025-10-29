Set-StrictMode -Version Latest

if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

$script:ModuleName    = 'Defensive'
$script:FirewallUrl   = 'https://storage.googleapis.com/sigma.00.edu.ci/dextro-firewall.wfw'
$script:FirewallRoot  = 'C:\\firewall'
$script:FirewallFile  = Join-Path $script:FirewallRoot 'firewall.wfw'

function Test-Ready {
  param($Context)

  if (-not (Get-Command 'netsh.exe' -ErrorAction SilentlyContinue)) {
    Write-Warn 'netsh.exe is not available; firewall import cannot run.'
    return $false
  }
  return $true
}

function Invoke-DownloadFirewallProfile {
  if (-not (Test-Path $script:FirewallRoot)) {
    Write-Info ("Creating firewall workspace at {0}" -f $script:FirewallRoot)
    New-Item -ItemType Directory -Path $script:FirewallRoot -Force | Out-Null
  }

  Write-Info 'Downloading firewall policy definition'
  $prev = $ProgressPreference
  try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $script:FirewallUrl -OutFile $script:FirewallFile -UseBasicParsing -ErrorAction Stop
  } finally {
    $ProgressPreference = $prev
  }
}

function Invoke-ImportFirewallProfile {
  if (-not (Test-Path $script:FirewallFile)) {
    throw 'Firewall configuration file not found after download.'
  }

  Write-Info 'Importing firewall profile using netsh'
  $args = @('advfirewall', 'import', $script:FirewallFile)
  $proc = Start-Process -FilePath 'netsh.exe' -ArgumentList $args -Wait -PassThru -NoNewWindow
  if ($proc.ExitCode -ne 0) {
    throw ("netsh advfirewall import failed with exit code {0}" -f $proc.ExitCode)
  }
}

function Invoke-Verify {
  param($Context)

  try {
    $output = & netsh advfirewall show currentprofile 2>$null
  } catch {
    return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message 'Failed to query firewall state.')
  }

  $enabled = $false
  if ($output) {
    $enabled = ($output -match '(?im)^\s*State\s*ON\b')
  }

  if ($enabled) {
    return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message 'Firewall current profile is enabled.')
  }

  return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message 'Firewall current profile is not enabled.')
}

function Invoke-Apply {
  param($Context)

  try {
    Invoke-DownloadFirewallProfile
    Invoke-ImportFirewallProfile
    return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message 'Imported CyberPatriot firewall configuration.')
  } catch {
    Write-Err ("Defensive module failed: {0}" -f $_.Exception.Message)
    return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message ('Firewall import failed: ' + $_.Exception.Message))
  }
}

Export-ModuleMember -Function Test-Ready,Invoke-Verify,Invoke-Apply
