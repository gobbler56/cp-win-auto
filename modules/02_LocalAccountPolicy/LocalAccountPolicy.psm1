Set-StrictMode -Version Latest

if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

$script:ModuleName          = 'LocalAccountPolicy'
$script:PolicyArchiveUrl    = 'https://storage.googleapis.com/sigma.00.edu.ci/server22.zip'
$script:PolicyArchivePath   = 'C:\\server22.zip'
$script:PolicyExtractRoot   = 'C:\\server22'
$script:PolicyPayloadFolder = 'server22'

function Test-Ready {
  param($Context)

  $required = @('Invoke-WebRequest', 'Expand-Archive', 'secedit.exe', 'auditpol.exe', 'gpupdate.exe')
  foreach ($name in $required) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
      Write-Warn ("Missing required command for LocalAccountPolicy: {0}" -f $name)
      return $false
    }
  }

  return $true
}

function Invoke-CopyTree {
  param(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Destination
  )

  if (-not (Test-Path $Source)) {
    throw ("Source path not found: {0}" -f $Source)
  }

  $robo = Get-Command 'robocopy.exe' -ErrorAction SilentlyContinue
  if ($robo) {
    $args = @(
      '"{0}"' -f $Source,
      '"{0}"' -f $Destination,
      '/E',
      '/R:1',
      '/W:1',
      '/NFL',
      '/NDL',
      '/NJH',
      '/NJS',
      '/NP'
    )

    $proc = Start-Process -FilePath $robo.Source -ArgumentList $args -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -gt 7) {
      throw ("robocopy failed with exit code {0}" -f $proc.ExitCode)
    }
  } else {
    Copy-Item -Path $Source -Destination $Destination -Recurse -Force -ErrorAction Stop
  }
}

function Invoke-PolicyImport {
  param()

  $archivePath = $script:PolicyArchivePath
  $extractRoot = $script:PolicyExtractRoot
  $payloadRoot = Join-Path $extractRoot $script:PolicyPayloadFolder

  if (Test-Path $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path $extractRoot) {
    Remove-Item -LiteralPath $extractRoot -Recurse -Force -ErrorAction SilentlyContinue
  }

  Write-Info ("Downloading policy archive from {0}" -f $script:PolicyArchiveUrl)
  $prevPref = $ProgressPreference
  try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $script:PolicyArchiveUrl -OutFile $archivePath -UseBasicParsing -ErrorAction Stop
  } finally {
    $ProgressPreference = $prevPref
  }

  Write-Info ("Expanding archive to {0}" -f $extractRoot)
  Expand-Archive -Path $archivePath -DestinationPath $extractRoot -Force -ErrorAction Stop

  if (-not (Test-Path $payloadRoot)) {
    throw ("Extracted archive did not contain expected folder '{0}'" -f $script:PolicyPayloadFolder)
  }

  $groupPolicySource = Join-Path $payloadRoot 'GroupPolicy'
  $policyDefSource   = Join-Path $payloadRoot 'PolicyDefinitions'
  $securityCfg       = Join-Path $payloadRoot 'Security.cfg'
  $auditIni          = Join-Path $payloadRoot 'Audit.ini'

  Write-Info 'Copying GroupPolicy content into System32'
  Invoke-CopyTree -Source $groupPolicySource -Destination 'C:\\Windows\\System32\\GroupPolicy'

  if (Test-Path $policyDefSource) {
    Write-Info 'Copying PolicyDefinitions into Windows directory'
    try {
      Invoke-CopyTree -Source $policyDefSource -Destination 'C:\\Windows\\PolicyDefinitions'
    } catch {
      Write-Warn ("PolicyDefinitions copy reported issues: {0}" -f $_.Exception.Message)
    }
  } else {
    Write-Warn 'PolicyDefinitions folder missing from archive; skipping copy'
  }

  if (-not (Test-Path $securityCfg)) {
    throw 'Security.cfg not found in policy archive.'
  }
  if (-not (Test-Path $auditIni)) {
    throw 'Audit.ini not found in policy archive.'
  }

  Write-Info 'Applying security template (secedit)'
  $secArgs = @('/configure','/cfg',$securityCfg,'/db','defltbase.sdb','/quiet')
  $secProc = Start-Process -FilePath 'secedit.exe' -ArgumentList $secArgs -Wait -PassThru -NoNewWindow
  if ($secProc.ExitCode -ne 0) {
    throw ("secedit.exe returned exit code {0}" -f $secProc.ExitCode)
  }

  Write-Info 'Restoring audit policy settings'
  $auditArgs = @('/restore',"/file:$auditIni")
  $auditProc = Start-Process -FilePath 'auditpol.exe' -ArgumentList $auditArgs -Wait -PassThru -NoNewWindow
  if ($auditProc.ExitCode -ne 0) {
    throw ("auditpol.exe returned exit code {0}" -f $auditProc.ExitCode)
  }

  Write-Info 'Forcing Group Policy refresh without logging off the current user'
  $gpProc = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', 'echo N|gpupdate.exe /force' -Wait -PassThru -NoNewWindow
  if ($gpProc.ExitCode -ne 0) {
    Write-Warn ("gpupdate.exe returned exit code {0}" -f $gpProc.ExitCode)
  }
}

function Invoke-Verify {
  param($Context)

  $requiredPaths = @(
    'C:\\Windows\\System32\\GroupPolicy\\Machine\\Registry.pol',
    'C:\\Windows\\System32\\GroupPolicy\\User\\Registry.pol',
    'C:\\Windows\\System32\\GroupPolicy\\GPT.INI'
  )

  $missing = @($requiredPaths | Where-Object { -not (Test-Path $_) })
  $status = if ($missing.Count -eq 0) { 'Succeeded' } else { 'Failed' }
  $message = if ($missing.Count -eq 0) {
    'Baseline GPO artifacts present.'
  } else {
    'Missing policy artifacts: ' + ($missing -join ', ')
  }

  return (New-ModuleResult -Name $script:ModuleName -Status $status -Message $message)
}

function Invoke-Apply {
  param($Context)

  try {
    Invoke-PolicyImport
    $message = 'Imported CyberPatriot local and account policy package and refreshed policies.'
    $status = 'Succeeded'
  } catch {
    Write-Err ("LocalAccountPolicy apply failed: {0}" -f $_.Exception.Message)
    $message = 'Failed to import local/account policies: ' + $_.Exception.Message
    $status = 'Failed'
  } finally {
    if (Test-Path $script:PolicyArchivePath) {
      Remove-Item -LiteralPath $script:PolicyArchivePath -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $script:PolicyExtractRoot) {
      Remove-Item -LiteralPath $script:PolicyExtractRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  return (New-ModuleResult -Name $script:ModuleName -Status $status -Message $message)
}

Export-ModuleMember -Function Test-Ready,Invoke-Verify,Invoke-Apply
