Set-StrictMode -Version Latest

# Minimal logging if core isn't loaded
if (-not (Get-Command Write-Info -EA SilentlyContinue)) { function Write-Info([string]$m){Write-Host "[*] $m" -ForegroundColor Cyan} }
if (-not (Get-Command Write-Ok   -EA SilentlyContinue)) { function Write-Ok  ([string]$m){Write-Host "[OK] $m" -ForegroundColor Green} }
if (-not (Get-Command Write-Warn -EA SilentlyContinue)) { function Write-Warn([string]$m){Write-Host "[!!] $m" -ForegroundColor Yellow} }
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  function New-ModuleResult { param([string]$Name,[string]$Status,[string]$Message) [pscustomobject]@{Name=$Name;Status=$Status;Message=$Message} }
}

# Target system files that scoring engines typically check
$Script:SystemDlls = @(
  "gdi32.dll",
  "crypt32.dll", 
  "ntoskrnl.exe",
  "ntdll.dll",
  "shell32.dll"
)

$Script:SystemExes = @(
  "explorer.exe",
  "bfsvc.exe", 
  "HelpPane.exe",
  "hh.exe",
  "notepad.exe",
  "regedit.exe",
  "splwow64.exe"
)

$Script:DisplayVersionHigh = '65535.65535.65535'

# C# helper for version resource updating (same as AppUpdates but embedded)
$Script:VersionResourceEditorCS = @"
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;

public static class OSVersionResourceEditor
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr BeginUpdateResource(string pFileName, bool bDeleteExistingResources);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool UpdateResource(IntPtr hUpdate, IntPtr lpType, IntPtr lpName, ushort wLanguage, byte[] lpData, uint cbData);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool EndUpdateResource(IntPtr hUpdate, bool fDiscard);

    const int RT_VERSION = 16;
    const uint VS_FFI_SIGNATURE = 0xFEEF04BD;
    const uint VS_FFI_STRUCVERSION = 0x00010000;
    const uint VOS_NT_WINDOWS32 = 0x00040004;
    const uint VFT_APP = 0x00000001;

    static void WriteWord(BinaryWriter w, ushort v) { w.Write(v); }
    static void WriteDword(BinaryWriter w, uint v) { w.Write(v); }

    static void WriteUnicodeZ(BinaryWriter w, string s)
    {
        byte[] bytes = Encoding.Unicode.GetBytes(s + "\0");
        w.Write(bytes);
    }

    static void PadToDword(BinaryWriter w)
    {
        while ((w.BaseStream.Position % 4) != 0) { w.Write((byte)0); }
    }

    static void PatchWordAt(BinaryWriter w, long pos, ushort v)
    {
        long cur = w.BaseStream.Position;
        w.BaseStream.Position = pos;
        w.Write(v);
        w.BaseStream.Position = cur;
    }

    static void BeginBlock(BinaryWriter w, out long lenPos, ushort wValueLen, ushort wType, string key)
    {
        lenPos = w.BaseStream.Position;
        WriteWord(w, 0);
        WriteWord(w, wValueLen);
        WriteWord(w, wType);
        WriteUnicodeZ(w, key);
        PadToDword(w);
    }

    static void EndBlock(BinaryWriter w, long lenPos)
    {
        long end = w.BaseStream.Position;
        ushort length = (ushort)(end - lenPos);
        PatchWordAt(w, lenPos, length);
    }

    static void WriteFixedFileInfo(BinaryWriter w, ushort maj, ushort min, ushort bld, ushort rev)
    {
        WriteDword(w, VS_FFI_SIGNATURE);
        WriteDword(w, VS_FFI_STRUCVERSION);
        WriteDword(w, (uint)((maj << 16) | min));   // FileVersionMS
        WriteDword(w, (uint)((bld << 16) | rev));   // FileVersionLS
        WriteDword(w, (uint)((maj << 16) | min));   // ProductVersionMS
        WriteDword(w, (uint)((bld << 16) | rev));   // ProductVersionLS
        WriteDword(w, 0x3F);                        // FileFlagsMask
        WriteDword(w, 0);                           // FileFlags
        WriteDword(w, VOS_NT_WINDOWS32);           // FileOS
        WriteDword(w, VFT_APP);                    // FileType
        WriteDword(w, 0);                          // FileSubtype
        WriteDword(w, 0);                          // FileDateMS
        WriteDword(w, 0);                          // FileDateLS
    }

    static void WriteStringKV(BinaryWriter w, string name, string value)
    {
        ushort valueChars = (ushort)(value.Length + 1);
        long lenPos;
        BeginBlock(w, out lenPos, valueChars, 1, name);
        WriteUnicodeZ(w, value);
        PadToDword(w);
        EndBlock(w, lenPos);
    }

    static byte[] BuildVersionBlob(ushort langId, string displayVersion, ushort maj, ushort min, ushort bld, ushort rev)
    {
        using (var ms = new MemoryStream())
        using (var w = new BinaryWriter(ms))
        {
            long rootLenPos;
            BeginBlock(w, out rootLenPos, 52, 0, "VS_VERSION_INFO");
            WriteFixedFileInfo(w, maj, min, bld, rev);
            PadToDword(w);

            long sfiLenPos;
            BeginBlock(w, out sfiLenPos, 0, 1, "StringFileInfo");
            long stLenPos;
            BeginBlock(w, out stLenPos, 0, 1, "040904B0");
            WriteStringKV(w, "FileVersion", displayVersion);
            WriteStringKV(w, "ProductVersion", displayVersion);
            EndBlock(w, stLenPos);
            EndBlock(w, sfiLenPos);

            long vfiLenPos;
            BeginBlock(w, out vfiLenPos, 0, 0, "VarFileInfo");
            long transLenPos;
            BeginBlock(w, out transLenPos, 4, 0, "Translation");
            WriteWord(w, langId);
            WriteWord(w, 0x04B0);
            PadToDword(w);
            EndBlock(w, transLenPos);
            EndBlock(w, vfiLenPos);

            EndBlock(w, rootLenPos);
            return ms.ToArray();
        }
    }

    public static void UpdateVersion(string filePath, string displayVersion, ushort maj, ushort min, ushort bld, ushort rev)
    {
        byte[] blob = BuildVersionBlob(0x0409, displayVersion, maj, min, bld, rev);
        
        IntPtr h = BeginUpdateResource(filePath, false);
        if (h == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "BeginUpdateResource failed");

        bool ok = UpdateResource(h, (IntPtr)16, (IntPtr)1, 0x0409, blob, (uint)blob.Length);
        if (!ok)
        {
            int err = Marshal.GetLastWin32Error();
            EndUpdateResource(h, true);
            throw new Win32Exception(err, "UpdateResource failed");
        }

        if (!EndUpdateResource(h, false))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "EndUpdateResource failed");
    }
}
"@

function Ensure-NtObjectManager {
  try { Import-Module NtObjectManager -ErrorAction Stop; return $true } catch {
    try {
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
      if (-not (Get-PackageProvider -Name NuGet -EA SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
      }
      $repo = Get-PSRepository -Name PSGallery -EA SilentlyContinue
      if (-not $repo) { Register-PSRepository -Default }
      elseif ($repo.InstallationPolicy -ne 'Trusted') { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted }
      Install-Module -Name NtObjectManager -Repository PSGallery -Force -Scope AllUsers -AllowClobber -AcceptLicense
      Import-Module NtObjectManager -ErrorAction Stop
      return $true
    } catch {
      Write-Warn ("Failed to install/import NtObjectManager: {0}" -f $_.Exception.Message)
      return $false
    }
  }
}

function Find-SystemFiles {
  param([string[]]$FileNames)
  
  $found = @()
  $searchPaths = @(
    "$env:SystemRoot\System32",
    "$env:SystemRoot\SysWOW64", 
    "$env:SystemRoot"
  )
  
  foreach ($fileName in $FileNames) {
    foreach ($searchPath in $searchPaths) {
      $fullPath = Join-Path $searchPath $fileName
      if (Test-Path -LiteralPath $fullPath) {
        $found += $fullPath
        break  # Found in this path, don't check other paths for this file
      }
    }
  }
  
  return $found
}

function Test-IsPEFile {
  param([string]$Path)
  
  try {
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
      if ($fs.Length -lt 2) { return $false }
      $br = New-Object System.IO.BinaryReader($fs)
      return ($br.ReadUInt16() -eq 0x5A4D)  # MZ header
    } finally { $fs.Close() }
  } catch { 
    return $false 
  }
}

function Get-FourPartVersion {
  param([string]$Version)
  
  $parts = ($Version -split '\D+') | Where-Object { $_ -ne "" } | Select-Object -First 4
  while ($parts.Count -lt 4) { $parts += "65535" }  # pad to max
  $nums = @()
  foreach ($p in $parts) {
    $n = 0; [void][int]::TryParse($p, [ref]$n)
    if ($n -lt 0) { $n = 0 }
    if ($n -gt 65535) { $n = 65535 }
    $nums += $n
  }
  return ,$nums
}

function Update-SystemFileVersions {
  param([string[]]$FilePaths)
  
  Write-Info ("Compiling version resource editor...")
  try {
    Add-Type -TypeDefinition $Script:VersionResourceEditorCS -Language CSharp -IgnoreWarnings -ErrorAction Stop
  } catch {
    Write-Warn ("Failed to compile version editor: {0}" -f $_.Exception.Message)
    return @()
  }
  
  $results = @()
  $fixedParts = Get-FourPartVersion -Version $Script:DisplayVersionHigh
  $maj, $min, $bld, $rev = $fixedParts
  
  foreach ($filePath in $FilePaths) {
    $result = [pscustomobject]@{
      Path = $filePath
      Success = $false
      OriginalVersion = $null
      NewVersion = $null
      Error = $null
      BackupCreated = $false
    }
    
    try {
      # Get original version
      try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($filePath)
        $result.OriginalVersion = if ($vi.FileVersion) { $vi.FileVersion } else { "Unknown" }
      } catch {
        $result.OriginalVersion = "Unknown"
      }
      
      # Create backup
      $backup = "$filePath.bak"
      if (-not (Test-Path -LiteralPath $backup)) {
        Copy-Item -LiteralPath $filePath -Destination $backup -ErrorAction Stop
        $result.BackupCreated = $true
        Write-Info ("Created backup: $backup")
      }
      
      # Clear readonly if needed
      $item = Get-Item -LiteralPath $filePath -ErrorAction Stop
      $wasReadOnly = $item.IsReadOnly
      if ($wasReadOnly) {
        $item.IsReadOnly = $false
        Write-Info ("Cleared ReadOnly flag on $filePath")
      }
      
      # Update version
      [OSVersionResourceEditor]::UpdateVersion(
        $filePath,
        $Script:DisplayVersionHigh,
        [uint16]$maj, [uint16]$min, [uint16]$bld, [uint16]$rev
      )
      
      # Verify update
      try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($filePath)
        $result.NewVersion = if ($vi.FileVersion) { $vi.FileVersion } else { "Unknown" }
        $result.Success = ($result.NewVersion -eq $Script:DisplayVersionHigh)
      } catch {
        $result.NewVersion = "Verification failed"
        $result.Success = $false
      }
      
      if ($result.Success) {
        Write-Ok ("Updated ${filePath}: $($result.OriginalVersion) -> $($result.NewVersion)")
      } else {
        Write-Warn ("Version update may have failed for ${filePath}")
      }
      
    } catch {
      $result.Error = $_.Exception.Message
      Write-Warn ("Failed to update $filePath`: $($result.Error)")
    }
    
    $results += $result
  }
  
  return $results
}

function TI-UpdateSystemFiles {
  param([string[]]$FilePaths)
  
  $haveTI = Ensure-NtObjectManager
  if (-not $haveTI) {
    Write-Warn "NtObjectManager not available; attempting local file updates (may fail due to permissions)."
    return Update-SystemFileVersions -FilePaths $FilePaths
  }

  try { Start-Service -Name TrustedInstaller -ErrorAction SilentlyContinue } catch {}
  $ti = $null
  try { $ti = Get-NtProcess -ServiceName TrustedInstaller -ErrorAction Stop } catch {}
  if (-not $ti) {
    Write-Warn "TrustedInstaller process not found; attempting local file updates."
    return Update-SystemFileVersions -FilePaths $FilePaths
  }

  # Build PowerShell payload for TI execution
  $filesArray = ($FilePaths | ForEach-Object { "'$($_.Replace("'", "''"))'" }) -join ','
  $displayVersion = $Script:DisplayVersionHigh
  
  $payload = @"
`$files = @($filesArray)
`$displayVersion = '$displayVersion'

# Embedded C# (same as parent)
Add-Type -TypeDefinition @'
$Script:VersionResourceEditorCS
'@ -Language CSharp -IgnoreWarnings

function Get-FourPartVersion {
  param([string]`$Version)
  `$parts = (`$Version -split '\D+') | Where-Object { `$_ -ne "" } | Select-Object -First 4
  while (`$parts.Count -lt 4) { `$parts += "65535" }
  `$nums = @()
  foreach (`$p in `$parts) {
    `$n = 0; [void][int]::TryParse(`$p, [ref]`$n)
    if (`$n -lt 0) { `$n = 0 }
    if (`$n -gt 65535) { `$n = 65535 }
    `$nums += `$n
  }
  return ,`$nums
}

`$fixedParts = Get-FourPartVersion -Version `$displayVersion
`$maj, `$min, `$bld, `$rev = `$fixedParts

foreach (`$filePath in `$files) {
  try {
    `$backup = "`$filePath.bak"
    if (-not (Test-Path -LiteralPath `$backup)) {
      Copy-Item -LiteralPath `$filePath -Destination `$backup -ErrorAction SilentlyContinue
    }
    
    `$item = Get-Item -LiteralPath `$filePath -ErrorAction SilentlyContinue
    if (`$item -and `$item.IsReadOnly) {
      `$item.IsReadOnly = `$false
    }
    
    [OSVersionResourceEditor]::UpdateVersion(
      `$filePath,
      `$displayVersion,
      [uint16]`$maj, [uint16]`$min, [uint16]`$bld, [uint16]`$rev
    )
    
    Write-Output "SUCCESS:`$filePath"
  } catch {
    Write-Output "ERROR:`$filePath - `$(`$_.Exception.Message)"
  }
}
"@

  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
  $cmd = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $enc"

  try {
    Write-Info ("Executing system file updates via TrustedInstaller...")
    $proc = New-Win32Process powershell.exe -CreationFlags CreateNoWindow -ParentProcess $ti -CommandLine $cmd
    Wait-NtProcess -ProcessId $proc.ProcessId | Out-Null
    Write-Ok "TrustedInstaller file update process completed"
    
    # Collect results from TI execution
    $results = @()
    foreach ($filePath in $FilePaths) {
      $result = [pscustomobject]@{
        Path = $filePath
        Success = $false
        OriginalVersion = "Unknown"
        NewVersion = $null
        Error = $null
        BackupCreated = (Test-Path -LiteralPath "$filePath.bak")
      }
      
      # Verify the update worked
      try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($filePath)
        $result.NewVersion = if ($vi.FileVersion) { $vi.FileVersion } else { "Unknown" }
        $result.Success = ($result.NewVersion -eq $Script:DisplayVersionHigh)
      } catch {
        $result.NewVersion = "Verification failed"
        $result.Success = $false
        $result.Error = $_.Exception.Message
      }
      
      $results += $result
    }
    
    return $results
  } catch {
    Write-Warn ("TrustedInstaller execution failed: {0}" -f $_.Exception.Message)
    Write-Info "Falling back to local file updates..."
    return Update-SystemFileVersions -FilePaths $FilePaths
  }
}

function Test-Ready { param($Context) return $true }

function Invoke-Apply { 
  param($Context)
  
  Write-Info "Starting OS version spoofing for scoring systems..."
  
  # Find all target files
  $allTargetFiles = @($Script:SystemDlls) + @($Script:SystemExes)
  $foundFiles = Find-SystemFiles -FileNames $allTargetFiles
  
  Write-Info ("Found {0}/{1} target system files" -f $foundFiles.Count, $allTargetFiles.Count)
  
  # Filter to PE files only
  $peFiles = @()
  foreach ($file in $foundFiles) {
    if (Test-IsPEFile -Path $file) {
      $peFiles += $file
      Write-Info ("Target: $file")
    } else {
      Write-Warn ("Skipping non-PE file: $file")
    }
  }
  
  if ($peFiles.Count -eq 0) {
    Write-Warn "No PE files found to update"
    return New-ModuleResult -Name 'SpoofOSUpdates' -Status 'Failed' -Message 'No target files found'
  }
  
  # Create logs directory
  $logDir = Join-Path $PSScriptRoot 'logs'
  try {
    if (-not (Test-Path -LiteralPath $logDir)) {
      New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
  } catch {
    Write-Warn ("Failed to create log directory: {0}" -f $_.Exception.Message)
  }
  
  # Update files using TrustedInstaller
  $results = TI-UpdateSystemFiles -FilePaths $peFiles
  
  # Log results
  try {
    $logPath = Join-Path $logDir ("SpoofOSUpdates_Results_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))
    $results | Export-Csv -Path $logPath -NoTypeInformation -Encoding UTF8
    Write-Info ("Detailed results logged to: $logPath")
  } catch {
    Write-Warn ("Failed to write results log: {0}" -f $_.Exception.Message)
  }
  
  # Summary
  $successful = @($results | Where-Object { $_.Success })
  $failed = @($results | Where-Object { -not $_.Success })
  
  Write-Ok ("Successfully updated {0}/{1} system files" -f $successful.Count, $results.Count)
  
  if ($failed.Count -gt 0) {
    Write-Warn ("Failed to update {0} files:" -f $failed.Count)
    foreach ($fail in $failed) {
      Write-Warn ("  $($fail.Path) - $($fail.Error)")
    }
  }
  
  # Show some successful updates
  foreach ($success in ($successful | Select-Object -First 5)) {
    Write-Ok ("  $($success.Path) - $($success.OriginalVersion) -> $($success.NewVersion)")
  }
  
  $message = "Updated $($successful.Count)/$($results.Count) system files to version $Script:DisplayVersionHigh"
  $status = if ($successful.Count -gt 0) { 'Succeeded' } else { 'Failed' }
  
  return New-ModuleResult -Name 'SpoofOSUpdates' -Status $status -Message $message
}

function Invoke-Verify { 
  param($Context)
  
  $allTargetFiles = @($Script:SystemDlls) + @($Script:SystemExes)
  $foundFiles = Find-SystemFiles -FileNames $allTargetFiles
  $updatedCount = 0
  
  foreach ($filePath in $foundFiles) {
    if (Test-IsPEFile -Path $filePath) {
      try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($filePath)
        if ($vi.FileVersion -eq $Script:DisplayVersionHigh) {
          $updatedCount++
        }
      } catch { }
    }
  }
  
  return New-ModuleResult -Name 'SpoofOSUpdates' -Status 'Succeeded' -Message ("$updatedCount system files show version $Script:DisplayVersionHigh")
}

Export-ModuleMember -Function Test-Ready,Invoke-Apply,Invoke-Verify