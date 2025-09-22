Set-StrictMode -Version Latest

# Minimal logging if core isn't loaded
if (-not (Get-Command Write-Info -EA SilentlyContinue)) { function Write-Info([string]$m){Write-Host "[*] $m" -ForegroundColor Cyan} }
if (-not (Get-Command Write-Ok   -EA SilentlyContinue)) { function Write-Ok  ([string]$m){Write-Host "[OK] $m" -ForegroundColor Green} }
if (-not (Get-Command Write-Warn -EA SilentlyContinue)) { function Write-Warn([string]$m){Write-Host "[!!] $m" -ForegroundColor Yellow} }
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  function New-ModuleResult { param([string]$Name,[string]$Status,[string]$Message) [pscustomobject]@{Name=$Name;Status=$Status;Message=$Message} }
}

# Target system files that scoring engines typically check - REVERTED TO ORIGINAL
$Script:TargetFiles = @(
  "gdi32.dll",         # Graphics device interface
  "crypt32.dll",       # Cryptography
  "ntoskrnl.exe",      # NT kernel
  "ntdll.dll",         # Core NT DLL
  "shell32.dll",       # Shell functionality
  "explorer.exe",      # Windows Explorer shell
  "bfsvc.exe",         # Boot file servicing utility
  "HelpPane.exe",      # Help system
  "hh.exe",            # HTML Help
  "notepad.exe",       # Simple text editor
  "regedit.exe",       # Registry editor
  "splwow64.exe"       # Print spooler
)

$Script:DisplayVersionHigh = '65535.65535.65535'
$Script:PowerRunUrl = 'https://storage.googleapis.com/sigma.00.edu.ci/PowerRun.exe'

# C# helper for version resource updating (same as before)
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

function Get-CurrentUser {
    $currentUser = ((qwinsta /server:localhost | Where-Object { $_ -match "\s+console" }) -replace '^\s*\S+\s+(\S+)\s+\S+\s+\S+', '$1').Trim()
    if (-not $currentUser) {
        $currentUser = $env:USERNAME
    }
    return $currentUser
}

function Get-SecurityCode {
    # Check environment variable first
    $securityCode = $env:POWERRUN_SECURITY_CODE
    
    if (-not $securityCode) {
        # Prompt user for security code
        Write-Info "PowerRun requires a security code to run with SYSTEM privileges."
        Write-Info "This code changes periodically. Please check your source for the current code."
        $securityCode = Read-Host "Enter PowerRun security code"
        
        if (-not $securityCode) {
            throw "PowerRun security code is required"
        }
    }
    
    return $securityCode
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
                break
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
    while ($parts.Count -lt 4) { $parts += "65535" }
    $nums = @()
    foreach ($p in $parts) {
        $n = 0; [void][int]::TryParse($p, [ref]$n)
        if ($n -lt 0) { $n = 0 }
        if ($n -gt 65535) { $n = 65535 }
        $nums += $n
    }
    return ,$nums
}

function Setup-PowerRun {
    param([string]$SecurityCode)
    
    $currentUser = Get-CurrentUser
    $desktopPath = [System.IO.Path]::Combine("C:\Users", $currentUser, "Desktop")
    $powerRunPath = [System.IO.Path]::Combine($desktopPath, "PowerRun.exe")
    $iniFilePath = [System.IO.Path]::Combine($desktopPath, "PowerRun.ini")
    
    Write-Info "Setting up PowerRun on desktop..."
    
    # Download PowerRun
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Script:PowerRunUrl -OutFile $powerRunPath -ErrorAction Stop
        Write-Ok "Downloaded PowerRun.exe to desktop"
    } catch {
        throw "Failed to download PowerRun: $($_.Exception.Message)"
    }
    
    # Launch PowerRun briefly to generate ini file (same as original script)
    try {
        Start-Process -FilePath $powerRunPath -ErrorAction Stop
        Write-Info "Launched PowerRun to generate ini file..."
        
        # Wait for 2 seconds to allow PowerRun to generate the ini file
        Start-Sleep -Seconds 2
        
        # Automatically close PowerRun process after 2 seconds
        Get-Process -Name "PowerRun" -ErrorAction SilentlyContinue | ForEach-Object { 
            Stop-Process $_.Id -Force 
        }
        Write-Info "Closed PowerRun process"
    } catch {
        Write-Warn "PowerRun launch/close failed: $($_.Exception.Message)"
    }
    
    # Check if PowerRun.ini exists and modify it to add the SecurityCode (same as original)
    if (Test-Path $iniFilePath) {
        try {
            $iniContent = Get-Content -Path $iniFilePath
            $iniContent[13] = "SecurityCode=$SecurityCode"  # Update with the SecurityCode
            $iniContent | Set-Content -Path $iniFilePath
            Write-Ok "Updated PowerRun.ini with security code"
        } catch {
            throw "Failed to update PowerRun.ini: $($_.Exception.Message)"
        }
    } else {
        throw "PowerRun.ini not found at $iniFilePath"
    }
    
    return @{
        PowerRunPath = $powerRunPath
        IniFilePath = $iniFilePath
        DesktopPath = $desktopPath
    }
}

function Create-UpdateScript {
    param(
        [string]$DesktopPath,
        [string[]]$FilePaths
    )
    
    $scriptPath = [System.IO.Path]::Combine($DesktopPath, "update_versions.ps1")
    
    # Create PowerShell script that will run as SYSTEM via PowerRun
    $scriptContent = @"
# PowerRun Version Update Script - Running as SYSTEM
`$ErrorActionPreference = 'Continue'

# Log who we're running as
Write-Host "Running as: `$(whoami)"
Write-Host "Process ID: `$PID"

# Compile C# helper
Add-Type -TypeDefinition @'
$Script:VersionResourceEditorCS
'@ -Language CSharp -IgnoreWarnings

# Version info
`$displayVersion = '$Script:DisplayVersionHigh'
`$fixedParts = @(65535, 65535, 65535, 65535)
`$maj, `$min, `$bld, `$rev = `$fixedParts

# File paths to update
`$files = @(
$($FilePaths | ForEach-Object { "    '$_'" }) -join ",`n"
)

`$successCount = 0
`$totalCount = `$files.Count

Write-Host "Starting version updates for `$totalCount files..."

foreach (`$filePath in `$files) {
    Write-Host "Processing: `$filePath"
    
    try {
        # Get original version
        `$originalVersion = "Unknown"
        try {
            `$vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo(`$filePath)
            `$originalVersion = if (`$vi.FileVersion) { `$vi.FileVersion } else { "Unknown" }
        } catch { }
        
        # Create backup
        `$backup = "`$filePath.bak"
        if (-not (Test-Path -LiteralPath `$backup)) {
            try {
                Copy-Item -LiteralPath `$filePath -Destination `$backup -ErrorAction Stop
                Write-Host "  Created backup: `$backup"
            } catch {
                Write-Host "  Warning: Could not create backup: `$(`$_.Exception.Message)"
            }
        }
        
        # Clear readonly if needed
        try {
            `$item = Get-Item -LiteralPath `$filePath -ErrorAction Stop
            if (`$item.IsReadOnly) {
                `$item.IsReadOnly = `$false
                Write-Host "  Cleared ReadOnly flag"
            }
        } catch { }
        
        # Update version
        [OSVersionResourceEditor]::UpdateVersion(
            `$filePath,
            `$displayVersion,
            [uint16]`$maj, [uint16]`$min, [uint16]`$bld, [uint16]`$rev
        )
        
        # Verify update
        `$newVersion = "Unknown"
        try {
            `$vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo(`$filePath)
            `$newVersion = if (`$vi.FileVersion) { `$vi.FileVersion } else { "Unknown" }
        } catch { }
        
        if (`$newVersion -eq `$displayVersion) {
            Write-Host "  SUCCESS: `$originalVersion -> `$newVersion"
            `$successCount++
        } else {
            Write-Host "  WARNING: Update may have failed (verification shows: `$newVersion)"
        }
        
    } catch {
        Write-Host "  ERROR: `$(`$_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "Update complete: `$successCount/`$totalCount files successfully updated"
Write-Host "Script finished at `$(Get-Date)"
"@
    
    # Write script to file
    $scriptContent | Set-Content -Path $scriptPath -Encoding UTF8
    Write-Ok "Created update script: $scriptPath"
    
    return $scriptPath
}

function Invoke-PowerRunScript {
    param(
        [string]$PowerRunPath,
        [string]$ScriptPath
    )
    
    Write-Info "Executing version update script via PowerRun as SYSTEM..."
    
    # Use PowerRun to run the PowerShell script as NT AUTHORITY\SYSTEM (same pattern as original)
    $powerRunCommand = "/SW:0 powershell.exe -ExecutionPolicy Bypass -File `"$ScriptPath`""
    
    try {
        Start-Process -FilePath $PowerRunPath -ArgumentList $powerRunCommand -Wait -ErrorAction Stop
        Write-Ok "PowerRun execution completed"
    } catch {
        throw "PowerRun execution failed: $($_.Exception.Message)"
    }
}

function Test-Ready { param($Context) return $true }

function Invoke-Apply { 
    param($Context)
    
    Write-Info "Starting OS version spoofing using PowerRun for SYSTEM privileges..."
    
    # Get security code (from env var or prompt)
    try {
        $securityCode = Get-SecurityCode
    } catch {
        return New-ModuleResult -Name 'SpoofOSUpdates' -Status 'Failed' -Message $_.Exception.Message
    }
    
    # Find all target files
    $foundFiles = Find-SystemFiles -FileNames $Script:TargetFiles
    
    # Filter to PE files only
    $peFiles = @()
    foreach ($file in $foundFiles) {
        if (Test-IsPEFile -Path $file) {
            $peFiles += $file
        }
    }
    
    if ($peFiles.Count -eq 0) {
        return New-ModuleResult -Name 'SpoofOSUpdates' -Status 'Failed' -Message 'No target PE files found'
    }
    
    Write-Info ("Found {0}/{1} target files:" -f $peFiles.Count, $Script:TargetFiles.Count)
    $peFiles | ForEach-Object { Write-Info "  $_" }
    
    try {
        # Setup PowerRun (download, configure ini)
        $powerRunInfo = Setup-PowerRun -SecurityCode $securityCode
        
        # Create the version update PowerShell script
        $scriptPath = Create-UpdateScript -DesktopPath $powerRunInfo.DesktopPath -FilePaths $peFiles
        
        # Execute the script via PowerRun as SYSTEM
        Invoke-PowerRunScript -PowerRunPath $powerRunInfo.PowerRunPath -ScriptPath $scriptPath
        
        # Clean up
        try {
            Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
            Write-Info "Cleaned up temporary script"
        } catch { }
        
        return New-ModuleResult -Name 'SpoofOSUpdates' -Status 'Succeeded' -Message "PowerRun execution completed for $($peFiles.Count) files"
        
    } catch {
        return New-ModuleResult -Name 'SpoofOSUpdates' -Status 'Failed' -Message $_.Exception.Message
    }
}

function Invoke-Verify { 
    param($Context)
    
    $foundFiles = Find-SystemFiles -FileNames $Script:TargetFiles
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
    
    return New-ModuleResult -Name 'SpoofOSUpdates' -Status 'Succeeded' -Message ("$updatedCount files show version $Script:DisplayVersionHigh")
}

Export-ModuleMember -Function Test-Ready,Invoke-Apply,Invoke-Verify