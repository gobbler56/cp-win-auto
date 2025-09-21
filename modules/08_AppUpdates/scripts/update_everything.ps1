<#  
Bulk-SetExeVersion.ps1
Recursively updates version metadata on all .exe files under:
- Program Files
- Program Files (x86)
- ProgramData

Sets both:
  - Fixed/binary version (drives FileMajorPart etc.)
  - String "FileVersion" and "ProductVersion"

Defaults to a safe high version: 65535.65535.65535 (and .65535 for the 4th fixed part),
which is the max 16-bit per-part and satisfies common “greater than” checks.
#>

[CmdletBinding()]
param(
  # Optional alternate roots; if omitted, the 3 standard roots are used.
  [string[]]$Roots,

  # Displayed string version for FileVersion/ProductVersion
  [string]$DisplayVersion = "65535.65535.65535",

  # Four-part fixed version for binary fields (Major.Minor.Build.Revision)
  # If omitted, derives from DisplayVersion and clamps parts to 0..65535.
  [string]$FixedVersion = $null,

  # Extra languages to try when writing the version block (besides 0409).
  [int[]]$ExtraLangs = @(0x0000)  # neutral
)

function Resolve-Roots {
  param([string[]]$r)
  $list = New-Object System.Collections.Generic.List[string]
  if ($r -and $r.Count) { $list.AddRange($r) }
  else {
    foreach ($envName in @('ProgramFiles','ProgramFiles(x86)','ProgramData')) {
      $p = [Environment]::GetEnvironmentVariable($envName)
      if ($p -and (Test-Path -LiteralPath $p)) { $list.Add($p) }
    }
  }
  # De-dup and normalize
  ($list | Sort-Object -Unique)
}

function Get-FourPart {
  param([string]$ver)
  $parts = ($ver -split '\D+') | Where-Object { $_ -ne "" } | Select-Object -First 4
  while ($parts.Count -lt 4) { $parts += "65535" }  # pad up to max by default
  $nums = @()
  foreach ($p in $parts) {
    $n = 0; [void][int]::TryParse($p, [ref]$n)
    if ($n -lt 0) { $n = 0 }
    if ($n -gt 65535) { $n = 65535 }
    $nums += $n
  }
  return ,$nums
}

$fixedParts = if ($FixedVersion) { Get-FourPart $FixedVersion } else { Get-FourPart $DisplayVersion }
$maj,$min,$bld,$rev = $fixedParts

# C# helper (no modern syntax—compatible with older Add-Type compilers)
$cs = @"
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;

public static class VersionResourceEditor
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

    static byte[] BuildVersionBlob(ushort langId,
                                   string displayFileVersion,
                                   string displayProductVersion,
                                   ushort maj, ushort min, ushort bld, ushort rev)
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
            BeginBlock(w, out stLenPos, 0, 1, "040904B0"); // en-US + Unicode cp
            WriteStringKV(w, "FileVersion", displayFileVersion);
            WriteStringKV(w, "ProductVersion", displayProductVersion);
            EndBlock(w, stLenPos);
            EndBlock(w, sfiLenPos);

            long vfiLenPos;
            BeginBlock(w, out vfiLenPos, 0, 0, "VarFileInfo");
            long transLenPos;
            BeginBlock(w, out transLenPos, 4, 0, "Translation");
            WriteWord(w, langId);
            WriteWord(w, 0x04B0); // Unicode codepage
            PadToDword(w);
            EndBlock(w, transLenPos);
            EndBlock(w, vfiLenPos);

            EndBlock(w, rootLenPos);
            return ms.ToArray();
        }
    }

    static void DoUpdate(string filePath, ushort langId, byte[] blob)
    {
        IntPtr h = BeginUpdateResource(filePath, false);
        if (h == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "BeginUpdateResource failed");

        bool ok = UpdateResource(h, (IntPtr)16 /*RT_VERSION*/, (IntPtr)1, langId, blob, (uint)blob.Length);
        if (!ok)
        {
            int err = Marshal.GetLastWin32Error();
            EndUpdateResource(h, true);
            throw new Win32Exception(err, "UpdateResource failed");
        }

        if (!EndUpdateResource(h, false))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "EndUpdateResource failed");
    }

    public static void UpdateVersionForLangs(string filePath, ushort[] langs,
                                             string displayFileVersion, string displayProductVersion,
                                             ushort maj, ushort min, ushort bld, ushort rev)
    {
        foreach (ushort lang in langs)
        {
            byte[] blob = BuildVersionBlob(lang, displayFileVersion, displayProductVersion, maj, min, bld, rev);
            try { DoUpdate(filePath, lang, blob); }
            catch (Win32Exception) { /* try next lang; some langs may not exist */ }
        }
    }
}
"@

# Compile helper once
Add-Type -TypeDefinition $cs -Language CSharp -IgnoreWarnings -ErrorAction Stop

$roots = Resolve-Roots -r $Roots
if (-not $roots -or $roots.Count -eq 0) { throw "No roots to scan." }

Write-Host "Scanning roots:" -ForegroundColor Cyan
$roots | ForEach-Object { Write-Host "  $_" }

# Build language list: US-English first, then extras (e.g., neutral 0x0000)
$languages = New-Object System.Collections.Generic.List[uint16]
$languages.Add(0x0409)
foreach ($l in $ExtraLangs) {
  if ($l -lt 0) { continue }
  $languages.Add([uint16]$l)
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($root in $roots) {
  if (-not (Test-Path -LiteralPath $root)) { continue }

  # Use -Filter for speed; skip reparse points to avoid junction loops
  try {
    Get-ChildItem -LiteralPath $root -Recurse -File -Filter *.exe -Force -ErrorAction SilentlyContinue |
      Where-Object { -not $_.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) } |
      ForEach-Object {
        $p = $_.FullName

        # Quick 'MZ' check
        $isPE = $false
        try {
          $fs = [System.IO.File]::Open($p, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
          try {
            $br = New-Object System.IO.BinaryReader($fs)
            $isPE = ($br.ReadUInt16() -eq 0x5A4D)
          } finally { $fs.Close() }
        } catch { $isPE = $false }

        if (-not $isPE) {
          $results.Add([pscustomobject]@{ Path=$p; Updated=$false; Reason="Not PE" })
          return
        }

        # Make backup if not present
        $backup = "$p.bak"
        try {
          if (-not (Test-Path -LiteralPath $backup)) {
            Copy-Item -LiteralPath $p -Destination $backup -ErrorAction Stop
          }
        } catch {
          $results.Add([pscustomobject]@{ Path=$p; Updated=$false; Reason="Backup failed: $($_.Exception.Message)" })
          return
        }

        # Clear ReadOnly if needed
        try {
          $item = Get-Item -LiteralPath $p -ErrorAction Stop
          if ($item.IsReadOnly) {
            $item.IsReadOnly = $false
          }
        } catch { }

        # Attempt update (try multiple language IDs for robustness)
        try {
          [VersionResourceEditor]::UpdateVersionForLangs(
            $p,
            $languages.ToArray(),
            $DisplayVersion,
            $DisplayVersion,
            [uint16]$maj, [uint16]$min, [uint16]$bld, [uint16]$rev
          )

          # Verify numerics after write
          $vi = $null
          try { $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($p) } catch { }
          $majAfter = if ($vi) { $vi.FileMajorPart } else { $null }

          $results.Add([pscustomobject]@{
            Path   = $p
            Updated= $true
            FileVersionString = if ($vi) { $vi.FileVersion } else { $null }
            ProductVersionString = if ($vi) { $vi.ProductVersion } else { $null }
            FileVersionMajorAfter = $majAfter
            Backup = $backup
          })
        } catch {
          $results.Add([pscustomobject]@{ Path=$p; Updated=$false; Reason="Update failed: $($_.Exception.Message)"; Backup=$backup })
        }
      }
  } catch {
    $results.Add([pscustomobject]@{ Path=$root; Updated=$false; Reason="Scan error: $($_.Exception.Message)" })
  }
}

# Summary
$ok = $results | Where-Object { $_.Updated } | Measure-Object | Select-Object -ExpandProperty Count
$fail = $results.Count - $ok
Write-Host ("Done. Updated: {0}, Failed/Skipped: {1}" -f $ok, $fail) -ForegroundColor Green

# Emit a small table to console
$results |
  Select-Object Path, Updated, FileVersionMajorAfter, FileVersionString, ProductVersionString, Reason |
  Format-Table -AutoSize

# Save a CSV log beside the script
$logPath = Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath ("BulkSetExeVersion_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))
$results | Export-Csv -Path $logPath -NoTypeInformation -Encoding UTF8
Write-Host "Log: $logPath"
