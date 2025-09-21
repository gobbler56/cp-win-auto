param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$Path,

  # What you want shown in Properties -> Details (both FileVersion & ProductVersion)
  [string]$DisplayVersion = "65535.65535.65535",

  # Optional fixed/binary 4-part version; if omitted we derive & clamp from DisplayVersion
  [string]$FixedVersion = $null,

  # Language ID for the version resource (default: en-US)
  [int]$LangId = 0x0409
)

if (!(Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }

# Basic PE sanity check
$fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
try {
  $br = New-Object System.IO.BinaryReader($fs)
  if ($br.ReadUInt16() -ne 0x5A4D) { throw "Not a PE (EXE/DLL) file: $Path" }
} finally { $fs.Close() }

# Backup once
$backup = "$Path.bak"
if (-not (Test-Path -LiteralPath $backup)) {
  Copy-Item -LiteralPath $Path -Destination $backup -ErrorAction Stop
}

function Get-FourPart {
  param([string]$ver)
  $parts = ($ver -split '\D+') | Where-Object { $_ -ne "" } | Select-Object -First 4
  while ($parts.Count -lt 4) { $parts += "0" }
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
        WriteWord(w, 0);                 // wLength (patched later)
        WriteWord(w, wValueLen);         // wValueLength
        WriteWord(w, wType);             // wType (0=binary, 1=text)
        WriteUnicodeZ(w, key);           // szKey
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
        // wValueLength = number of WCHARs in value including trailing NUL
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

            // StringFileInfo
            long sfiLenPos;
            BeginBlock(w, out sfiLenPos, 0, 1, "StringFileInfo");
            {
                long stLenPos;
                // 0409 (en-US) + 04B0 (Unicode codepage)
                BeginBlock(w, out stLenPos, 0, 1, "040904B0");
                WriteStringKV(w, "FileVersion", displayFileVersion);
                WriteStringKV(w, "ProductVersion", displayProductVersion);
                EndBlock(w, stLenPos);
            }
            EndBlock(w, sfiLenPos);

            // VarFileInfo
            long vfiLenPos;
            BeginBlock(w, out vfiLenPos, 0, 0, "VarFileInfo");
            {
                long transLenPos;
                BeginBlock(w, out transLenPos, 4, 0, "Translation");
                WriteWord(w, langId);
                WriteWord(w, 0x04B0); // Unicode CP
                PadToDword(w);
                EndBlock(w, transLenPos);
            }
            EndBlock(w, vfiLenPos);

            EndBlock(w, rootLenPos);
            return ms.ToArray();
        }
    }

    public static void UpdateVersion(string filePath,
                                     ushort langId,
                                     string displayFileVersion,
                                     string displayProductVersion,
                                     ushort maj, ushort min, ushort bld, ushort rev)
    {
        byte[] blob = BuildVersionBlob(langId, displayFileVersion, displayProductVersion, maj, min, bld, rev);

        IntPtr h = BeginUpdateResource(filePath, false);
        if (h == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "BeginUpdateResource failed");

        bool ok = UpdateResource(h, (IntPtr)RT_VERSION, (IntPtr)1, langId, blob, (uint)blob.Length);
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

try {
  Add-Type -TypeDefinition $cs -Language CSharp -IgnoreWarnings -ErrorAction Stop
  [VersionResourceEditor]::UpdateVersion(
    $Path,
    [uint16]$LangId,
    $DisplayVersion,
    $DisplayVersion,
    [uint16]$maj, [uint16]$min, [uint16]$bld, [uint16]$rev
  )
  Write-Host "SUCCESS: Updated '$Path'"
  Write-Host "   Displayed File/Product version : $DisplayVersion"
  Write-Host "   Fixed (binary) version         : $maj.$min.$bld.$rev"
  Write-Host "   Backup saved to                : $backup"
} catch {
  Write-Error $_
  Write-Host "Restored from backup? Your original is at: $backup"
  exit 1
}
