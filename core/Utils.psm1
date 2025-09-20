Set-StrictMode -Version Latest

function Write-Info { param([string]$Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "[OK] $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "[!!] $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "[xx] $Msg" -ForegroundColor Red }

function Import-Json { param([string]$Path)
  if (-not (Test-Path $Path)) { return $null }
  Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}
function Save-Json { param([Parameter(Mandatory)][object]$Object, [Parameter(Mandatory)][string]$Path)
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
  ($Object | ConvertTo-Json -Depth 6) | Out-File -LiteralPath $Path -Encoding utf8
}

# ---------- HTML/text helpers ----------
function ConvertFrom-HtmlEntities { param([string]$s) return [System.Net.WebUtility]::HtmlDecode($s) }
function Get-TextBetween {
  param([string]$Text,[string]$Start,[string]$End)
  $m = [regex]::Match($Text,[regex]::Escape($Start) + '(.*?)' + [regex]::Escape($End), 'Singleline,IgnoreCase')
  if ($m.Success) { return $m.Groups[1].Value } else { return $null }
}

# ---------- Local account helpers ----------
function Get-BuiltinAdministratorName {
  try {
    $acc = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
      Where-Object { $_.SID -like '*-500' } | Select-Object -First 1
    if ($acc) { return $acc.Name }
  } catch {}
  return 'Administrator'
}
function Get-DefaultLocalAccounts {
  $builtinAdmin = Get-BuiltinAdministratorName
  @('Guest','DefaultAccount','WDAGUtilityAccount',$builtinAdmin)
}
function Get-LocalUserNames {
  param([switch]$ExcludeDefaults)
  $users = Get-LocalUser -ErrorAction SilentlyContinue
  if (-not $users) { return @() }
  $names = $users | Select-Object -ExpandProperty Name
  if ($ExcludeDefaults) { $defaults = Get-DefaultLocalAccounts; $names = $names | Where-Object { $defaults -notcontains $_ } }
  $names
}
function To-SecureString { param([string]$s) ConvertTo-SecureString $s -AsPlainText -Force }
function New-RandomPassword {
  param([int]$Length = 20)
  $lc='abcdefghijkmnopqrstuvwxyz';$uc='ABCDEFGHJKLMNPQRSTUVWXYZ';$dg='23456789';$sc='!@#$%^&*()-_=+[]{}:,.?'
  $pick = { param($s,$n) -join (1..$n | ForEach-Object { $s[(Get-Random -Max $s.Length)] }) }
  $base = @($pick.Invoke($lc,1),$pick.Invoke($uc,1),$pick.Invoke($dg,1),$pick.Invoke($sc,1),$pick.Invoke($lc+$uc+$dg+$sc,$Length-4)) -join ''
  -join ($base.ToCharArray() | Sort-Object {Get-Random})
}
function Ensure-LocalUserExists {
  param([Parameter(Mandatory)][string]$Name,[SecureString]$Password,[switch]$CreateIfMissing)
  $u = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
  if (-not $u -and $CreateIfMissing) {
    if (-not $Password) { $Password = To-SecureString (New-RandomPassword) }
    try { New-LocalUser -Name $Name -Password $Password -FullName $Name -PasswordNeverExpires:$false -UserMayNotChangePassword:$false -AccountNeverExpires:$false -ErrorAction Stop | Out-Null }
    catch { & net user $Name ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))) /add /y | Out-Null }
    $u = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
  }
  return $u
}
function Set-LocalUserPassword {
  param([Parameter(Mandatory)][string]$Name,[SecureString]$Password)
  if (-not $Password) { $Password = To-SecureString (New-RandomPassword) }
  try { Set-LocalUser -Name $Name -Password $Password -ErrorAction Stop }
  catch { & net user $Name ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))) | Out-Null }
}
function Enable-LocalUserSafe { param([string]$Name) try { Enable-LocalUser -Name $Name -ErrorAction Stop } catch { & net user $Name /active:yes | Out-Null } }
function Disable-LocalUserSafe { param([string]$Name) try { Disable-LocalUser -Name $Name -ErrorAction Stop } catch { & net user $Name /active:no  | Out-Null } }
function Remove-LocalUserSafe { param([string]$Name) try { Remove-LocalUser -Name $Name -ErrorAction Stop } catch { & net user $Name /delete | Out-Null } }
function Set-LocalPasswordExpires {
  param([Parameter(Mandatory)][string]$Name,[bool]$Expires)
  $ok=$false;$dom=$env:COMPUTERNAME;$flag=if($Expires){"TRUE"}else{"FALSE"}
  try { $out = & wmic useraccount where "name='$Name' and domain='$dom'" set PasswordExpires=$flag 2>$null; if ($LASTEXITCODE -eq 0 -and ($out -join '') -match 'updated') { $ok=$true } } catch {}
  if (-not $ok) {
    try { $adsi=[ADSI]"WinNT://./$Name,user"; $UF_DONT_EXPIRE_PASSWD=0x10000; $flags=[int]$adsi.UserFlags;
      if ($Expires) { $flags = $flags -band (-bnot $UF_DONT_EXPIRE_PASSWD) } else { $flags = $flags -bor $UF_DONT_EXPIRE_PASSWD }
      $adsi.UserFlags=$flags; $adsi.SetInfo(); $ok=$true } catch {}
  }
  return $ok
}
function Set-LocalUserCanChangePassword { param([Parameter(Mandatory)][string]$Name,[bool]$CanChange)
  try { & net user $Name /passwordchg:$(if($CanChange){'yes'}else{'no'}) | Out-Null; return $true } catch { return $false }
}
function Test-LocalGroupMember {
  param([Parameter(Mandatory)][string]$Group,[Parameter(Mandatory)][string]$User)
  try { $members = Get-LocalGroupMember -Group $Group -ErrorAction Stop; return $members | Where-Object { $_.ObjectClass -eq 'User' -and $_.Name -match ("\\$([regex]::Escape($User))$") } | ForEach-Object { $true } | Select-Object -First 1 }
  catch { return $false }
}
function Add-UserToLocalGroupSafe {
  param([Parameter(Mandatory)][string]$Group,[Parameter(Mandatory)][string]$User)
  if (-not (Get-LocalGroup -Name $Group -ErrorAction SilentlyContinue)) { New-LocalGroup -Name $Group -ErrorAction SilentlyContinue | Out-Null }
  if (-not (Test-LocalGroupMember -Group $Group -User $User)) { try { Add-LocalGroupMember -Group $Group -Member $User -ErrorAction Stop | Out-Null } catch {} }
}
function Remove-UserFromLocalGroupSafe { param([Parameter(Mandatory)][string]$Group,[Parameter(Mandatory)][string]$User)
  if (Test-LocalGroupMember -Group $Group -User $User) { try { Remove-LocalGroupMember -Group $Group -Member $User -ErrorAction Stop | Out-Null } catch {} }
}

# Detect primary auto-logon user so we can avoid rotating its password (CP guidance)
function Get-AutoLogonUser {
  try {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $p = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if ($p -and $p.AutoAdminLogon -eq '1' -and $p.DefaultUserName) { return [string]$p.DefaultUserName }
  } catch {}
  return $null
}

Export-ModuleMember -Function `
  Write-Info,Write-Ok,Write-Warn,Write-Err,Import-Json,Save-Json,ConvertFrom-HtmlEntities,Get-TextBetween, `
  Get-BuiltinAdministratorName,Get-DefaultLocalAccounts,Get-LocalUserNames,To-SecureString,New-RandomPassword, `
  Ensure-LocalUserExists,Set-LocalUserPassword,Enable-LocalUserSafe,Disable-LocalUserSafe,Remove-LocalUserSafe, `
  Set-LocalPasswordExpires,Set-LocalUserCanChangePassword,Test-LocalGroupMember,Add-UserToLocalGroupSafe,Remove-UserFromLocalGroupSafe, `
  Get-AutoLogonUser
