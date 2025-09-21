Set-StrictMode -Version Latest

# Import required modules if not already loaded
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot 'Utils.psm1')
}
Import-Module "$PSScriptRoot/NLP.OpenRouter.psm1" -ErrorAction SilentlyContinue

function Remove-HTMLTags {
  param([string]$content)
  if (-not $content) { return "" }
  $content = [regex]::Replace($content, "<head.*?>.*?</head>", "", [System.Text.RegularExpressions.RegexOptions]::Singleline)
  $content = [regex]::Replace($content, "<script.*?>.*?</script>", "", [System.Text.RegularExpressions.RegexOptions]::Singleline)
  $content = [regex]::Replace($content, "<style.*?>.*?</style>", "", [System.Text.RegularExpressions.RegexOptions]::Singleline)
  $content = [regex]::Replace($content, "<.*?>", "")
  $content = $content -replace "\s+", " "
  return $content.Trim()
}

function Get-ReadmeHtmlFromUrlFile {
  param([string[]]$Candidates = @(
    "C:\CyberPatriot\README.url",
    "$env:PUBLIC\Desktop\README.url",
    "$env:USERPROFILE\Desktop\README.url"
  ))

  foreach ($p in $Candidates) {
    if (Test-Path $p) {
      $urlLine = Get-Content -LiteralPath $p | Where-Object { $_ -match '^\s*URL=(.+)$' } | Select-Object -First 1
      if ($urlLine) {
        $url = ($urlLine -replace '^\s*URL=','').Trim()
        if ($url) {
          try {
            $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
            return [pscustomobject]@{ Url=$url; Html=$resp.Content }
          } catch {
            throw ("Failed to download README from {0}: {1}" -f $url, $_.Exception.Message)
          }
        }
      }
      throw ("README.url found but URL= line missing in {0}" -f $p)
    }
  }
  throw "No README.url file found in default locations."
}

function Get-ReadmeInfo {
  param([string]$Root = $PSScriptRoot)

  try {
    $fetch = Get-ReadmeHtmlFromUrlFile
  } catch {
    # If README isn't present, return an empty structure so modules can still run.
    return [pscustomobject]@{
      AuthorizedUsers  = @()
      AuthorizedAdmins = @()
      Notes            = @()
      Directives       = [pscustomobject]@{ GroupsToCreate=@(); GroupMembersToAdd=@{}; UsersToCreate=@(); CriticalServices=@() }
      SourcePath       = $null
    }
  }

  $rawHtml   = $fetch.Html
  $plainText = Remove-HTMLTags -content $rawHtml

  # Use OpenRouter extraction if available; else return minimal
  if (Get-Command Invoke-ReadmeExtraction -ErrorAction SilentlyContinue) {
    try {
      $doc = Invoke-ReadmeExtraction -RawHtml $rawHtml -PlainText $plainText
      if ($doc) {
        $admins = @()
        $users  = @()
        $groups = @{}
        foreach ($u in $doc.all_users) {
          $users += $u.name
          if ($u.account_type -eq 'admin') { $admins += $u.name }
          if ($u.groups) {
            foreach ($g in $u.groups) {
              if (-not $groups.ContainsKey($g)) { $groups[$g] = @() }
              $groups[$g] += $u.name
            }
          }
        }
        $directives = [ordered]@{
          GroupsToCreate            = @($groups.Keys | Select-Object -Unique)
          GroupMembersToAdd         = @{} 
          UsersToCreate             = @()
          TerminatedUsers           = @()
          UnauthorizedUsersExplicit = @()
          EnsureGuestDisabled       = $true
          EnsureAdministratorDisabled = $true
          CriticalServices          = @($doc.critical_services)
        }
        foreach ($k in $groups.Keys) { $directives.GroupMembersToAdd[$k] = @($groups[$k] | Select-Object -Unique) }
        return [pscustomobject]@{
          AuthorizedUsers  = @($users | Select-Object -Unique)
          AuthorizedAdmins = @($admins | Select-Object -Unique)
          Notes            = @()
          Directives       = [pscustomobject]$directives
          SourcePath       = $fetch.Url
        }
      }
    } catch {
      Write-Warn ("OpenRouter parse failed: {0}" -f $_.Exception.Message)
    }
  }

  # Fallback: empty structure
  return [pscustomobject]@{
    AuthorizedUsers  = @()
    AuthorizedAdmins = @()
    Notes            = @()
    Directives       = [pscustomobject]@{ GroupsToCreate=@(); GroupMembersToAdd=@{}; UsersToCreate=@(); CriticalServices=@() }
    SourcePath       = $fetch.Url
  }
}

Export-ModuleMember -Function Get-ReadmeInfo
