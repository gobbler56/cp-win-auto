Set-StrictMode -Version Latest
. $PSScriptRoot/Utils.psm1
Import-Module "$PSScriptRoot/NLP.OpenRouter.psm1" -Force

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
            throw "Failed to download README from $url: $($_.Exception.Message)"
          }
        }
      }
      throw "README.url found but URL= line missing in $p"
    }
  }
  throw "No README.url file found in default locations."
}

function Get-ReadmeInfo {
  param([string]$Root = $PSScriptRoot)

  $fetch = Get-ReadmeHtmlFromUrlFile
  $rawHtml   = $fetch.Html
  $plainText = Remove-HTMLTags -content $rawHtml

  $doc = Invoke-ReadmeExtraction -RawHtml $rawHtml -PlainText $plainText
  if (-not $doc) { throw "Model returned no data." }

  # Normalize to engine shape
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

  # Build directives the module will consume
  $directives = [ordered]@{
    GroupsToCreate            = @($groups.Keys | Select-Object -Unique)
    GroupMembersToAdd         = @{}
    UsersToCreate             = @()   # we don't “guess” new vs existing; module will create if missing anyway
    TerminatedUsers           = @()
    UnauthorizedUsersExplicit = @()
    EnsureGuestDisabled       = $true
    EnsureAdministratorDisabled = $true
    CriticalServices          = @($doc.critical_services)
  }
  foreach ($k in $groups.Keys) {
    $directives.GroupMembersToAdd[$k] = @($groups[$k] | Select-Object -Unique)
  }

  return [pscustomobject]@{
    AuthorizedUsers  = @($users | Select-Object -Unique)
    AuthorizedAdmins = @($admins | Select-Object -Unique)
    Notes            = @()
    Directives       = [pscustomobject]$directives
    SourcePath       = $fetch.Url
  }
}

Export-ModuleMember -Function Get-ReadmeInfo
