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

function Find-RecentHireMentions {
  param(
    [string]$PlainText,
    [System.Collections.Generic.HashSet[string]]$TerminatedSet = $(New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase))
  )

  $results = @()
  if (-not $PlainText) { return $results }

  if (-not $TerminatedSet) {
    $TerminatedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  }

  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $sentences = [regex]::Split($PlainText, '(?<=[\.\?\!])\s+|\r?\n+')
  foreach ($sentence in $sentences) {
    $s = ($sentence -as [string]).Trim()
    if (-not $s) { continue }
    if ($s -notmatch '(?i)\b(create|make|add|set\s*up|setup)\b') { continue }
    if ($s -notmatch '(?i)\b(user|account)\b') { continue }

    $name = $null
    if ($s -match '(?i)\b(?:named|called|name(?:d)?\s+(?:as|for|after)?)\s+[""''“”]?([A-Za-z0-9._-]+)[""''“”]?') {
      $name = $matches[1]
    } elseif ($s -match '(?i)\buser\s+[""''“”]?([A-Za-z0-9._-]+)[""''“”]?') {
      $name = $matches[1]
    } elseif ($s -match '(?i)\baccount\s+[""''“”]?([A-Za-z0-9._-]+)[""''“”]?') {
      $name = $matches[1]
    }

    if (-not $name) { continue }
    $name = $name.Trim('"', '\'', "“", "”")
    if (-not $name) { continue }
    if ($name -match '^(?:user|account|employee|admin|administrator)$') { continue }
    if ($TerminatedSet.Contains($name)) { continue }

    if ($seen.Add($name)) {
      $accountType = 'standard'
      if ($s -match '(?i)\badmin(?:istrator)?\b') {
        $accountType = 'admin'
      } elseif ($s -match '(?i)\bstandard\b') {
        $accountType = 'standard'
      }

      $results += [pscustomobject]@{
        Name        = $name
        AccountType = $accountType
        Groups      = @()
      }
    }
  }

  return $results
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
      Directives       = [pscustomobject]@{
        GroupsToCreate            = @()
        GroupMembersToAdd         = @{}
        UsersToCreate             = @()
        TerminatedUsers           = @()
        CriticalServices          = @()
        UnauthorizedUsersExplicit = @()
        EnsureGuestDisabled       = $true
        EnsureAdministratorDisabled = $true
      }
      SourcePath       = $null
      RawHtml          = ""
      PlainText        = ""
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
        $terminatedRaw = @($doc.terminated_users) | Where-Object { $_ }
        $terminatedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $terminated = @()
        foreach ($t in $terminatedRaw) {
          $name = ($t -as [string]).Trim()
          if ($name) {
            if ($terminatedSet.Add($name)) { $terminated += $name }
          }
        }
        foreach ($u in $doc.all_users) {
          if (-not $u.name) { continue }
          if ($terminatedSet.Contains($u.name)) { continue }
          $users += $u.name
          if ($u.account_type -eq 'admin') { $admins += $u.name }
          if ($u.groups) {
            foreach ($g in $u.groups) {
              if (-not $groups.ContainsKey($g)) { $groups[$g] = @() }
              $groups[$g] += $u.name
            }
          }
        }

        $recent = @()
        foreach ($entry in @($doc.recent_hires)) {
          if (-not $entry.name) { continue }
          if ($terminatedSet.Contains($entry.name)) { continue }
          $recent += [pscustomobject]@{
            Name        = $entry.name
            AccountType = $entry.account_type
            Groups      = @($entry.groups)
          }
          $users += $entry.name
          if ($entry.account_type -eq 'admin') { $admins += $entry.name }
          if ($entry.groups) {
            foreach ($g in $entry.groups) {
              if (-not $groups.ContainsKey($g)) { $groups[$g] = @() }
              $groups[$g] += $entry.name
            }
          }
        }

        foreach ($entry in (Find-RecentHireMentions -PlainText $plainText -TerminatedSet $terminatedSet)) {
          if (-not $entry.Name) { continue }
          if (-not ($recent | Where-Object { $_.Name -eq $entry.Name })) {
            $recent += [pscustomobject]@{
              Name        = $entry.Name
              AccountType = $entry.AccountType
              Groups      = @($entry.Groups)
            }
          }
          $users += $entry.Name
          if ($entry.AccountType -eq 'admin') { $admins += $entry.Name }
        }

        $directives = [ordered]@{
          GroupsToCreate            = @($groups.Keys | Select-Object -Unique)
          GroupMembersToAdd         = @{}
          UsersToCreate             = @($recent)
          TerminatedUsers           = @($terminated)
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
          RawHtml          = $rawHtml
          PlainText        = $plainText
        }
      }
    } catch {
      Write-Warn ("OpenRouter parse failed: {0}" -f $_.Exception.Message)
    }
  }

  # Fallback: empty structure
  $heuristicRecent = Find-RecentHireMentions -PlainText $plainText
  $heuristicUsers  = @()
  $heuristicAdmins = @()
  foreach ($entry in $heuristicRecent) {
    if ($entry.Name) {
      $heuristicUsers += $entry.Name
      if ($entry.AccountType -eq 'admin') { $heuristicAdmins += $entry.Name }
    }
  }

  return [pscustomobject]@{
    AuthorizedUsers  = @($heuristicUsers | Select-Object -Unique)
    AuthorizedAdmins = @($heuristicAdmins | Select-Object -Unique)
    Notes            = @()
    Directives       = [pscustomobject]@{
      GroupsToCreate            = @()
      GroupMembersToAdd         = @{}
      UsersToCreate             = @($heuristicRecent)
      TerminatedUsers           = @()
      CriticalServices          = @()
      UnauthorizedUsersExplicit = @()
      EnsureGuestDisabled       = $true
      EnsureAdministratorDisabled = $true
    }
    SourcePath       = $fetch.Url
    RawHtml          = $rawHtml
    PlainText        = $plainText
  }
}

Export-ModuleMember -Function Get-ReadmeInfo
