# Readme.Parser.psm1
# Requires: Windows PowerShell 5.1+ or PowerShell 7+
# Purpose : Parse CyberPatriot README.url target into a structured object the engine can consume.

# Ensure modern behavior and catch uninitialized vars early
#requires -Version 5.1
Set-StrictMode -Version Latest

# --- Optional utilities -------------------------------------------------------
# Load Utils.psm1 (for Write-Info etc.) only if not already available
if (-not (Get-Command Write-Info -ErrorAction SilentlyContinue)) {
    $utilsPath = Join-Path $PSScriptRoot 'Utils.psm1'
    if (Test-Path -LiteralPath $utilsPath) {
        Import-Module -Force -DisableNameChecking $utilsPath
    }
}

# Load optional OpenRouter helper module (defines Invoke-ReadmeExtraction)
$nlpPath = Join-Path $PSScriptRoot 'NLP.OpenRouter.psm1'
if (Test-Path -LiteralPath $nlpPath) {
    Import-Module -ErrorAction SilentlyContinue $nlpPath
}

# If Write-Info isn't available, provide a lightweight fallback
if (-not (Get-Command Write-Info -ErrorAction SilentlyContinue)) {
    function Write-Info { param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Message) Write-Verbose ($Message -join ' ') }
}

# --- Helpers ------------------------------------------------------------------
function Remove-HTMLTags {
    <#
    .SYNOPSIS
        Strip HTML, <script>, <style>, and compress whitespace (case-insensitive).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Content
    )
    if (-not $Content) { return "" }

    # Case-insensitive & single-line replacements
    $opts = [System.Text.RegularExpressions.RegexOptions]::Singleline -bor `
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase

    $c = [regex]::Replace($Content, "<head.*?>.*?</head>", "", $opts)
    $c = [regex]::Replace($c,     "<script.*?>.*?</script>", "", $opts)
    $c = [regex]::Replace($c,     "<style.*?>.*?</style>",   "", $opts)
    $c = [regex]::Replace($c,     "<.*?>",                   "", $opts)

    # Normalize whitespace
    $c = $c -replace "\s+", " "
    return $c.Trim()
}

function Find-RecentHireMentions {
    <#
    .SYNOPSIS
        Heuristically detect mentions like "create/add/setup user <name>"
        and infer account type (admin vs standard).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PlainText,
        [System.Collections.Generic.HashSet[string]]$TerminatedSet
    )

    $results = @()
    if (-not $PlainText) { return $results }

    if (-not $TerminatedSet) {
        $TerminatedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    }

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    # Split by sentence-ish boundaries
    $sentences = [regex]::Split($PlainText, '(?<=[\.\?\!])\s+|\r?\n+')
    foreach ($sentence in $sentences) {
        $s = ($sentence -as [string]).Trim()
        if (-not $s) { continue }

        # Require verbs + the notion of a user/account creation
        if ($s -notmatch '(?i)\b(create|make|add|set\s*up|setup)\b') { continue }
        if ($s -notmatch '(?i)\b(user|account)\b') { continue }

        # Names: allow typical username charset (letters, digits, . _ -)
        $name = $null
        if     ($s -match '(?i)\b(?:named|called|name(?:d)?(?:\s+(?:as|for|after))?)\s+["''“”]?([A-Za-z0-9._-]+)["''“”]?') { $name = $matches[1] }
        elseif ($s -match '(?i)\buser\s+["''“”]?([A-Za-z0-9._-]+)["''“”]?')                                            { $name = $matches[1] }
        elseif ($s -match '(?i)\baccount\s+["''“”]?([A-Za-z0-9._-]+)["''“”]?')                                         { $name = $matches[1] }

        if (-not $name) { continue }

        # Correctly trim quotes (avoid trimming backslashes!)
        $name = $name.Trim('"', '''', '“', '”')
        if (-not $name) { continue }

        # Filter generic tokens
        if ($name -match '^(?:user|account|employee|admin|administrator)$') { continue }
        if ($TerminatedSet.Contains($name)) { continue }

        if ($seen.Add($name)) {
            $accountType = if ($s -match '(?i)\badmin(?:istrator)?\b') { 'admin' } else { 'standard' }
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
    <#
    .SYNOPSIS
        Locate README.url and download its target HTML.
    .OUTPUTS
        PSCustomObject { Url, Html }
    .NOTES
        Searches common locations in priority order.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Candidates = @(
            'C:\CyberPatriot\README.url',
            (Join-Path $env:PUBLIC     'Desktop\README.url'),
            (Join-Path $env:USERPROFILE 'Desktop\README.url')
        )
    )

    foreach ($p in $Candidates) {
        if (-not (Test-Path -LiteralPath $p)) { continue }

        $line = Get-Content -LiteralPath $p -ErrorAction Stop |
                Where-Object { $_ -match '^\s*URL\s*=(.+)$' } |
                Select-Object -First 1

        if (-not $line) {
            throw ("README.url found but no 'URL=' line in {0}" -f $p)
        }

        $url = ($line -replace '^\s*URL\s*=', '').Trim()
        if (-not $url) {
            throw ("README.url found but URL is empty in {0}" -f $p)
        }

        try {
            # UseBasicParsing is harmless on 5.1 and ignored on 7+
            $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
            return [pscustomobject]@{ Url = $url; Html = $resp.Content }
        }
        catch {
            throw ("Failed to download README from {0}: {1}" -f $url, $_.Exception.Message)
        }
    }

    throw "No README.url file found in default locations."
}

function Get-ReadmeInfo {
    <#
    .SYNOPSIS
        Parse README target into a structured object for the engine.
    .OUTPUTS
        PSCustomObject with:
            AuthorizedUsers, AuthorizedAdmins, Notes, Directives, SourcePath, RawHtml, PlainText
    #>
    [CmdletBinding()]
    [Alias('Get-Readme')]
    param(
        [string]$Root = $PSScriptRoot
    )

    # ------------------ Fetch README HTML ------------------
    try {
        $fetch = Get-ReadmeHtmlFromUrlFile
    }
    catch {
        # README not present or fetch failed: return empty structure so the rest of the pipeline can still run
        Write-Info "[Readme] No README available or failed to fetch. Returning empty directives."
        return [pscustomobject]@{
            AuthorizedUsers  = @()
            AuthorizedAdmins = @()
            Notes            = @()
            Directives       = [pscustomobject]@{
                GroupsToCreate              = @()
                GroupMembersToAdd           = @{}
                UsersToCreate               = @()
                TerminatedUsers             = @()
                CriticalServices            = @()
                UnauthorizedUsersExplicit   = @()
                EnsureGuestDisabled         = $true
                EnsureAdministratorDisabled = $true
            }
            SourcePath = $null
            RawHtml    = ""
            PlainText  = ""
        }
    }

    $rawHtml   = $fetch.Html
    $plainText = Remove-HTMLTags -Content $rawHtml

    # ------------------ LLM-Assisted Parse (optional) ------------------
    if (Get-Command Invoke-ReadmeExtraction -ErrorAction SilentlyContinue) {
        try {
            $doc = Invoke-ReadmeExtraction -RawHtml $rawHtml -PlainText $plainText

            if ($doc) {
                $admins        = @()
                $users         = @()
                $groups        = @{}
                $recent        = @()
                $terminatedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                $terminated    = @()

                foreach ($t in @($doc.terminated_users) | Where-Object { $_ }) {
                    $n = ($t -as [string]).Trim()
                    if ($n -and $terminatedSet.Add($n)) { $terminated += $n }
                }

                foreach ($u in @($doc.all_users)) {
                    if (-not $u.name) { continue }
                    if ($terminatedSet.Contains($u.name)) { continue }

                    $users += $u.name
                    if ($u.account_type -eq 'admin') { $admins += $u.name }

                    foreach ($g in @($u.groups)) {
                        if (-not $g) { continue }
                        if (-not $groups.ContainsKey($g)) { $groups[$g] = @() }
                        $groups[$g] += $u.name
                    }
                }

                foreach ($entry in @($doc.recent_hires)) {
                    if (-not $entry.name) { continue }
                    if ($terminatedSet.Contains($entry.name)) { continue }

                    $recent += [pscustomobject]@{
                        Name        = $entry.name
                        AccountType = $entry.account_type
                        Groups      = @($entry.groups)
                    }

                    $users  += $entry.name
                    if ($entry.account_type -eq 'admin') { $admins += $entry.name }

                    foreach ($g in @($entry.groups)) {
                        if (-not $g) { continue }
                        if (-not $groups.ContainsKey($g)) { $groups[$g] = @() }
                        $groups[$g] += $entry.name
                    }
                }

                # Also run heuristics over plaintext to catch stragglers
                foreach ($h in (Find-RecentHireMentions -PlainText $plainText -TerminatedSet $terminatedSet)) {
                    if (-not $h.Name) { continue }
                    if (-not ($recent | Where-Object { $_.Name -eq $h.Name })) {
                        $recent += [pscustomobject]@{
                            Name        = $h.Name
                            AccountType = $h.AccountType
                            Groups      = @($h.Groups)
                        }
                    }
                    $users += $h.Name
                    if ($h.AccountType -eq 'admin') { $admins += $h.Name }
                }

                $directives = [ordered]@{
                    GroupsToCreate              = @($groups.Keys | Select-Object -Unique)
                    GroupMembersToAdd           = @{}
                    UsersToCreate               = @($recent)
                    TerminatedUsers             = @($terminated)
                    UnauthorizedUsersExplicit   = @()
                    EnsureGuestDisabled         = $true
                    EnsureAdministratorDisabled = $true
                    CriticalServices            = @($doc.critical_services)
                }
                foreach ($k in $groups.Keys) {
                    $directives.GroupMembersToAdd[$k] = @($groups[$k] | Select-Object -Unique)
                }

                return [pscustomobject]@{
                    AuthorizedUsers  = @($users  | Select-Object -Unique)
                    AuthorizedAdmins = @($admins | Select-Object -Unique)
                    Notes            = @()
                    Directives       = [pscustomobject]$directives
                    SourcePath       = $fetch.Url
                    RawHtml          = $rawHtml
                    PlainText        = $plainText
                }
            }
        }
        catch {
            Write-Warning ("OpenRouter parse failed: {0}" -f $_.Exception.Message)
        }
    }

    # ------------------ Heuristic Fallback ------------------
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
        AuthorizedUsers  = @($heuristicUsers  | Select-Object -Unique)
        AuthorizedAdmins = @($heuristicAdmins | Select-Object -Unique)
        Notes            = @()
        Directives       = [pscustomobject]@{
            GroupsToCreate              = @()
            GroupMembersToAdd           = @{}
            UsersToCreate               = @($heuristicRecent)
            TerminatedUsers             = @()
            CriticalServices            = @()
            UnauthorizedUsersExplicit   = @()
            EnsureGuestDisabled         = $true
            EnsureAdministratorDisabled = $true
        }
        SourcePath = $fetch.Url
        RawHtml    = $rawHtml
        PlainText  = $plainText
    }
}

# --- Export / Promote ---------------------------------------------------------
# If we are running as a module, export members.
# If this file gets executed as a script, also promote the key functions to global scope
# so callers like Run.ps1 can still invoke Get-ReadmeInfo.
$publicFunctions = @(
    'Get-ReadmeInfo',
    'Remove-HTMLTags',
    'Find-RecentHireMentions',
    'Get-ReadmeHtmlFromUrlFile'
)

if ($PSModuleName) {
    Export-ModuleMember -Function $publicFunctions -Alias Get-Readme
}
else {
    foreach ($fn in $publicFunctions) {
        $src = Get-Item ("function:{0}" -f $fn) -ErrorAction SilentlyContinue
        if ($src) {
            Set-Item -Path ("function:global:{0}" -f $fn) -Value $src.ScriptBlock -ErrorAction SilentlyContinue
        }
    }
    # Also expose alias in script execution scenario
    if (-not (Get-Alias Get-Readme -ErrorAction SilentlyContinue)) {
        Set-Alias -Name Get-Readme -Value Get-ReadmeInfo -Scope Global
    }
}
