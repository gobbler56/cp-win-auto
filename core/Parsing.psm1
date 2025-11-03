# Readme.Parser.psm1
# Requires: Windows PowerShell 5.1+ or PowerShell 7+
Set-StrictMode -Version Latest

if (-not (Get-Command Write-Info -ErrorAction SilentlyContinue)) {
    $utilsPath = Join-Path $PSScriptRoot 'Utils.psm1'
    if (Test-Path -LiteralPath $utilsPath) {
        Import-Module -Force -DisableNameChecking $utilsPath
    } else {
        function Write-Info { param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Message) Write-Verbose ($Message -join ' ') }
    }
}

$nlpPath = Join-Path $PSScriptRoot 'NLP.OpenRouter.psm1'
if (Test-Path -LiteralPath $nlpPath) {
    Import-Module -ErrorAction SilentlyContinue $nlpPath
}

function Remove-HTMLTags {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Content)
    if (-not $Content) { return "" }
    $opts = [System.Text.RegularExpressions.RegexOptions]::Singleline -bor `
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $c = [regex]::Replace($Content, "<head.*?>.*?</head>", "", $opts)
    $c = [regex]::Replace($c,     "<script.*?>.*?</script>", "", $opts)
    $c = [regex]::Replace($c,     "<style.*?>.*?</style>",   "", $opts)
    $c = [regex]::Replace($c,     "<.*?>",                   "", $opts)
    $c = $c -replace "\s+", " "
    return $c.Trim()
}

function Get-ReadmeHtmlFromUrlFile {
    [CmdletBinding()]
    param(
        [string]$AeacusReadmePath = 'C:\aeacus\assets\ReadMe.html',
        [string[]]$Candidates = @(
            'C:\CyberPatriot\README.url',
            (Join-Path $env:PUBLIC     'Desktop\README.url'),
            (Join-Path $env:USERPROFILE 'Desktop\README.url')
        )
    )

    # Check for Aeacus practice image README first
    if (Test-Path -LiteralPath $AeacusReadmePath) {
        Write-Info "[Readme] Found Aeacus practice image README at: $AeacusReadmePath"
        try {
            $htmlContent = Get-Content -LiteralPath $AeacusReadmePath -Raw -ErrorAction Stop
            return [pscustomobject]@{
                Url  = "file:///$AeacusReadmePath"
                Html = $htmlContent
            }
        } catch {
            Write-Warning ("Failed to read Aeacus README from {0}: {1}" -f $AeacusReadmePath, $_.Exception.Message)
            # Fall through to CyberPatriot logic
        }
    }

    # Fall back to CyberPatriot competition README logic
    foreach ($p in $Candidates) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $line = Get-Content -LiteralPath $p -ErrorAction Stop |
                Where-Object { $_ -match '^\s*URL\s*=(.+)$' } |
                Select-Object -First 1
        if (-not $line) { throw ("README.url found but no 'URL=' line in {0}" -f $p) }
        $url = ($line -replace '^\s*URL\s*=', '').Trim()
        if (-not $url) { throw ("README.url found but URL is empty in {0}" -f $p) }
        try {
            $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
            return [pscustomobject]@{ Url = $url; Html = $resp.Content }
        } catch {
            throw ("Failed to download README from {0}: {1}" -f $url, $_.Exception.Message)
        }
    }
    throw "No README.url file found in default locations."
}

function ConvertFrom-ModelJsonStrict {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)
    try { return ($Text | ConvertFrom-Json) } catch {}
    $m = [regex]::Match($Text, '(?s)\{.*\}')
    if ($m.Success) {
        try { return ($m.Value | ConvertFrom-Json) } catch {}
    }
    throw "Model did not return valid JSON. Raw: $Text"
}

function Normalize-ReadmeDoc {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Doc)

    if (-not $Doc.PSObject.Properties.Name -contains 'all_users')        { $Doc | Add-Member -NotePropertyName all_users        -NotePropertyValue @() }
    if (-not $Doc.PSObject.Properties.Name -contains 'recent_hires')     { $Doc | Add-Member -NotePropertyName recent_hires     -NotePropertyValue @() }
    if (-not $Doc.PSObject.Properties.Name -contains 'terminated_users') { $Doc | Add-Member -NotePropertyName terminated_users -NotePropertyValue @() }
    if (-not $Doc.PSObject.Properties.Name -contains 'critical_services'){ $Doc | Add-Member -NotePropertyName critical_services-NotePropertyValue @() }

    foreach ($k in 'all_users','recent_hires','terminated_users','critical_services') {
        $v = $Doc.$k
        if ($null -eq $v) { $Doc.$k = @(); continue }
        if ($v -isnot [System.Collections.IEnumerable] -or $v -is [string]) { $Doc.$k = @($v) }
    }

    foreach ($k in 'new_hires','users_to_create') {
        if (-not ($Doc.PSObject.Properties.Name -contains $k)) { continue }
        $v = $Doc.$k
        if ($null -eq $v) { $Doc.$k = @(); continue }
        if ($v -isnot [System.Collections.IEnumerable] -or $v -is [string]) { $Doc.$k = @($v) }
    }

    $convertToRecentHire = {
        param($Items)
        $result = @()
        foreach ($item in @($Items)) {
            if (-not $item) { continue }
            if ($item -is [string]) {
                $nm = ($item -as [string]).Trim()
                if (-not $nm) { continue }
                $result += [pscustomobject]@{ name = $nm; account_type = 'standard'; groups = @() }
            }
            else {
                $result += $item
            }
        }
        return $result
    }

    if ($Doc.PSObject.Properties.Name -contains 'new_hires') {
        $Doc.recent_hires = @($Doc.recent_hires + (& $convertToRecentHire $Doc.new_hires))
    }

    if ($Doc.PSObject.Properties.Name -contains 'users_to_create') {
        $Doc.recent_hires = @($Doc.recent_hires + (& $convertToRecentHire $Doc.users_to_create))
    }

    if ($Doc.PSObject.Properties.Name -contains 'Directives' -and $Doc.Directives) {
        if ($Doc.Directives.PSObject.Properties.Name -contains 'UsersToCreate') {
            $Doc.recent_hires = @($Doc.recent_hires + (& $convertToRecentHire $Doc.Directives.UsersToCreate))
        }
    }

    foreach ($colName in 'all_users','recent_hires') {
        $sanitized = @()
        foreach ($u in @($Doc.$colName)) {
            if (-not $u) { continue }
            $nm = ($u.name -as [string]).Trim()
            if (-not $nm) { continue }
            $acct = ($u.account_type -as [string])
            if ($acct -notin @('admin','standard')) { $acct = 'standard' }
            $groups = @()
            foreach ($g in @($u.groups)) {
                if ($g) { $groups += ($g -as [string]) }
            }
            $sanitized += [pscustomobject]@{
                name         = $nm
                account_type = $acct
                groups       = @($groups | Select-Object -Unique)
            }
        }
        $Doc.$colName = $sanitized
    }

    $Doc.terminated_users  = @(@($Doc.terminated_users)  | ForEach-Object { ($_ -as [string]).Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $Doc.critical_services = @(@($Doc.critical_services) | ForEach-Object { ($_ -as [string]).Trim() } | Where-Object { $_ } | Select-Object -Unique)
    return $Doc
}

function Get-ReadmeInfo {
    [CmdletBinding()]
    [Alias('Get-Readme')]
    param([string]$Root = $PSScriptRoot)

    try { $fetch = Get-ReadmeHtmlFromUrlFile }
    catch {
        Write-Info "[Readme] No README available or fetch failed. Returning empty directives."
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

    if (-not (Get-Command Invoke-ReadmeExtraction -ErrorAction SilentlyContinue)) {
        throw "Invoke-ReadmeExtraction not available. Ensure NLP.OpenRouter.psm1 is loaded."
    }

    $rawModel = Invoke-ReadmeExtraction -RawHtml $rawHtml -PlainText $plainText -Url $fetch.Url
    Write-Info "[Readme] AI raw response follows:"
    Write-Host $rawModel
    $doc      = ConvertFrom-ModelJsonStrict -Text $rawModel
    $doc      = Normalize-ReadmeDoc -Doc $doc

    $terminatedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in @($doc.terminated_users)) { [void]$terminatedSet.Add($t) }

    $users  = @()
    $admins = @()
    $groups = @{}
    $recent = @()

    foreach ($u in @($doc.all_users)) {
        if ($terminatedSet.Contains($u.name)) { continue }
        $users += $u.name
        if ($u.account_type -eq 'admin') { $admins += $u.name }
        foreach ($g in @($u.groups)) {
            if (-not $g) { continue }
            if (-not $groups.ContainsKey($g)) { $groups[$g] = @() }
            $groups[$g] += $u.name
        }
    }

    foreach ($r in @($doc.recent_hires)) {
        if ($terminatedSet.Contains($r.name)) { continue }
        $recent += [pscustomobject]@{
            Name        = $r.name
            AccountType = $r.account_type
            Groups      = @($r.groups)
        }
        $users += $r.name
        if ($r.account_type -eq 'admin') { $admins += $r.name }
        foreach ($g in @($r.groups)) {
            if (-not $g) { continue }
            if (-not $groups.ContainsKey($g)) { $groups[$g] = @() }
            $groups[$g] += $r.name
        }
    }

    $directives = [ordered]@{
        GroupsToCreate              = @($groups.Keys | Select-Object -Unique)
        GroupMembersToAdd           = @{}
        UsersToCreate               = @($recent)
        TerminatedUsers             = @(@($doc.terminated_users) | Select-Object -Unique)
        CriticalServices            = @(@($doc.critical_services) | Select-Object -Unique)
        UnauthorizedUsersExplicit   = @()
        EnsureGuestDisabled         = $true
        EnsureAdministratorDisabled = $true
    }
    foreach ($k in $groups.Keys) {
        $directives.GroupMembersToAdd[$k] = @($groups[$k] | Select-Object -Unique)
    }

    Write-Info ("[Readme] AI parsed: {0} all_users, {1} hires, {2} terminated, {3} groups" -f `
        $users.Count, @($recent).Count, $directives.TerminatedUsers.Count, $directives.GroupsToCreate.Count)

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

$publicFunctions = @('Get-ReadmeInfo','Remove-HTMLTags','Get-ReadmeHtmlFromUrlFile')
$moduleName = $null
if (Test-Path -LiteralPath 'variable:PSModuleName') {
    $moduleName = Get-Variable -Name PSModuleName -ValueOnly -ErrorAction SilentlyContinue
}
if ($moduleName) {
    Export-ModuleMember -Function $publicFunctions -Alias Get-Readme
} else {
    foreach ($fn in $publicFunctions) {
        $src = Get-Item ("function:{0}" -f $fn) -ErrorAction SilentlyContinue
        if ($src) { Set-Item -Path ("function:global:{0}" -f $fn) -Value $src.ScriptBlock -ErrorAction SilentlyContinue }
    }
    if (-not (Get-Alias Get-Readme -ErrorAction SilentlyContinue)) {
        Set-Alias -Name Get-Readme -Value Get-ReadmeInfo -Scope Global
    }
}
