Set-StrictMode -Version Latest

if (-not (Get-Command New-ModuleResult -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Contracts.psm1')
}
if (-not (Get-Command Write-Info -EA SilentlyContinue)) {
  Import-Module -Force -DisableNameChecking (Join-Path $PSScriptRoot '../../core/Utils.psm1')
}

$script:ModuleName            = 'ForensicsQuestions'
$script:ApiUrl                = 'https://openrouter.ai/api/v1/chat/completions'
$script:ApiKeyEnvVar          = 'OPENROUTER_API_KEY'
$script:OpenRouterModel       = if ($env:OPENROUTER_MODEL) { $env:OPENROUTER_MODEL } else { 'openai/gpt-5' }
$script:OpenRouterMaxTokens   = {
  $default = 4000
  if (-not $env:OPENROUTER_MAX_TOKENS) { return $default }

  $parsed = 0
  if ([int]::TryParse($env:OPENROUTER_MAX_TOKENS, [ref]$parsed)) {
    if ($parsed -gt 0) { return $parsed }
  }

  return $default
}.Invoke()
$script:QuestionPattern       = 'Forensics Question *.txt'
$script:PlaceholderPattern    = '^(ANSWER:\s*)(<Type Answer Here>)(\s*)$'
$script:PlaceholderRegex      = New-Object System.Text.RegularExpressions.Regex($script:PlaceholderPattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
$script:MaxCommandOutputBytes = 200 * 1024
$script:MaxCommandRequests    = 6
$script:SystemPrompt          = @"
You are an experienced digital forensics analyst assisting with CyberPatriot-style Windows tasks.
Review the forensic question text and decide whether you can answer immediately or need more local data.
If you can answer now, respond starting with "FINAL ANSWER:" followed by one or more answer lines (each answer on its own line).
If you require data, respond starting with "NEED DATA:" and list at most $($script:MaxCommandRequests) commands (one per line) from this allow-listed set:
  - dir <path>
  - type <path>
  - get-content -totalcount <n> <path>
  - get-content -tail <n> <path>
  - findstr /i "pattern" <path>
  - base64-decode <encoded text>
  - hex-to-ascii <hex string>
  - xor-hex <hex string 1> <hex string 2>
Do not request other commands.
Only provide a FINAL ANSWER when you are confident.
If the information remains insufficient, reply with "CANNOT ANSWER".
"@

function Get-OpenRouterApiKey {
  $key = [System.Environment]::GetEnvironmentVariable($script:ApiKeyEnvVar)
  if (-not $key) { return '' }
  return $key
}

function Test-Ready {
  param($Context)

  if (-not (Get-OpenRouterApiKey)) {
    Write-Warn "OpenRouter API key is missing (set `$env:$($script:ApiKeyEnvVar)); ForensicsQuestions module will be skipped."
    return $false
  }

  return $true
}

function Get-MainDesktopPath {
  param($Context)

  if ($env:USERPROFILE) {
    $desktop = Join-Path $env:USERPROFILE 'Desktop'
    if (Test-Path -LiteralPath $desktop) { return $desktop }
  }

  if ($Context -and $Context.AutoLogonUser) {
    $drive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
    $candidate = Join-Path (Join-Path $drive 'Users') $Context.AutoLogonUser
    $desktop = Join-Path $candidate 'Desktop'
    if (Test-Path -LiteralPath $desktop) { return $desktop }
  }

  return $null
}

function Get-QuestionFiles {
  param($Context)

  $files = @()
  $primaryDesktop = Get-MainDesktopPath -Context $Context
  if ($primaryDesktop) {
    try {
      $files = Get-ChildItem -Path $primaryDesktop -Filter $script:QuestionPattern -File -ErrorAction Stop
    } catch {}

    if ($files -and $files.Count -gt 0) {
      return (Sort-QuestionFiles -Files $files)
    }
  }

  $fallback = @()
  $drive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
  $usersRoot = Join-Path $drive 'Users'
  if (Test-Path -LiteralPath $usersRoot) {
    foreach ($userDir in (Get-ChildItem -Path $usersRoot -Directory -ErrorAction SilentlyContinue)) {
      $desktop = Join-Path $userDir.FullName 'Desktop'
      if (-not (Test-Path -LiteralPath $desktop)) { continue }
      try {
        $candidate = Get-ChildItem -Path $desktop -Filter $script:QuestionPattern -File -ErrorAction Stop
        if ($candidate) { $fallback += $candidate }
      } catch {}
    }
  }

  return (Sort-QuestionFiles -Files $fallback)
}

function Sort-QuestionFiles {
  param([System.IO.FileInfo[]]$Files)

  if (-not $Files) { return @() }

  $decorated = foreach ($file in $Files) {
    $match = [regex]::Match($file.BaseName, 'Forensics Question\s*(\d+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $hasNumber = $match.Success
    $number = if ($hasNumber) { [int]$match.Groups[1].Value } else { [int]::MaxValue }
    [pscustomobject]@{ File = $file; HasNumber = $hasNumber; Number = $number; Name = $file.Name }
  }

  $ordered = $decorated | Sort-Object -Property @{Expression={ if ($_.HasNumber) { 0 } else { 1 } }}, @{Expression={ $_.Number }}, @{Expression={ $_.Name }}
  return @($ordered | ForEach-Object { $_.File })
}

function Read-QuestionContent {
  param([string]$Path)

  try {
    return Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
  } catch {
    throw ("Failed to read forensic question file {0}: {1}" -f $Path, $_.Exception.Message)
  }
}

function Test-HasPlaceholder {
  param([string]$Content)
  if (-not $Content) { return $false }
  return $script:PlaceholderRegex.IsMatch($Content)
}

function Build-InitialUserPrompt {
  param([string]$Path,[string]$Content)

  $trimmed = $Content.Trim()
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine("Forensic question file: $Path")
  [void]$sb.AppendLine('--- QUESTION TEXT BEGIN ---')
  [void]$sb.AppendLine($trimmed)
  [void]$sb.AppendLine('--- QUESTION TEXT END ---')
  [void]$sb.AppendLine()
  [void]$sb.Append('Determine the correct answer(s) or request additional data using the allowed commands.')
  return $sb.ToString()
}

function Invoke-ChatCompletion {
  param(
    [object[]]$Messages,
    [int]$MaxTokens = $script:OpenRouterMaxTokens
  )

  $apiKey = Get-OpenRouterApiKey
  if (-not $apiKey) {
    throw 'OpenRouter API key not found.'
  }

  $body = @{
    model       = $script:OpenRouterModel
    temperature = 0
    max_tokens  = $MaxTokens
    messages    = $Messages
  }

  $json = $body | ConvertTo-Json -Depth 6

  $headers = @{
    'Authorization' = "Bearer $apiKey"
    'Content-Type'  = 'application/json'
  }
  if ($env:OPENROUTER_SITE) { $headers['HTTP-Referer'] = $env:OPENROUTER_SITE }
  if ($env:OPENROUTER_TITLE) { $headers['X-Title'] = $env:OPENROUTER_TITLE }

  try {
    $response = Invoke-RestMethod -Uri $script:ApiUrl -Method Post -Headers $headers -Body $json -ErrorAction Stop
  } catch {
    throw ("OpenRouter request failed: {0}" -f $_.Exception.Message)
  }

  if (-not $response -or -not $response.choices -or $response.choices.Count -eq 0) {
    throw 'OpenRouter response was empty.'
  }

  $content = $response.choices[0].message.content
  if (-not $content) {
    throw 'OpenRouter returned no content.'
  }

  return [string]$content
}

function Clean-AnswerLine {
  param([string]$Line)
  if (-not $Line) { return '' }
  $value = $Line.Trim()
  $value = $value -replace '^[\-\*\u2022]+\s*',''
  $value = $value -replace '^\d+[\.)]\s*',''
  return $value.Trim()
}

function Parse-AiResponse {
  param([string]$Response)

  if (-not $Response) { return [pscustomobject]@{ Status='Unknown'; Answers=@(); Requests=@(); Raw='' } }

  $text = $Response.Trim()
  $lines = @($text -split '\r?\n')
  if ($lines.Count -eq 0) { return [pscustomobject]@{ Status='Unknown'; Answers=@(); Requests=@(); Raw=$text } }

  $first = $lines[0]
  if ($first -match '^(?i)\s*FINAL\s+ANSWER\s*:\s*(.*)$') {
    $answers = @()
    $initial = Clean-AnswerLine $Matches[1]
    if ($initial) { $answers += $initial }
    if ($lines.Count -gt 1) {
      foreach ($line in $lines[1..($lines.Count-1)]) {
        $clean = Clean-AnswerLine $line
        if ($clean) { $answers += $clean }
      }
    }
    if (-not $answers -or (@($answers | Where-Object { $_ -match '(?i)manual review' }).Count -gt 0)) {
      return [pscustomobject]@{ Status='ManualReview'; Answers=@(); Requests=@(); Raw=$text }
    }
    return [pscustomobject]@{ Status='Final'; Answers=@($answers); Requests=@(); Raw=$text }
  }

  if ($first -match '^(?i)\s*NEED\s+DATA\s*:\s*(.*)$') {
    $requests = @()
    $initial = $Matches[1].Trim()
    if ($initial) { $requests += $initial }
    if ($lines.Count -gt 1) {
      foreach ($line in $lines[1..($lines.Count-1)]) {
        $trimmed = $line.Trim()
        if ($trimmed) { $requests += $trimmed }
      }
    }
    return [pscustomobject]@{ Status='NeedData'; Answers=@(); Requests=@($requests); Raw=$text }
  }

  if ($first -match '^(?i)\s*(CANNOT\s+ANSWER|UNABLE\s+TO\s+ANSWER|NO\s+ANSWER)') {
    return [pscustomobject]@{ Status='ManualReview'; Answers=@(); Requests=@(); Raw=$text }
  }

  return [pscustomobject]@{ Status='Unknown'; Answers=@(); Requests=@(); Raw=$text }
}

function Limit-Output {
  param([string]$Text)

  if (-not $Text) { return '' }

  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
  if ($bytes.Length -le $script:MaxCommandOutputBytes) { return $Text }

  $limit = $script:MaxCommandOutputBytes
  $truncated = [System.Text.Encoding]::UTF8.GetString($bytes, 0, $limit)
  return ($truncated.TrimEnd() + "`r`n...[output truncated]...")
}

function Split-CommandLine {
  param([string]$Command)

  $parts = New-Object System.Collections.Generic.List[string]
  if ([string]::IsNullOrWhiteSpace($Command)) { return @() }

  $current = New-Object System.Text.StringBuilder
  $inQuote = $false
  $quoteChar = [char]0

  foreach ($ch in $Command.ToCharArray()) {
    if ($inQuote) {
      if ($ch -eq $quoteChar) {
        $inQuote = $false
      } else {
        [void]$current.Append($ch)
      }
      continue
    }

    if ($ch -eq [char]34 -or $ch -eq [char]39) {
      $inQuote = $true
      $quoteChar = $ch
      continue
    }

    if ([char]::IsWhiteSpace($ch)) {
      if ($current.Length -gt 0) {
        $parts.Add($current.ToString()) | Out-Null
        $current.Clear() | Out-Null
      }
      continue
    }

    [void]$current.Append($ch)
  }

  if ($current.Length -gt 0) { $parts.Add($current.ToString()) | Out-Null }
  return @($parts)
}

function Read-FileSample {
  param([string]$Path,[int]$ByteLimit = $script:MaxCommandOutputBytes)

  if (-not (Test-Path -LiteralPath $Path)) {
    throw ("File not found: {0}" -f $Path)
  }

  $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    $buffer = New-Object byte[] $ByteLimit
    $read = $fs.Read($buffer, 0, $buffer.Length)
    $text = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $read)
    if ($fs.Length -gt $read) {
      $text += "`r`n...[output truncated]..."
    }
    return $text
  } finally {
    $fs.Dispose()
  }
}

function Invoke-AllowedCommand {
  param([string]$Command)

  $result = [pscustomobject]@{ Command=$Command; Allowed=$true; Success=$false; Output=''; Error='' }
  $tokens = Split-CommandLine $Command
  if (-not $tokens -or $tokens.Count -eq 0) {
    $result.Allowed = $false
    $result.Error = 'Empty command'
    return $result
  }

  $cmd = $tokens[0].ToLowerInvariant()

  switch ($cmd) {
    'dir' {
      if ($tokens.Count -lt 2) {
        $result.Success = $false
        $result.Error = 'Path argument missing.'
        break
      }
      $path = $tokens[1]
      $useLiteral = -not [System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($path)
      try {
        $items = if ($useLiteral) {
          Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop
        } else {
          Get-ChildItem -Path $path -Force -ErrorAction Stop
        }
        $count = @($items).Count
        $items = $items | Sort-Object Name | Select-Object -First 200
        $table = $items | Select-Object Mode,LastWriteTime,Length,Name | Format-Table -AutoSize | Out-String
        $output = "Directory listing for $path (showing $(@($items).Count) of $count items)" + "`r`n" + $table.TrimEnd()
        if ($count -gt 200) { $output += "`r`n...[listing truncated]..." }
        $result.Output = Limit-Output $output
        $result.Success = $true
      } catch {
        $result.Error = $_.Exception.Message
      }
    }
    'type' {
      if ($tokens.Count -lt 2) {
        $result.Error = 'Path argument missing.'
        break
      }
      $path = $tokens[1]
      try {
        $text = Read-FileSample -Path $path
        $result.Output = Limit-Output $text
        $result.Success = $true
      } catch {
        $result.Error = $_.Exception.Message
      }
    }
    'get-content' {
      if ($tokens.Count -lt 4) {
        $result.Error = 'Expected syntax: get-content -totalcount|-tail <n> <path>'
        break
      }
      $option = $tokens[1].ToLowerInvariant()
      $count = 0
      if (-not [int]::TryParse($tokens[2], [ref]$count) -or $count -le 0) {
        $result.Error = 'Count must be a positive integer.'
        break
      }
      $path = $tokens[3]
      try {
        if ($option -eq '-totalcount') {
          $lines = Get-Content -LiteralPath $path -TotalCount $count -ErrorAction Stop
        } elseif ($option -eq '-tail') {
          $lines = Get-Content -LiteralPath $path -Tail $count -ErrorAction Stop
        } else {
          $result.Error = 'Only -TotalCount and -Tail are supported.'
          break
        }
        $text = ($lines -join [Environment]::NewLine)
        $result.Output = Limit-Output $text
        $result.Success = $true
      } catch {
        $result.Error = $_.Exception.Message
      }
    }
    'findstr' {
      if ($tokens.Count -lt 3) {
        $result.Error = 'Expected syntax: findstr [/i] "pattern" <path>'
        break
      }
      $path = $tokens[-1]
      $options = @()
      $patternParts = @()
      foreach ($token in $tokens[1..($tokens.Count-2)]) {
        if ($token.StartsWith('/')) { $options += $token.ToLowerInvariant() }
        else { $patternParts += $token }
      }
      if (-not (Test-Path -LiteralPath $path)) {
        $result.Error = "File not found: $path"
        break
      }
      $pattern = ($patternParts -join ' ').Trim()
      if (-not $pattern) {
        $result.Error = 'Pattern missing.'
        break
      }
      $ignoreCase = $options -contains '/i'
      try {
        $matches = Select-String -LiteralPath $path -Pattern $pattern -SimpleMatch -CaseSensitive:(-not $ignoreCase) -ErrorAction Stop
        if (-not $matches) {
          $result.Output = 'No matches.'
        } else {
          $matches = @($matches | Select-Object -First 200)
          $lines = $matches | ForEach-Object { "Line $($_.LineNumber): $($_.Line.TrimEnd())" }
          $result.Output = Limit-Output ($lines -join "`r`n")
          if (@($matches).Count -eq 200) { $result.Output += "`r`n...[matches truncated]..." }
        }
        $result.Success = $true
      } catch {
        $result.Error = $_.Exception.Message
      }
    }
    'base64-decode' {
      if ($tokens.Count -lt 2) {
        $result.Error = 'Encoded text missing.'
        break
      }
      $joined = ($tokens[1..($tokens.Count-1)] -join '')
      try {
        $bytes = [System.Convert]::FromBase64String($joined)
        $decoded = [System.Text.Encoding]::UTF8.GetString($bytes)
        $result.Output = Limit-Output $decoded
        $result.Success = $true
      } catch {
        $result.Error = $_.Exception.Message
      }
    }
    'hex-to-ascii' {
      if ($tokens.Count -lt 2) {
        $result.Error = 'Hex string missing.'
        break
      }
      $hex = ($tokens[1..($tokens.Count-1)] -join '') -replace '[^0-9a-fA-F]', ''
      if ($hex.Length % 2 -ne 0) {
        $result.Error = 'Hex string length must be even.'
        break
      }
      try {
        $bytes = New-Object byte[] ($hex.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
          $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
        }
        $ascii = [System.Text.Encoding]::UTF8.GetString($bytes)
        $result.Output = Limit-Output $ascii
        $result.Success = $true
      } catch {
        $result.Error = $_.Exception.Message
      }
    }
    'xor-hex' {
      if ($tokens.Count -lt 3) {
        $result.Error = 'Expected syntax: xor-hex <hex1> <hex2>'
        break
      }
      $hex1 = ($tokens[1] -replace '[^0-9a-fA-F]', '')
      $hex2 = ($tokens[2] -replace '[^0-9a-fA-F]', '')
      if ($hex1.Length -ne $hex2.Length) {
        $result.Error = 'Hex strings must be the same length.'
        break
      }
      if ($hex1.Length % 2 -ne 0) {
        $result.Error = 'Hex strings must have even length.'
        break
      }
      try {
        $len = $hex1.Length / 2
        $bytes = New-Object byte[] $len
        for ($i = 0; $i -lt $len; $i++) {
          $b1 = [Convert]::ToByte($hex1.Substring($i * 2, 2), 16)
          $b2 = [Convert]::ToByte($hex2.Substring($i * 2, 2), 16)
          $bytes[$i] = $b1 -bxor $b2
        }
        $ascii = [System.Text.Encoding]::UTF8.GetString($bytes)
        $hexOut = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
        $result.Output = Limit-Output ("ASCII: $ascii`r`nHEX: $hexOut")
        $result.Success = $true
      } catch {
        $result.Error = $_.Exception.Message
      }
    }
    Default {
      $result.Allowed = $false
      $result.Error = 'Command not allow-listed.'
    }
  }

  return $result
}

function Execute-RequestedCommands {
  param([string[]]$Requests)

  $results = New-Object System.Collections.Generic.List[object]
  if (-not $Requests) { return @() }

  $count = 0
  foreach ($req in $Requests) {
    if ($count -ge $script:MaxCommandRequests) {
      [void]$results.Add([pscustomobject]@{ Command=$req; Allowed=$false; Success=$false; Output=''; Error='Request limit exceeded.' })
      continue
    }
    $count++
    [void]$results.Add((Invoke-AllowedCommand -Command $req))
  }

  return @($results)
}

function Build-CommandResultsPrompt {
  param([object[]]$Results)

  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine('Requested commands were executed. Here are the results:')
  foreach ($entry in $Results) {
    [void]$sb.AppendLine("COMMAND: $($entry.Command)")
    if (-not $entry.Allowed) {
      [void]$sb.AppendLine("RESULT: not permitted ($($entry.Error))")
    } elseif (-not $entry.Success) {
      if ($entry.Error) {
        [void]$sb.AppendLine("RESULT: failed ($($entry.Error))")
      } else {
        [void]$sb.AppendLine('RESULT: command failed.')
      }
    } else {
      [void]$sb.AppendLine('OUTPUT:')
      [void]$sb.AppendLine($entry.Output)
    }
    [void]$sb.AppendLine()
  }
  return $sb.ToString().TrimEnd()
}

function Invoke-ForensicsQuestion {
  param([string]$Path,[string]$Content)

  $messages = @(
    @{ role = 'system'; content = $script:SystemPrompt },
    @{ role = 'user';   content = (Build-InitialUserPrompt -Path $Path -Content $Content) }
  )

  $response1 = Invoke-ChatCompletion -Messages $messages
  $parsed1 = Parse-AiResponse -Response $response1

  if ($parsed1.Status -eq 'Final') {
    return [pscustomobject]@{ Status='Answered'; Answers=$parsed1.Answers; Responses=@($response1); Commands=@(); Manual=$false }
  }

  if ($parsed1.Status -eq 'ManualReview') {
    return [pscustomobject]@{ Status='ManualReview'; Answers=@(); Responses=@($response1); Commands=@(); Manual=$true }
  }

  if ($parsed1.Status -ne 'NeedData') {
    return [pscustomobject]@{ Status='ManualReview'; Answers=@(); Responses=@($response1); Commands=@(); Manual=$true }
  }

  $executed = Execute-RequestedCommands -Requests $parsed1.Requests
  $messages += @{ role = 'assistant'; content = $response1 }
  $messages += @{ role = 'user'; content = (Build-CommandResultsPrompt -Results $executed) }

  try {
    $response2 = Invoke-ChatCompletion -Messages $messages
  } catch {
    return [pscustomobject]@{ Status='ManualReview'; Answers=@(); Responses=@($response1); Commands=$executed; Manual=$true }
  }

  $parsed2 = Parse-AiResponse -Response $response2
  if ($parsed2.Status -eq 'Final') {
    return [pscustomobject]@{ Status='Answered'; Answers=$parsed2.Answers; Responses=@($response1,$response2); Commands=$executed; Manual=$false }
  }

  return [pscustomobject]@{ Status='ManualReview'; Answers=@(); Responses=@($response1,$response2); Commands=$executed; Manual=$true }
}

function Write-AnswersToFile {
  param([string]$Path,[string]$Original,[string[]]$Answers)

  if (-not $Answers -or $Answers.Count -eq 0) { return $false }

  $replacement = ($Answers | ForEach-Object { "ANSWER: $_" }) -join "`r`n"
  $newContent = $script:PlaceholderRegex.Replace($Original, $replacement, 1)
  if ($newContent -eq $Original) { return $false }

  $backup = "$Path.bak"
  try {
    Copy-Item -LiteralPath $Path -Destination $backup -Force
  } catch {
    Write-Warn ("Failed to create backup for {0}: {1}" -f $Path, $_.Exception.Message)
  }

  [System.IO.File]::WriteAllText($Path, $newContent, [System.Text.Encoding]::UTF8)
  return $true
}

function Invoke-Apply {
  param($Context)

  $files = Get-QuestionFiles -Context $Context
  if (-not $files -or $files.Count -eq 0) {
    Write-Info 'No forensic question files discovered.'
    return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message 'No forensic questions found.')
  }

  $answered = 0
  $manual = 0
  $skipped = 0
  $errors = 0

  foreach ($file in $files) {
    Write-Info ("Processing {0}" -f $file.FullName)
    try {
      $content = Read-QuestionContent -Path $file.FullName
    } catch {
      Write-Err $_.Exception.Message
      $errors++
      continue
    }

    if (-not (Test-HasPlaceholder -Content $content)) {
      Write-Info 'Placeholder not found; skipping (already answered).'
      $skipped++
      continue
    }

    try {
      $outcome = Invoke-ForensicsQuestion -Path $file.FullName -Content $content
    } catch {
      Write-Err ("AI workflow failed for {0}: {1}" -f $file.FullName, $_.Exception.Message)
      $manual++
      continue
    }

    if ($outcome.Status -eq 'Answered') {
      if (Write-AnswersToFile -Path $file.FullName -Original $content -Answers $outcome.Answers) {
        Write-Ok ("Answered forensic question in {0}" -f $file.Name)
        $answered++
      } else {
        Write-Warn ("Failed to update {0} after receiving answer." -f $file.FullName)
        $errors++
      }
    } else {
      Write-Warn ("Manual review required for {0}" -f $file.FullName)
      $manual++
    }
  }

  $message = "Answered $answered question(s); $manual pending manual review; $skipped already complete; $errors error(s)."
  $status = if ($errors -eq 0 -and $manual -eq 0) { 'Succeeded' } elseif ($answered -gt 0) { 'PartialSuccess' } else { 'Failed' }
  return (New-ModuleResult -Name $script:ModuleName -Status $status -Message $message)
}

function Invoke-Verify {
  param($Context)

  $files = Get-QuestionFiles -Context $Context
  if (-not $files -or $files.Count -eq 0) {
    return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message 'No forensic question files found.')
  }

  $pending = 0
  foreach ($file in $files) {
    try {
      $content = Read-QuestionContent -Path $file.FullName
    } catch {
      $pending++
      continue
    }
    if (Test-HasPlaceholder -Content $content) { $pending++ }
  }

  if ($pending -eq 0) {
    return (New-ModuleResult -Name $script:ModuleName -Status 'Succeeded' -Message 'All forensic question files have answers.')
  }

  return (New-ModuleResult -Name $script:ModuleName -Status 'Failed' -Message ("{0} forensic question file(s) still contain placeholders." -f $pending))
}

Export-ModuleMember -Function Test-Ready,Invoke-Apply,Invoke-Verify
