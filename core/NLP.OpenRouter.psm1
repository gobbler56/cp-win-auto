Set-StrictMode -Version Latest

$script:READMESYS_PROMPT = @'
You are a STRICT extractor for CyberPatriot READMEs. 
Return ONLY minified JSON, no prose, no markdown, no code fences. 
If something is not present, return an empty array [] or empty object {} as appropriate.

Contract (keys and types are REQUIRED):
{
  "all_users": [ { "name": "string", "account_type": "standard|admin", "groups": ["string", ...] }, ... ],
  "recent_hires": [ { "name": "string", "account_type": "standard|admin", "groups": ["string", ...] }, ... ],
  "terminated_users": ["string", ...],
  "critical_services": ["string", ...]
}

Rules:
- Use the README’s own lists as ground truth; do not hallucinate names.
- Include every allowed/authorized person under "all_users" with their account_type (admin if they’re an administrator, otherwise standard). Include any groups if listed.
- Put ONLY newly required accounts under "recent_hires".
- Put ONLY explicitly unauthorized or removed users under "terminated_users".
- If Guest should be disabled or Administrator disabled, DO NOT list them in all_users; engine handles built-ins.
- If a task says “Create user account for user penguru”, emit:
  "recent_hires":[{"name":"penguru","account_type":"standard","groups":[]}].
- If a task says “Change unauthorized administrator jchutney to standard user”, ensure "all_users" contains jchutney as standard (not admin).
- Do not include textual explanations. Output MUST be valid JSON, a single object, no trailing commas.

Examples:
INPUT (plain text snippet):
"4. Remove unauthorized user darkarmy
5. Remove unauthorized user fsociety
6. Create user account for user penguru
7. Change unauthorized administrator jchutney to standard user"

VALID OUTPUT:
{"all_users":[{"name":"jchutney","account_type":"standard","groups":[]}],"recent_hires":[{"name":"penguru","account_type":"standard","groups":[]}],"terminated_users":["darkarmy","fsociety"],"critical_services":[]}
'@

function Invoke-ReadmeExtraction {
  <#
    Uses OpenRouter to extract structured directives from a CyberPatriot README.
    Requires: $env:OPENROUTER_API_KEY
    Model: $env:OPENROUTER_MODEL (default: openai/gpt-5-mini)

    Returns the raw JSON string provided by the model.
  #>
  param(
    [Parameter(Mandatory)][string]$RawHtml,
    [string]$PlainText = "",
    [string]$Url = ""
  )

  $apiKey = $env:OPENROUTER_API_KEY
  if (-not $apiKey) { throw "OPENROUTER_API_KEY not set" }

  $model = if ($env:OPENROUTER_MODEL) { $env:OPENROUTER_MODEL } else { 'openai/gpt-5-mini' }

  $userContentBuilder = [System.Text.StringBuilder]::new()
  if ($Url) {
    [void]$userContentBuilder.Append("SOURCE: $Url`n`n")
  }
  if ($PlainText) {
    [void]$userContentBuilder.Append($PlainText)
  } elseif ($RawHtml) {
    [void]$userContentBuilder.Append($RawHtml)
  }

  $messages = @(
    @{ role = 'system'; content = $script:READMESYS_PROMPT },
    @{ role = 'user';   content = $userContentBuilder.ToString() }
  )

  $body = @{
    model = $model
    temperature = 0
    top_p = 1
    messages = $messages
  } | ConvertTo-Json -Depth 10

  $headers = @{
    'Authorization' = "Bearer $apiKey"
    'Content-Type'  = 'application/json'
    'X-Title'       = 'CP-Readme-Extraction'
  }

  try {
    $resp = Invoke-RestMethod -Method Post -Uri 'https://openrouter.ai/api/v1/chat/completions' -Headers $headers -Body $body -ErrorAction Stop
    $txt  = [string]$resp.choices[0].message.content
    if (-not $txt) { throw "OpenRouter returned empty content" }
    return $txt.Trim()
  } catch {
    throw "OpenRouter extraction failed: $($_.Exception.Message)"
  }
}

Export-ModuleMember -Function Invoke-ReadmeExtraction
