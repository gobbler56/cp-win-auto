Set-StrictMode -Version Latest

function Invoke-ReadmeExtraction {
  <#
    Uses OpenRouter to extract structured directives from a CyberPatriot README (HTML).
    Requires: $env:OPENROUTER_API_KEY
    Model: $env:OPENROUTER_MODEL (default: openai/gpt-5-mini)

    Returns a PSCustomObject matching the schema:
    {
      title: string,
      all_users: [{name, account_type: admin|standard, groups: [..]}],
      critical_services: [string]
    }
  #>
  param(
    [Parameter(Mandatory)][string]$RawHtml,
    [string]$PlainText = ""
  )

  $apiKey = $env:OPENROUTER_API_KEY
  if (-not $apiKey) { throw "OPENROUTER_API_KEY not set" }

  $model = if ($env:OPENROUTER_MODEL) { $env:OPENROUTER_MODEL } else { 'openai/gpt-5-mini' }

  $system = @"
You are a **deterministic information extraction engine** for CyberPatriot Windows images.
Input is an HTML README page (sometimes ASPX). Output **must** be a single JSON object matching the EXACT schema below.
You must **NOT** invent users, groups, or services. Only include items explicitly present in the text.
When uncertain, leave arrays empty. Never output null/undefined and never add extra keys.

Extraction rules:
- **Title**: Prefer page <title> or the first visible heading naming the image (strip suffix like "README").
- **Users**: Combine all users mentioned anywhere (authorized lists, prose instructions like “create user ...”, screenshots text if present).
  * Name is the local account token: strip annotations like "(you)", emails/domains, punctuation around quotes.
  * `account_type`: "admin" if placed in Administrators or listed under "Authorized Administrators"; else "standard".
  * `groups`: include any named local groups each user should belong to (e.g., "hypersonic") as they appear in text.
- **Groups**: If the README says “create group ... and add ...”, you still encode this only via each user's `groups` array.
- **Critical services**: List service/product names explicitly mentioned as important to keep/configure (e.g., "IIS", "RDP", "SMB", "DNS", "MySQL", "Apache", "PHP", "FileZilla"). Don’t infer.
- Ignore passwords provided in the README.
- Ignore any domain/AD directives entirely (this is **local-only**).
- Be strict: if something isn’t stated, don’t output it.

Return ONLY JSON. No explanations.
"@

  # JSON Schema for OpenRouter structured outputs
  $schema = @{
    type = "object"
    additionalProperties = $false
    required = @("title","all_users","critical_services")
    properties = @{
      title = @{ type = "string" }
      all_users = @{
        type = "array"
        items = @{
          type = "object"
          additionalProperties = $false
          required = @("name","account_type","groups")
          properties = @{
            name = @{ type = "string" }
            account_type = @{ type = "string"; enum = @("admin","standard") }
            groups = @{
              type = "array"
              items = @{ type = "string" }
            }
          }
        }
      }
      critical_services = @{
        type = "array"
        items = @{ type = "string" }
      }
    }
  }

  $messages = @(
    @{ role = "system"; content = $system },
    @{ role = "user"; content = @"
<INPUT>
[RAW_HTML_START]
$RawHtml
[RAW_HTML_END]

[PLAIN_TEXT_START]
$PlainText
[PLAIN_TEXT_END]
</INPUT>
"@ }
  )

  $body = @{
    model = $model
    temperature = 0
    top_p = 1
    # Let the model use as many tokens as needed for high-variance HTML pages
    # (models will cap at their own server-side max; no artificial cap here)
    messages = $messages
    response_format = @{
      type = "json_schema"
      json_schema = @{
        name = "structured_readme"
        schema = $schema
      }
    }
  } | ConvertTo-Json -Depth 20

  $headers = @{
    "Authorization" = "Bearer $apiKey"
    "Content-Type"  = "application/json"
    "X-Title"       = "CP-Readme-Extraction"
  }

  try {
    $resp = Invoke-RestMethod -Method Post -Uri 'https://openrouter.ai/api/v1/chat/completions' -Headers $headers -Body $body -ErrorAction Stop
    $txt  = $resp.choices[0].message.content
    if (-not $txt) { throw "OpenRouter returned empty content" }
    if ($txt -match '^\s*```') { $txt = ($txt -replace '^\s*```(?:json)?','' -replace '```\s*$','').Trim() }
    return ($txt | ConvertFrom-Json)
  } catch {
    throw "OpenRouter extraction failed: $($_.Exception.Message)"
  }
}

Export-ModuleMember -Function Invoke-ReadmeExtraction
