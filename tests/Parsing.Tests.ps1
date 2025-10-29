$modulePath = Join-Path $PSScriptRoot '../core/Parsing.psm1'
. $modulePath

Describe 'Find-RecentHireMentions' {
  It 'detects quoted user creation instructions' {
    $text = 'Your company just hired a new employee. Make a new account for this employee named "penguru".'
    $results = Find-RecentHireMentions -PlainText $text
    $results | Should -Not -BeNullOrEmpty
    $results[0].Name | Should -Be 'penguru'
    $results[0].AccountType | Should -Be 'standard'
  }

  It 'flags admin accounts when sentence specifies administrator' {
    $text = 'Create a new user called "weston" and make them an administrator.'
    $results = Find-RecentHireMentions -PlainText $text
    $results | Should -Not -BeNullOrEmpty
    ($results | Where-Object Name -eq 'weston').AccountType | Should -Be 'admin'
  }

  It 'ignores names in terminated set' {
    $text = 'Make a new account named "former" for onboarding.'
    $terminated = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    [void]$terminated.Add('former')
    $results = Find-RecentHireMentions -PlainText $text -TerminatedSet $terminated
    $results | Should -BeNullOrEmpty
  }
}
