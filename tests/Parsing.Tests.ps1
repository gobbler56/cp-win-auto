$modulePath = Join-Path $PSScriptRoot '../core/Parsing.psm1'
. $modulePath

Describe 'Get-ReadmeHtmlFromUrlFile' {
  Context 'Aeacus practice image support' {
    It 'should check for Aeacus README first when file exists' {
      # Create a temporary Aeacus README for testing
      $tempAeacusPath = Join-Path $env:TEMP 'test_aeacus_readme.html'
      $testHtml = '<html><body><h1>Test Aeacus README</h1></body></html>'
      Set-Content -Path $tempAeacusPath -Value $testHtml -Force

      try {
        $result = Get-ReadmeHtmlFromUrlFile -AeacusReadmePath $tempAeacusPath -ErrorAction SilentlyContinue
        $result | Should -Not -BeNullOrEmpty
        $result.Html | Should -Be $testHtml
        $result.Url | Should -Match 'file:///'
      }
      finally {
        if (Test-Path $tempAeacusPath) {
          Remove-Item $tempAeacusPath -Force
        }
      }
    }

    It 'should fall back to CyberPatriot logic when Aeacus README does not exist' {
      $nonExistentPath = 'C:\NonExistent\Path\ReadMe.html'
      # This should throw because no README.url files exist in test environment
      { Get-ReadmeHtmlFromUrlFile -AeacusReadmePath $nonExistentPath -Candidates @('C:\NonExistent\README.url') } |
        Should -Throw
    }
  }
}

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
