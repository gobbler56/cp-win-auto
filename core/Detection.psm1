
    Set-StrictMode -Version Latest

    function Get-OSProfile {
      $os = (Get-CimInstance Win32_OperatingSystem).Caption
      if ($os -match 'Windows 11') { return 'win11' }
      elseif ($os -match 'Windows Server 2019') { return 'server2019' }
      elseif ($os -match 'Windows Server 2022') { return 'server2022' }
      else { return 'win11' }
    }

    function Get-Role {
      try {
        $ad = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction Stop
        if ($ad.Installed) { return 'dc' }
      } catch {}
      return 'member'
    }

    function Get-InstalledFeatures {
      try { Get-WindowsFeature | Where-Object Installed }
      catch { @() }
    }

    function Detect-Stacks {
      $browsers = @()
      if (Test-Path "$env:ProgramFiles\Mozilla Firefox\firefox.exe") { $browsers += 'Firefox' }
      if (Test-Path "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe" -or
          Test-Path "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") { $browsers += 'Edge' }
      if (Test-Path "$env:ProgramFiles\Google\Chrome\Application\chrome.exe" -or
          Test-Path "$env:ProgramFiles (x86)\Google\Chrome\Application\chrome.exe") { $browsers += 'Chrome' }

      $web = @()
      if (Get-Service -Name W3SVC -ErrorAction SilentlyContinue) { $web += 'IIS' }
      if (Test-Path "C:\xampp") { $web += 'Apache' }
      if (Test-Path "C:\Apache24") { $web += 'Apache' }

      $php = Test-Path "C:\xampp\php\php.ini" -or Test-Path "C:\PHP\php.ini"
      $mysql = Get-Service -Name mysql*,mariadb* -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } | Select-Object -First 1
      $filezilla = Get-Service -Name *filezilla* -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } | Select-Object -First 1
      $rdp = Get-Service -Name TermService -ErrorAction SilentlyContinue

      [pscustomobject]@{
        Browsers = $browsers
        Web      = $web
        PHP      = [bool]$php
        MySQL    = [bool]$mysql
        FileZilla= [bool]$filezilla
        RDP      = [bool]$rdp
      }
    }

    Export-ModuleMember -Function Get-OSProfile,Get-Role,Get-InstalledFeatures,Detect-Stacks

