function Get-AuthorName {
  [CmdletBinding()][OutputType([string])]
  param (
    [Parameter(Position = 0, Mandatory = $false)]
    [Alias('n')][AllowNull()]
    [string]$ModuleName
  )

  begin {
    $an = '';
  }

  process {
    if ([string]::IsNullOrWhiteSpace($ModuleName)) {
      trap {
        $os = [PsModuleBase]::GetHostOs()
        $an = switch ($true) {
          $($os -eq "Windows") {
            Get-CimInstance -ClassName Win32_UserAccount -Verbose:$false | Where-Object { [Environment]::UserName -eq $_.Name } | Select-Object -ExpandProperty FullName
            break
          }
          $($os -in ("MacOSX", "Linux")) {
            $s = getent passwd "$([Environment]::UserName)"
            $s.Split(":")[4]
            break
          }
          Default {
            Write-Warning -Message "$([Environment]::OSVersion.Platform) OS is Not supported!"
          }
        }
      }
      $an = ''; if ($null -ne (Get-Command git -CommandType Application -ea Ignore)) {
        $an = git config --get user.name;
      }
      if ([string]::IsNullOrWhiteSpace($an)) {
        $an = [Environment]::GetEnvironmentVariable('USER')
      }
    } else {
      throw [System.NotImplementedException]::new("WIP")
    }
  }

  end {
    return $an
  }
}