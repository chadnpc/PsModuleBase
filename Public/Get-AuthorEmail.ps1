function Get-AuthorEmail {
  [CmdletBinding()]
  param (
    [Parameter(Position = 0, Mandatory = $false)]
    [Alias('n')][AllowNull()]
    [string]$ModuleName
  )

  begin {
    $ae = "";
  }

  process {
    if ([string]::IsNullOrWhiteSpace($ModuleName)) {
      trap {
        Write-Warning "Running {$c} is not possible, so I assume your email is `"`$([Environment]::UserName)@gmail.com`""
        $ae = "$([Environment]::UserName)@gmail.com"
      }
      $c = { git config --get user.email }
      if ($null -ne (Get-Command git -CommandType Application -ea Ignore)) {
        $ae = $c.Invoke()
      }
    } else {
      throw [System.NotImplementedException]::new("WIP")
    }
  }

  end {
    return $ae
  }
}