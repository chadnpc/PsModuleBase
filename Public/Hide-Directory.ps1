function Hide-Directory {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Path = $PWD
  )

  begin {
  }

  process {
    $attributes = (Get-Item $Path -Force).Attributes
    $attributes = $attributes -bor [System.IO.FileAttributes]::Hidden
    $attributes = $attributes -bor [System.IO.FileAttributes]::System
    $attributes = $attributes -bxor [System.IO.FileAttributes]::Directory
    Set-ItemProperty -Path $Path -Name Attributes -Value $attributes -Force
  }

  end {
  }
}