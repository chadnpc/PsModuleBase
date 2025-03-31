function Get-LocalModule {
  # .SYNOPSIS
  # Gets basic details of an Installed Psmodule
  # .DESCRIPTION
  # Its like using Get-InstalledModule but you can even find unregistered/"manually Installed" modules. (as long as they are in any of $env:PSModulePath folders)
  # .EXAMPLE
  # Get-LocalModule psake | Select-Object -ExpandProperty Path | Import-Module -Verbose
  [CmdletBinding()]
  [OutputType([LocalPsModule])]
  param (
    # The name of the installed modul to search on the machine.
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
        [OutputType([System.Management.Automation.CompletionResult])]
        param(
          [string] $CommandName,
          [string] $ParameterName,
          [string] $WordToComplete,
          [System.Management.Automation.Language.CommandAst] $CommandAst,
          [System.Collections.IDictionary] $FakeBoundParameters
        )
        $CompletionResults = [System.Collections.Generic.List[CompletionResult]]::new()
        $matchingNames = [LocalPsModule]::new().GetValidValues().Where({ $_ -like "$WordToComplete*" })
        foreach ($n in $matchingNames) { $CompletionResults.Add([System.Management.Automation.CompletionResult]::new($n)) }
        return $CompletionResults
      })]
    [string]$Name,

    # The required module version. You don't use this parameter,
    # then this cmdlet will search for the highest version from the specified scope.
    [Parameter(Mandatory = $false, Position = 1)]
    [ValidateNotNullOrEmpty()]
    [version]$version,

    # If you don't use this parameter then, this cmdlet uses LocalMachine as a default scope.
    [Parameter(Mandatory = $false, Position = 2)]
    [ValidateSet('CurrentUser', 'LocalMachine')]
    [string]$Scope
  )
  begin {
    $PsModule = $null
  }
  process {
    $PsModule = switch ($true) {
      $($PSBoundParameters.ContainsKey('version') -and $PSBoundParameters.ContainsKey('Scope')) { New-Object LocalPsModule($Name, $Scope, $version) ; break }
      $($PSBoundParameters.ContainsKey('version') -and !$PSBoundParameters.ContainsKey('Scope')) { New-Object LocalPsModule($Name, 'LocalMachine', $version) ; break }
      $(!$PSBoundParameters.ContainsKey('version') -and $PSBoundParameters.ContainsKey('Scope')) { New-Object LocalPsModule($Name, $Scope, $version) ; break }
      $(!$PSBoundParameters.ContainsKey('version') -and !$PSBoundParameters.ContainsKey('Scope')) { New-Object LocalPsModule($Name) ; break }
      Default { New-Object LocalPsModule($Name) }
    }
  }
  end {
    return $PsModule
  }
}