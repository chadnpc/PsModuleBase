function Get-ModuleDetails {
  # .SYNOPSIS
  #   Displays detailed information about a specified module.
  # .DESCRIPTION
  #   A longer description of the function, its purpose, common use cases, etc.
  # .NOTES
  #   Information or caveats about the function e.g. 'This function is not supported in Linux'
  # .LINK
  #   Show-ModuleInfo: Provides a more user-friendly view of module details.
  # .EXAMPLE
  #   Get-ModuleDetails cliHelper.env
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrWhiteSpace()]
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
    [string]$Name
  )

  begin {
  }

  process {
  }

  end {
  }
}