function Search-Module {
  <#
  .SYNOPSIS
    Broader function to search specific repositories for modules.
  .DESCRIPTION
    Searches for modules in the specified repositories (local or online)
  #>
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