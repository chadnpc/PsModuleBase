function Get-ModulePath {
  # .DESCRIPTION
  #  Gets the path of installed modul; a path you can use with Import-module.
  # .EXAMPLE
  # Get-ModulePath -Name posh-git -version 0.7.3 | Import-module -verbose
  # Will retrieve posh-git version 0.7.3 from $env:PSModulePath and import it.
  [CmdletBinding()][OutputType([string])]
  param(
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
    [string]$Name,

    [Parameter(Mandatory = $false, Position = 1)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (!($_ -as 'version' -is [version])) {
          throw [System.ArgumentException]::New('Please Provide a valid version string')
        }; $true
      }
    )]
    [string]$version,

    [Parameter(Mandatory = $false, Position = 2)]
    [ValidateSet('LocalMachine', 'CurrentUser')]
    [string]$Scope = 'LocalMachine'
  )
  if ($PSBoundParameters.ContainsKey('version')) {
    return (Find-InstalledModule -Name $Name -Version ([version]::New($version)) -Scope $Scope).Path
  } else {
    return (Find-InstalledModule -Name $Name -Scope $Scope).Path
  }
}