function Read-ModuleData {
  # .SYNOPSIS
  #   Reads a specific value from a PowerShell metdata file (e.g. a module manifest)
  # .DESCRIPTION
  #   By default Get-ModuleManifest gets all keys in the metadata file
  # .LINK
  #   https://github.com/chadnpc/PsCraft/blob/main/Public/Read-ModuleData.ps1
  # .EXAMPLE
  #   Read-ModuleData .
  #   Reads the Moduledata from the current directory, assumes that the module name is the same as the directory name
  [CmdletBinding(ConfirmImpact = 'None', DefaultParameterSetName = 'ModuleName')]
  [OutputType([PsObject])]
  param (
    [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = 'ModuleName')]
    [ValidateNotNullOrWhiteSpace()][Alias('m')][string]
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
    $Module = $PSScriptRoot,

    [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = 'File')]
    [ValidateNotNullOrWhiteSpace()][Alias('f')][string]
    $File,

    [Parameter(Position = 1, Mandatory = $false)]
    [AllowNull()][string]
    $Property,

    [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'File')]
    [ValidateScript({
        $p = (Resolve-Path $_ -ea Ignore)
        if ((Test-Path -Path $p -PathType Container -ea Ignore)) {
          return $true
        } else {
          throw [System.ArgumentException]::new("directory '$_' does not exist.", 'Path')
        }
      }
    )][Alias('Path')][string]
    $Source = (Resolve-Path .).Path,

    [switch]$NoNullResult
  )

  process {
    if ($PSCmdlet.ParameterSetName -eq 'File') {
      if (![IO.Directory]::Exists($Source)) { [string]$Source = Resolve-Path $Source -ea Stop }
      if (!$PSCmdlet.MyInvocation.BoundParameters.ContainsKey('File')) {
        $File = [IO.Path]::Combine($Source, (Get-Culture).Name, "$([IO.DirectoryInfo]::New($Source).BaseName).strings.psd1");
      }; $File = Resolve-Path $File;

      $data = [scriptblock]::Create("$([IO.File]::ReadAllText($File))").Invoke()
      $_res = [string]::IsNullOrWhiteSpace($Property) ? $data : $data.$Property
    } else {
      $_res = [PsModuleBase]::ReadModuledata($Module, $Property)
    }
    if ($null -eq $_res -and $NoNullResult) {
      $Error_params = @{
        ExceptionName    = "System.Management.Automation.ItemNotFoundException"
        ExceptionMessage = "Can't find '$Property' in $File"
        ErrorId          = "PropertyNotFound,Metadata\Get-Metadata"
        Caller           = $PSCmdlet
        ErrorCategory    = "ObjectNotFound"
      }
      Write-TerminatingError @Error_params
    }
    return $_res
  }
}