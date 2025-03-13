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
  begin {
    if (![IO.Directory]::Exists($Source)) { [string]$Source = Resolve-Path $Source -ea Stop }
    if (!$PSCmdlet.MyInvocation.BoundParameters.ContainsKey('File')) {
      $File = [IO.Path]::Combine($Source, (Get-Culture).Name, "$([IO.DirectoryInfo]::New($Source).BaseName).strings.psd1");
    }; $File = Resolve-Path $File;
  }
  process {
    if ($PSCmdlet.ParameterSetName -eq "ModuleName") {
      $_res = [PsModuleBase]::ReadModuledata($Module, $Property)
    } else {
      $data = [scriptblock]::Create("$([IO.File]::ReadAllText($File))").Invoke()
      $_res = [string]::IsNullOrWhiteSpace($Property) ? $data : $data.$Property
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