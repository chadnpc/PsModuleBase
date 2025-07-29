function Get-ModuleDetails {
  # .SYNOPSIS
  #   Displays detailed information about a specified module.
  # .DESCRIPTION
  #   This function provides comprehensive detailed information about a PowerShell module,
  #   including manifest data, file structure, dependencies, and exported functions.
  #   It returns structured data that can be used programmatically or displayed in detail.
  # .PARAMETER Name
  #   The name of the module to get details for.
  # .PARAMETER Version
  #   Optional specific version of the module. If not specified, uses the latest version.
  # .PARAMETER Scope
  #   The installation scope to search in. Defaults to LocalMachine if not specified.
  # .PARAMETER IncludeFiles
  #   Include detailed file information in the output.
  # .PARAMETER IncludeFunctions
  #   Include detailed function information in the output.
  # .NOTES
  #   This function leverages the LocalPsModule class and PsModuleBase utilities
  #   to provide comprehensive module analysis.
  # .LINK
  #   Show-ModuleInfo: Provides a more user-friendly view of module details.
  # .EXAMPLE
  #   Get-ModuleDetails -Name "PsModuleBase"
  #   Gets detailed information for the PsModuleBase module.
  # .EXAMPLE
  #   Get-ModuleDetails -Name "MyModule" -Version "1.0.0" -IncludeFiles -IncludeFunctions
  #   Gets comprehensive details including files and functions for version 1.0.0 of MyModule.
  # .OUTPUTS
  #   PSCustomObject with detailed module information
  [CmdletBinding()]
  # [OutputType([PSCustomObject])]
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
    [string]$Name,

    [Parameter(Mandatory = $false, Position = 1)]
    [ValidateNotNullOrEmpty()]
    [version]$Version,

    [Parameter(Mandatory = $false, Position = 2)]
    [ValidateSet('CurrentUser', 'LocalMachine')]
    [string]$Scope = 'LocalMachine',

    [Parameter(Mandatory = $false)]
    [switch]$IncludeFiles,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeFunctions
  )

  begin {
    Write-Verbose "Starting Get-ModuleDetails for module: $Name"
  }

  process {
    try {
      # Create LocalPsModule object based on provided parameters
      $moduleObj = if ($PSBoundParameters.ContainsKey('Version') -and $PSBoundParameters.ContainsKey('Scope')) {
        [LocalPsModule]::new($Name, $Scope, $Version)
      } elseif ($PSBoundParameters.ContainsKey('Version')) {
        [LocalPsModule]::new($Name, $Version)
      } elseif ($PSBoundParameters.ContainsKey('Scope')) {
        [LocalPsModule]::new($Name, $Scope)
      } else {
        [LocalPsModule]::new($Name)
      }

      if (-not $moduleObj.Exists) {
        $errorMessage = "Module '$Name' not found"
        if ($PSBoundParameters.ContainsKey('Version')) {
          $errorMessage += " with version '$Version'"
        }
        if ($PSBoundParameters.ContainsKey('Scope')) {
          $errorMessage += " in scope '$Scope'"
        }
        Write-Error $errorMessage -ErrorAction Stop
      }

      # Build detailed module information object
      $moduleDetails = [PSCustomObject]@{
        Name             = $moduleObj.Name
        Version          = $moduleObj.Version
        Path             = $moduleObj.Path.FullName
        ManifestPath     = $moduleObj.Psd1.FullName
        Scope            = $moduleObj.Scope
        Exists           = $moduleObj.Exists
        IsReadOnly       = $moduleObj.IsReadOnly
        HasVersionDirs   = $moduleObj.HasVersiondirs
        ManifestInfo     = $null
        Files            = $null
        Functions        = $null
        Dependencies     = $null
        ExportedCommands = $null
        Size             = $null
        LastModified     = $null
      }

      # Add manifest information if available
      if ($null -ne $moduleObj.Info) {
        $moduleDetails.ManifestInfo = $moduleObj.Info

        # Extract dependencies
        if ($moduleObj.Info.PSObject.Properties.Name -contains 'RequiredModules' -and $null -ne $moduleObj.Info.RequiredModules) {
          $moduleDetails.Dependencies = $moduleObj.Info.RequiredModules
        }

        # Extract exported commands
        $exportedCommands = @{}
        if ($moduleObj.Info.PSObject.Properties.Name -contains 'FunctionsToExport' -and $null -ne $moduleObj.Info.FunctionsToExport) {
          $exportedCommands.Functions = $moduleObj.Info.FunctionsToExport
        }
        if ($moduleObj.Info.PSObject.Properties.Name -contains 'CmdletsToExport' -and $null -ne $moduleObj.Info.CmdletsToExport) {
          $exportedCommands.Cmdlets = $moduleObj.Info.CmdletsToExport
        }
        if ($moduleObj.Info.PSObject.Properties.Name -contains 'AliasesToExport' -and $null -ne $moduleObj.Info.AliasesToExport) {
          $exportedCommands.Aliases = $moduleObj.Info.AliasesToExport
        }
        $moduleDetails.ExportedCommands = $exportedCommands
      }

      # Add file information if requested
      if ($IncludeFiles -and $moduleObj.Path.Exists) {
        try {
          $files = Get-ChildItem -Path $moduleObj.Path.FullName -Recurse -File -ErrorAction SilentlyContinue
          $moduleDetails.Files = $files | Select-Object Name, FullName, Length, LastWriteTime, Extension | Sort-Object FullName

          # Calculate total size
          $totalSize = ($files | Measure-Object -Property Length -Sum).Sum
          $moduleDetails.Size = if ($totalSize -gt 1MB) {
            "{0:N2} MB" -f ($totalSize / 1MB)
          } elseif ($totalSize -gt 1KB) {
            "{0:N2} KB" -f ($totalSize / 1KB)
          } else {
            "$totalSize bytes"
          }

          # Get last modified date
          $moduleDetails.LastModified = ($files | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
        } catch {
          Write-Warning "Could not retrieve file information: $($_.Exception.Message)"
        }
      }

      # Add function information if requested
      if ($IncludeFunctions -and $moduleObj.Path.Exists) {
        try {
          $functionFiles = Get-ChildItem -Path $moduleObj.Path.FullName -Recurse -Filter "*.ps1" -ErrorAction SilentlyContinue
          $functions = @()

          foreach ($file in $functionFiles) {
            try {
              $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
              if ($content -match 'function\s+([^\s\{]+)') {
                $functionName = $matches[1]

                # Extract synopsis if available
                $synopsis = ""
                if ($content -match '\.SYNOPSIS\s*\n\s*#\s*(.+)') {
                  $synopsis = $matches[1].Trim()
                }

                $functions += [PSCustomObject]@{
                  Name     = $functionName
                  File     = $file.Name
                  FilePath = $file.FullName
                  Synopsis = $synopsis
                }
              }
            } catch {
              Write-Verbose "Could not parse function from file: $($file.FullName)"
            }
          }

          $moduleDetails.Functions = $functions | Sort-Object Name
        } catch {
          Write-Warning "Could not retrieve function information: $($_.Exception.Message)"
        }
      }

      Write-Verbose "Successfully retrieved module details for: $Name"
      return $moduleDetails
    } catch {
      Write-Error "Failed to retrieve module details for '$Name': $($_.Exception.Message)" -ErrorAction Stop
    }
  }

  end {
    Write-Verbose "Completed Get-ModuleDetails for module: $Name"
  }
}