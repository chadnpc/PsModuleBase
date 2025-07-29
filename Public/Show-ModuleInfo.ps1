function Show-ModuleInfo {
  # .SYNOPSIS
  #   Provides a more user-friendly view of module details.
  # .DESCRIPTION
  #   This function displays comprehensive information about a PowerShell module in a user-friendly format.
  #   It leverages the LocalPsModule class to retrieve and present module details including version,
  #   path, manifest information, and installation scope.
  # .PARAMETER Name
  #   The name of the module to display information for.
  # .PARAMETER Version
  #   Optional specific version of the module to display. If not specified, shows the latest version.
  # .PARAMETER Scope
  #   The installation scope to search in. Defaults to LocalMachine if not specified.
  # .EXAMPLE
  #   Show-ModuleInfo -Name "PsModuleBase"
  #   Displays information for the PsModuleBase module.
  # .EXAMPLE
  #   Show-ModuleInfo -Name "MyModule" -Version "1.0.0" -Scope CurrentUser
  #   Displays information for version 1.0.0 of MyModule from CurrentUser scope.
  # .OUTPUTS
  #   LocalPsModule object with formatted display
  [CmdletBinding()]
  # [OutputType([LocalPsModule])]
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
    [string]$Scope = 'LocalMachine'
  )

  begin {
    Write-Verbose "Starting Show-ModuleInfo for module: $Name"
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

      # Display formatted module information
      Write-Host "`n=== Module Information ===" -ForegroundColor Cyan
      Write-Host "Name:         " -NoNewline -ForegroundColor Yellow
      Write-Host $moduleObj.Name -ForegroundColor White

      Write-Host "Version:      " -NoNewline -ForegroundColor Yellow
      Write-Host $moduleObj.Version -ForegroundColor White

      Write-Host "Path:         " -NoNewline -ForegroundColor Yellow
      Write-Host $moduleObj.Path.FullName -ForegroundColor White

      Write-Host "Manifest:     " -NoNewline -ForegroundColor Yellow
      Write-Host $moduleObj.Psd1.FullName -ForegroundColor White

      Write-Host "Scope:        " -NoNewline -ForegroundColor Yellow
      Write-Host $moduleObj.Scope -ForegroundColor White

      Write-Host "Exists:       " -NoNewline -ForegroundColor Yellow
      $existsColor = if ($moduleObj.Exists) { "Green" } else { "Red" }
      Write-Host $moduleObj.Exists -ForegroundColor $existsColor

      Write-Host "Read-Only:    " -NoNewline -ForegroundColor Yellow
      $readOnlyColor = if ($moduleObj.IsReadOnly) { "Red" } else { "Green" }
      Write-Host $moduleObj.IsReadOnly -ForegroundColor $readOnlyColor

      Write-Host "Has Version Dirs: " -NoNewline -ForegroundColor Yellow
      Write-Host $moduleObj.HasVersiondirs -ForegroundColor White

      # Display manifest information if available
      if ($null -ne $moduleObj.Info) {
        Write-Host "`n=== Manifest Details ===" -ForegroundColor Cyan

        $manifestProps = @('Author', 'CompanyName', 'Copyright', 'Description', 'GUID', 'PowerShellVersion', 'RequiredModules', 'FunctionsToExport')
        foreach ($prop in $manifestProps) {
          if ($moduleObj.Info.PSObject.Properties.Name -contains $prop -and $null -ne $moduleObj.Info.$prop) {
            Write-Host "$($prop):".PadRight(18) -NoNewline -ForegroundColor Yellow
            if ($prop -eq 'RequiredModules' -and $moduleObj.Info.$prop -is [array]) {
              Write-Host ($moduleObj.Info.$prop -join ', ') -ForegroundColor White
            } elseif ($prop -eq 'FunctionsToExport' -and $moduleObj.Info.$prop -is [array]) {
              $functions = $moduleObj.Info.$prop
              if ($functions.Count -gt 5) {
                Write-Host "$($functions[0..4] -join ', '), ... (and $($functions.Count - 5) more)" -ForegroundColor White
              } else {
                Write-Host ($functions -join ', ') -ForegroundColor White
              }
            } else {
              Write-Host $moduleObj.Info.$prop -ForegroundColor White
            }
          }
        }
      }
      Write-Host "`n=========================" -ForegroundColor Cyan
      return $moduleObj
    } catch {
      Write-Error "Failed to retrieve module information for '$Name': $($_.Exception.Message)" -ErrorAction Stop
    }
  }

  end {
    Write-Verbose "Completed Show-ModuleInfo for module: $Name"
  }
}