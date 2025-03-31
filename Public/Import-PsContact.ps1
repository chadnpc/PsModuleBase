function Import-PsContact {
  # .SYNOPSIS
  #   Imports contact information needed to send encrypted data. (Wrapper for [PsModuleBase]::ImportContactData)
  # .NOTES
  #   Reads from clipboard if no -Path or -Content is provided (interactive feature).
  [CmdletBinding()]
  Param (
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('FullName')]
    [string[]]
    $Path,

    [string]
    $Content,

    [switch]
    $TrustedOnly
  )

  process {
    $jsonToProcess = [System.Collections.Generic.List[string]]::new()

    # Prioritize Content parameter
    if ($Content) {
      $jsonToProcess.Add($Content)
    }
    # Then process Path parameter
    elseif ($Path) {
      foreach ($file in Resolve-PathEx -Path $Path -Type File -Mode AnyWarning -Provider FileSystem) {
        if ($file.Success) {
          foreach ($filePath in $file.Path) {
            Write-Verbose "Reading contact data from: $filePath"
            try {
              $text = [System.IO.File]::ReadAllText($filePath)
              $jsonToProcess.Add($text)
            } catch {
              $PSCmdlet.WriteError( (New-ErrorRecord -ErrorId FileReadError -Category ReadError -Message "Failed to read contact file '$filePath': $($_.Exception.Message)" -TargetObject $filePath -Exception $_.Exception) )
            }
          }
        } else {
          $PSCmdlet.WriteWarning("Could not resolve or access path: $($file.Input). Message: $($file.Message)")
        }
      }
    }
    # Finally, try clipboard if nothing else was provided
    elseif (!$PSBoundParameters.ContainsKey('Content') -and !$PSBoundParameters.ContainsKey('Path')) {
      Write-Verbose "No -Path or -Content provided, attempting to read from clipboard."
      try {
        # Get-Clipboard might not be available everywhere (e.g., server core, PS remote session without UI)
        if (Get-Command Get-Clipboard -ErrorAction SilentlyContinue) {
          $clipboardContent = (Get-Clipboard) -join "`n"
          if ($clipboardContent) {
            $jsonToProcess.Add($clipboardContent)
          } else {
            Write-Warning "Clipboard is empty or could not be read."
          }
        } else {
          Write-Warning "Get-Clipboard command not available in this session."
        }
      } catch {
        $PSCmdlet.WriteError( (New-ErrorRecord -ErrorId ClipboardError -Category ReadError -Message "Failed to read from clipboard: $($_.Exception.Message)" -TargetObject $null -Exception $_.Exception) )
      }
    }

    # Check if we have anything to import
    if ($jsonToProcess.Count -eq 0) {
      Write-Verbose "No contact data found to import."
      return
    }

    # Process collected JSON data
    foreach ($jsonData in $jsonToProcess) {
      try {
        # Call the static method
        $importedContact = [PsModuleBase]::ImportContactData($jsonData, $TrustedOnly)
        # Output the successfully imported contact object
        Write-Output $importedContact
      } catch {
        # Write non-terminating error for each failed import
        $PSCmdlet.WriteError($_)
      }
    }
  }
}