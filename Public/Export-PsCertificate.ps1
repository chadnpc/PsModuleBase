function Export-PsCertificate {
  # .SYNOPSIS
  #   Creates an export of your own PsModuleBase certificate (public key only). (Wrapper for [PsModuleBase]::ExportCertificatePublicKey)

  # .NOTES
  #   The file dialog prompt via Show-SaveFileDialog only works on Windows with Desktop GUI environment.
  #   Use -Path or -PassThru for cross-platform/non-interactive scenarios.
  [CmdletBinding()]
  param (
    [string]
    $Path,

    [switch]
    $PassThru
  )

  begin {
    $jsonData = $null
    try {
      # Call the static method to get the JSON data
      $jsonData = [PsModuleBase]::ExportCertificatePublicKey()
    } catch {
      # Throw terminating error if export failed (e.g., no cert found)
      $PSCmdlet.ThrowTerminatingError($_)
      return # Stop execution
    }

    # Handle output based on parameters (Keep UI logic here)
    if ($PassThru) {
      # Return json string directly
      Write-Output $jsonData
    } elseif ($Path) {
      # Write to specified file path
      try {
        [System.IO.File]::WriteAllText($Path, $jsonData, [System.Text.Encoding]::UTF8)
        Write-Verbose "Certificate exported to $Path"
      } catch {
        $PSCmdlet.WriteError( (New-ErrorRecord -ErrorId FileWriteError -Category WriteError -Message "Failed to write export file '$Path': $($_.Exception.Message)" -TargetObject $Path -Exception $_.Exception) )
      }
    } else {
      # Use UI prompt (Windows specific)
      if ($IsWindows) {
        # Ensure the private helper function is available
        # Consider moving Show-SaveFileDialog to the main psm1 or making it public if used often
        # Assuming it's dot-sourced or available in the session:
        try {
          $selectedPath = Show-SaveFileDialog -Filter 'Json Files (*.json)|*.json' -InitialDirectory .
          if ($selectedPath) {
            [System.IO.File]::WriteAllText($selectedPath, $jsonData, [System.Text.Encoding]::UTF8)
            Write-Verbose "Certificate exported to $selectedPath"
          } else {
            Write-Warning "Export cancelled by user."
          }
        } catch {
          # Handle cases where Show-SaveFileDialog isn't available or fails
          $PSCmdlet.WriteError( (New-ErrorRecord -ErrorId FileDialogError -Category OperationStopped -Message "Failed to show save file dialog or write file. Use -Path or -PassThru instead. Error: $($_.Exception.Message)" -TargetObject $null -Exception $_.Exception) )
        }
      } else {
        # Error on non-windows if no path/passthru specified
        $PSCmdlet.WriteError( (New-ErrorRecord -ErrorId NoPathSpecified -Category InvalidArgument -Message "On non-Windows systems, you must specify the -Path parameter or use -PassThru.") )
      }
    }
  }
  # Process block is empty as logic moved to begin for early exit on export failure
  process {}
}