function Unprotect-Document {
  # .SYNOPSIS
  #   Decrypts data or file encrypted with PsModuleBase for the current user. (Wrapper for [PsModuleBase]::UnprotectDataset)
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", "")] # Write-Host is used by called method for feedback
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory = $true, ParameterSetName = 'File', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('FullName')]
    [string[]]$Path,

    [Parameter(Mandatory = $true, ParameterSetName = 'Content', ValueFromPipelineByPropertyName = $true)]
    [string]$Content,

    [ValidateScript({
        # Allow OutPath not existing if Type=Content, but require it to be a dir if it exists
        # If Type=File, it MUST exist and be a dir. This validation is better done inside the process block.
        if (Test-Path $_) { Test-Path $_ -PathType Container } else { $true }
      })]
    [string]$OutPath
  )

  process {
    if ($PSCmdlet.ParameterSetName -eq 'Content') {
      Write-Verbose "Attempting to unprotect content..."
      # Validate OutPath if provided for content
      if ($OutPath -and !(Test-Path -LiteralPath $OutPath -PathType Container)) {
        $PSCmdlet.WriteError( (New-ErrorRecord -Message "Output directory specified by -OutPath does not exist: '$OutPath'" -ErrorId 'OutPathNotFoundContent' -Category ObjectNotFound -TargetObject $OutPath) )
        return # Stop processing this content item
      }
      try {
        # Pass $PSCmdlet for error writing context
        $decryptedContentOrPath = [PsModuleBase]::UnprotectDataset($Content, $OutPath, $PSCmdlet)
        # Output depends on whether OutPath was used for content
        if ($OutPath) {
          # If OutPath was used, method returns null on success (file written) or error
          # If it returns a path, it means it wrote the file
          if ($null -eq $decryptedContentOrPath) {
            # Check if an error was written by the method, otherwise assume success but no output needed
          } else {
            # Should not happen if OutPath was specified for content, but handle defensively
            # Write-Output $decryptedContentOrPath
          }
        } elseif ($null -ne $decryptedContentOrPath) {
          # No OutPath, method returns decrypted string
          Write-Output $decryptedContentOrPath
        }
        # Errors are written by UnprotectDataset via $PSCmdlet.WriteError
      } catch {
        # Catch unexpected errors in the wrapper itself
        $PSCmdlet.WriteError($_)
      }
    } elseif ($PSCmdlet.ParameterSetName -eq 'File') {
      # Use Resolve-PathEx carefully or replace with simpler Resolve-Path if sufficient
      foreach ($fileInfo in Resolve-PathEx -Path $Path -Type File -Mode AnyWarning -Provider FileSystem) {
        if ($fileInfo.Success) {
          foreach ($resolvedPath in $fileInfo.Path) {
            # Determine root output directory
            $outputDirectory = $OutPath # Use explicit OutPath if provided
            if (!$outputDirectory) {
              # Default to same directory as input file
              $outputDirectory = Split-Path -Path $resolvedPath -Parent
            }

            # Ensure output directory exists
            if (!(Test-Path -LiteralPath $outputDirectory -PathType Container)) {
              $PSCmdlet.WriteError( (New-ErrorRecord -Message "Output directory does not exist: '$outputDirectory' for input file '$resolvedPath'" -ErrorId 'OutPathNotFoundFile' -Category ObjectNotFound -TargetObject $outputDirectory) )
              continue # Skip this file
            }

            Write-Verbose "Unprotecting file: $resolvedPath to directory $outputDirectory"
            try {
              $jsonFileContent = [System.IO.File]::ReadAllText($resolvedPath)
              # Pass $PSCmdlet for error writing context
              # UnprotectDataset will handle writing the file and Write-Host output
              $unprotectedFilePath = [PsModuleBase]::UnprotectDataset($jsonFileContent, $outputDirectory, $PSCmdlet)
              # Optionally output the path of the created file
              if ($unprotectedFilePath) { Write-Output $unprotectedFilePath }
              # Errors are written by UnprotectDataset via $PSCmdlet.WriteError
            } catch {
              # Catch errors from file reading or unexpected wrapper errors
              $PSCmdlet.WriteError($_)
            }
          }
        } else {
          $PSCmdlet.WriteWarning("Could not resolve or access path: $($fileInfo.Input). Message: $($fileInfo.Message)")
        }
      }
    }
  }
}