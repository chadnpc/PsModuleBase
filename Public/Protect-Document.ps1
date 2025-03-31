function Protect-Document {
  # .SYNOPSIS
  #   Encrypt a document for a specific recipient and sign it. (Wrapper for [PsModuleBase] methods)
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", "")] # Write-Host is used by called method for feedback
  [CmdletBinding(DefaultParameterSetName = 'File')]
  Param (
    [Parameter(Mandatory = $true)]
    [string]$Recipient, # Name or Thumbprint of the contact

    [Parameter(Mandatory = $true, ParameterSetName = 'File', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('FullName')]
    [string[]]$Path,

    [Parameter(Mandatory = $true, ParameterSetName = 'Content', ValueFromPipelineByPropertyName = $true)]
    [string]$Content,

    [Parameter(ParameterSetName = 'Content', ValueFromPipelineByPropertyName = $true)]
    [string]$Name = "$([guid]::NewGuid())-$(Get-Date -Format yyyy-MM-dd)",

    [Parameter(ParameterSetName = 'File')]
    [switch]$PassThru,

    [Parameter(ParameterSetName = 'File')]
    [ValidateScript({ Test-Path -Path $_ -PathType Container })] # Ensure OutPath is an existing directory
    [string]$OutPath
  )

  begin {
    # Get own certificate (signing key)
    $ownCertificate = @([PsModuleBase]::GetCertificate($true))[0]
    if (!$ownCertificate) {
      $PSCmdlet.ThrowTerminatingError( (New-ErrorRecord -Message 'No applicable user certificate found! Use New-PsCertificate or Set-PsCertificate first.' -ErrorId 'OwnCertNotFound' -Category ObjectNotFound) )
      return # Stop
    }
    Write-Verbose "Using own certificate for signing: $($ownCertificate.Subject)"

    # Get recipient contact certificate (encryption key)
    $contact = @([PsModuleBase]::GetContact($Recipient) | Sort-Object NotAfter -Descending | Select-Object -First 1)[0]
    if (!$contact) {
      $PSCmdlet.ThrowTerminatingError( (New-ErrorRecord -Message "Contact '$Recipient' not found! Use Get-PsContact to list contacts or Import-PsContact to add them. Sender must use Export-PsCertificate." -ErrorId 'ContactNotFound' -Category ObjectNotFound -TargetObject $Recipient) )
      return # Stop
    }
    Write-Verbose "Using contact certificate for encryption: $($contact.Certificate.Subject)"

    # Validate OutPath if provided
    if ($PSBoundParameters.ContainsKey('OutPath')) {
      if (!(Test-Path -LiteralPath $OutPath -PathType Container)) {
        $PSCmdlet.ThrowTerminatingError( (New-ErrorRecord -Message "Output directory specified by -OutPath does not exist: '$OutPath'" -ErrorId 'OutPathNotFound' -Category ObjectNotFound -TargetObject $OutPath) )
        return # Stop
      }
    }
  }
  process {
    try {
      switch ($PSCmdlet.ParameterSetName) {
        'File' {
          $results = [System.Collections.Generic.List[string]]::new()
          # Use Resolve-PathEx carefully or replace with simpler Resolve-Path if sufficient
          foreach ($fileInfo in Resolve-PathEx -Path $Path -Type File -Mode AnyWarning -Provider FileSystem) {
            if ($fileInfo.Success) {
              foreach ($resolvedPath in $fileInfo.Path) {
                Write-Verbose "Protecting file: $resolvedPath"
                $resultJson = [PsModuleBase]::ProtectFile($resolvedPath, $ownCertificate, $contact, $OutPath, $PassThru)
                if ($PassThru) { $results.Add($resultJson) }
              }
            } else {
              $PSCmdlet.WriteWarning("Could not resolve or access path: $($fileInfo.Input). Message: $($fileInfo.Message)")
            }
          }
          if ($PassThru) { Write-Output $results }
        }
        'Content' {
          Write-Verbose "Protecting content named: $Name"
          $resultJson = [PsModuleBase]::ProtectContent($Content, $Name, $ownCertificate, $contact)
          Write-Output $resultJson
        }
      }
    } catch {
      # Catch errors from the static methods or path resolution
      $PSCmdlet.WriteError($_) # Write as non-terminating for pipeline input
    }
  }
}