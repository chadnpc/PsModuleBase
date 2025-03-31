function Get-PsCertificate {
  # .SYNOPSIS
  #   Retrieves PsModuleBase certificates. (Wrapper for [PsModuleBase]::GetCertificate)
  [CmdletBinding()]
  param (
    [switch]
    $Current
  )

  process {
    # Call the static method
    $certificates = [PsModuleBase]::GetCertificate($Current)

    # Format output as PSCustomObject like before for consistency
    $certificates | ForEach-Object {
      [PSCustomObject]@{
        PSTypeName  = 'PsModuleBase.Certificate'
        Subject     = $_.Subject
        NotAfter    = $_.NotAfter
        Thumbprint  = $_.Thumbprint
        Certificate = $_ # Include the full object
      }
    }
  }
}