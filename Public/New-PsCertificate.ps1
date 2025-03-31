function New-PsCertificate {
  # .SYNOPSIS
  #     Generate a new certificate to use as your own PsModuleBase certificate. (Wrapper for [PsModuleBase]::CreateCertificate)
  # .NOTES
  #     Attempts to read username from Teams registry key on Windows if Name is not provided. This auto-detection is platform-specific.
  #     It's recommended to explicitly provide the -Name parameter for cross-platform reliability.
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
  [CmdletBinding()]
  param (
    [string]$Name
  )

  begin {
    if (!$Name) {
      # Platform-specific fallback (Keep outside the core class method)
      if ($IsWindows) {
        try {
          $Name = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\Teams' -ErrorAction SilentlyContinue).HomeUserUpn
        } catch {
          Write-Warning "Could not auto-detect name from Teams registry key."
        }
      }
      # Alternative fallback (e.g., UserPrincipalName if in domain, or $env:USERNAME)
      if (!$Name -and $env:USERPRINCIPALNAME) { $Name = $env:USERPRINCIPALNAME }
      if (!$Name) { $Name = $env:USERNAME }

      if (!$Name) {
        throw "Could not automatically determine a name. Please specify the -Name parameter (e.g., your email address)."
      }
      Write-Verbose "Using auto-detected name: $Name"
    }
  }
  process {
    try {
      # Call the static method
      $cert = [PsModuleBase]::CreateCertificate($Name)

      # Output formatted object similar to Get-PsCertificate
      [PSCustomObject]@{
        PSTypeName  = 'PsModuleBase.Certificate'
        Subject     = $cert.Subject
        NotAfter    = $cert.NotAfter
        Thumbprint  = $cert.Thumbprint
        Certificate = $cert
      }
    } catch {
      # Write terminating error if creation failed
      $PSCmdlet.ThrowTerminatingError($_)
    }
  }
}