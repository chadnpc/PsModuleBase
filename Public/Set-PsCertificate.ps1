function Set-PsCertificate {
  # .SYNOPSIS
  #   Configure the certificate to use for PsModuleBase. (Wrapper for [PsModuleBase]::SetCurrentUserCertificate)
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
  [CmdletBinding(DefaultParameterSetName = 'Thumbprint')] # Ensure DefaultParameterSetName is set
  param (
    [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
    [string]$Thumbprint,

    [Parameter(Mandatory = $true, ParameterSetName = 'FriendlyName')]
    [string]$FriendlyName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Subject')]
    [string]$Subject
  )

  process {
    try {
      # Call the static method using splatting for parametersets
      $str = ''
      if ($PSCmdlet.ParameterSetName -eq 'Thumbprint') { $str = $Thumbprint }
      elseif ($PSCmdlet.ParameterSetName -eq 'FriendlyName') { $str = $FriendlyName }
      elseif ($PSCmdlet.ParameterSetName -eq 'Subject') { $str = $Subject }

      [PsModuleBase]::SetCurrentUserCertificate($str)

      Write-Verbose "Successfully set PsModuleBase certificate configuration."
      # Optionally, show the currently selected cert
      Get-PsCertificate -Current
    } catch {
      $PSCmdlet.ThrowTerminatingError($_)
    }
  }
}