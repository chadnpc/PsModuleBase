function Get-PsContact {
  <#
    .SYNOPSIS
        Get a list of all contacts you have registered. (Wrapper for [PsModuleBase]::GetContact)

    #>
  [CmdletBinding()]
  Param (
    [string]
    $Name = '*'
  )

  process {
    try {
      # Call the static method
      [PsModuleBase]::GetContact($Name)
    } catch {
      # Handle errors during contact retrieval if needed, though class method logs warnings
      $PSCmdlet.WriteError($_)
    }
  }
}