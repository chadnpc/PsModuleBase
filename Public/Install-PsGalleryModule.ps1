function Install-PsGalleryModule {
  #  .SYNOPSIS
  #     Like install-Module but it manually installs the module when the normal way fails.
  #  .DESCRIPTION
  #     Installs a PowerShell module even on systems that don't have a working PowerShellGet.
  #     But Sometimes you just need to apply a quick fix like this one:
  #
  #     Unregister-PSRepository -Name PSGallery
  #     Register-PSRepository -Default
  #     if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
  #         Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
  #     }
  #     When all that fails, then this function comes in handy.
  [CmdletBinding()]
  [OutputType([IO.FileInfo])]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({ $_ -match '^[a-zA-Z0-9_.-]+$' })]
    [Alias('Name', 'n')]
    [string]$ModuleName,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ ($_ -as 'version') -is [version] -or $_ -eq 'latest' })]
    [string]$Version = 'latest',
    [switch]$UpdateOnly,
    [switch]$Passthru
  )
  Begin {
    [LocalPsModule]::ret = 0; $response = $null; $downloadUrl = ''; $Module_Path = ''
  }
  Process {
    # Try Using normal Installation
    try {
      if ($PSCmdlet.MyInvocation.BoundParameters['UpdateOnly']) {
        [LocalPsModule]::Update($ModuleName, $Version)
      } else {
        [LocalPsModule]::Install($ModuleName, $Version)
      }
      $Module_Path = (Get-LocalModule -Name $moduleName).Psd1 | Split-Path -ErrorAction Stop
    } catch {
      $VerboseMsg = 'Normal Installation Failed :' + $_.Exception.Message + "`nUsing Manual Instalation ..."
      Write-Verbose $VerboseMsg -Verbose
      # For some reason Install-Module can fail (ex: on Arch). This is a manual workaround when that happens.
      $version_filter = if ($Version -eq 'latest') { 'IsLatestVersion' } else { "Version eq '$Version'" }
      $url = "https://www.powershellgallery.com/api/v2/Packages?`$filter=Id eq '$moduleName' and $version_filter"
      try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Verbose:$false
        if ($null -eq $response) {
          $Error_params = @{
            ExceptionName    = 'System.InvalidOperationException'
            ExceptionMessage = "Module '$moduleName' was not found in PSGallery repository."
            ErrorId          = 'CouldNotFindModule'
            CallerPSCmdlet   = $PSCmdlet
            ErrorCategory    = 'InvalidResult'
          }
          Write-TerminatingError @Error_params
        }
        [ValidateNotNullOrEmpty()][string]$downloadUrl = $response.content.src
        [ValidateNotNullOrEmpty()][string]$moduleName = $response.properties.Id
        [ValidateNotNullOrEmpty()][string]$Version = $response.properties.Version
        $Module_Path = [LocalPsModule]::GetInstallPath($moduleName, $Version)
      } catch {
        $Error_params = @{
          ExceptionName    = 'System.InvalidOperationException'
          ExceptionMessage = "Failed to find PsGallery release for '$moduleName' version '$Version'. Url used: '$url'. $($_.Exception.Message)"
          ErrorId          = 'RestMethod_Failed'
          CallerPSCmdlet   = $PSCmdlet
          ErrorCategory    = 'OperationStopped'
        }
        Write-TerminatingError @Error_params
      }
      if (!(Test-Path -Path $Module_Path -PathType Container -ErrorAction Ignore)) { New-Directory -Path $Module_Path }
      $ModuleNupkg = [IO.Path]::Combine($Module_Path, "$moduleName.nupkg")
      Write-Host "Download $moduleName.nupkg ... " -NoNewline -ForegroundColor DarkCyan
      Invoke-WebRequest -Uri $downloadUrl -OutFile $ModuleNupkg -Verbose:$false;
      if ($IsWindows) { Unblock-File -Path $ModuleNupkg }
      Expand-Archive $ModuleNupkg -DestinationPath $Module_Path -Verbose:$false -Force
      $Items_to_CleanUp = [System.Collections.ObjectModel.Collection[System.Object]]::new()
      @('_rels', 'package', '*Content_Types*.xml', "$ModuleNupkg", "$($moduleName.Tolower()).nuspec" ) | ForEach-Object { [void]$Items_to_CleanUp.Add((Get-Item -Path "$Module_Path/$_" -ErrorAction Ignore)) }
      $Items_to_CleanUp = $Items_to_CleanUp | Sort-Object -Unique
      foreach ($Item in $Items_to_CleanUp) {
        [bool]$Recurse = $Item.Attributes -eq [System.IO.FileAttributes]::Directory
        Remove-Item -LiteralPath $Item.FullName -Recurse:$Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }
}