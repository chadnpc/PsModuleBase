#!/usr/bin/env pwsh
using namespace System.IO
using namespace System.Text
using namespace system.reflection
using namespace System.ComponentModel
using namespace System.Collections.Generic
using namespace System.Security.Cryptography
using namespace System.Management.Automation
using namespace Microsoft.PowerShell.Commands
using namespace System.Runtime.InteropServices
using namespace System.Collections.ObjectModel
using namespace System.Security.Cryptography.X509Certificates

#region    Classes
enum ModuleSource {
  LocalMachine
  PsGallery
}
enum InstallScope {
  LocalMachine # i.e: AllUsers
  CurrentUser
}

enum ModuleItemType {
  File
  Directory
}

class SearchParams {
  [bool] $SkipDefaults = $true
  [string[]] $PropstoExclude
  [string[]] $PropstoInclude
  [SearchOption] $searchOption
  hidden [string[]]$Values
  [int]$MaxDepth = 10
}

class ModuleItem {
  [ValidateNotNullOrWhiteSpace()][string]$Name
  [string[]]$Attributes = @()
  [FileSystemInfo]$value
  static [ReadOnlyCollection[string]]$DefaultNames = [ModuleItem]::GetDefaultNames()

  ModuleItem([string]$name, $value) {
    $this.Name = $name; $this.value = $value
    $this.psobject.properties.add([PsScriptProperty]::new('Exists', { return Test-Path -Path $this.value.FullName -ea Ignore }, { throw [SetValueException]::new('Exists is read-only') }))
    if ($name -in [ModuleItem]::DefaultNames) {
      $this.Attributes += "ManifestKey"
    }
  }
  static [ReadOnlyCollection[string]] GetDefaultNames() {
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-modulemanifest#example-5-getting-module-information
    return New-ReadOnlyCollection -list ((Get-Module PsModuleBase -Verbose:$false).PsObject.Properties.Name + 'ModuleVersion')
  }
  [void] hidden _init_([ModuleItemType]$type) {
    if ($type -eq "File") { $this.Attributes += "FileContent" }
    $this.psobject.properties.add([PsScriptProperty]::new('Type', [scriptblock]::Create("return [ModuleItemType]::$Type"), [scriptblock]::Create("throw [SetValueException]::new('$Type is read-only')") ))
  }
  [string] ToString() { return $this.Name }
}
class ModuleFile : ModuleItem {
  ModuleFile([string]$Name, [string]$value) : base($Name, [FileInfo]::new($value)) { $this._init_("File") }
  ModuleFile([string]$Name, [FileInfo]$value) : base($name, $value) { $this._init_("File") }
}

class ModuleFolder: ModuleItem {
  ModuleFolder([string]$Name, [string]$value): base ($name, [DirectoryInfo]::new($value)) { $this._init_("Directory") }
  ModuleFolder([string]$Name, [DirectoryInfo]$value) : base($name, $value) { $this._init_("Directory") }
}

class PSGalleryItem {
  [string] $Name
  [version] $Version
  [string] $Path
  [string] $Repository
  PSGalleryItem() {}
  PSGalleryItem([hashtable]$map) {
    $map.Keys.ForEach({
        $this.$_ = $map[$_]
      }
    )
  }
}

class PSRepoItem {
  [string] $AdditionalMetadata
  [string] $Author
  [string] $CompanyName
  [string] $Copyright
  [Object[]] $Dependencies
  [string] $Description
  [string] $IconUri
  [hashtable] $Includes
  [object] $InstalledDate
  [uri] $LicenseUri
  [string] $Name
  [string] $PackageManagementProvider
  [version] $PowerShellGetFormatVersion
  [uri] $ProjectUri
  [object] $PublishedDate
  [string] $ReleaseNotes
  [string] $Repository
  [string] $RepositorySourceLocation
  [string[]] $Tags
  [string] $Type
  [object] $UpdatedDate
  [version] $Version
  PSRepoItem() {}
  PSRepoItem([Object]$Object) {
    if ($null -ne $Object) {
      $Object.PsObject.Properties.Name.ForEach({
          $this.$_ = $Object.$_
        }
      )
    }
  }
  [string] ToString() {
    return $this.Name
  }
}

class LocalPsModule {
  [ValidateNotNullOrEmpty()][FileInfo]$Psd1
  [ValidateNotNullOrEmpty()][version]$version
  [ValidateNotNullOrWhiteSpace()][string]$Name
  [ValidateNotNullOrEmpty()][IO.DirectoryInfo]$Path
  [bool]$HasVersiondirs = $false
  [bool]$IsReadOnly = $false
  [PsObject]$Info = $null
  [bool]$Exists = $false
  [InstallScope]$Scope

  LocalPsModule() {}
  LocalPsModule([string]$Name) {
    [void][LocalPsModule]::From($Name, $null, $null, [ref]$this)
  }
  LocalPsModule([string]$Name, [string]$scope) {
    [void][LocalPsModule]::From($Name, $scope, $null, [ref]$this)
  }
  LocalPsModule([string]$Name, [version]$version) {
    [void][LocalPsModule]::From($Name, $null, $version, [ref]$this)
  }
  LocalPsModule([string]$Name, [string]$scope, [version]$version) {
    [void][LocalPsModule]::From($Name, $scope, $version, [ref]$this)
  }
  static [LocalPsModule] Create() { return [LocalPsModule]::new() }
  static [LocalPsModule] Create([string]$Name) {
    $o = [LocalPsModule]::new(); return [LocalPsModule]::From($Name, $null, $null, [ref]$o)
  }
  static [LocalPsModule] Create([string]$Name, [string]$scope) {
    $o = [LocalPsModule]::new(); return [LocalPsModule]::From($Name, $scope, $null, [ref]$o)
  }
  static [LocalPsModule] Create([string]$Name, [version]$version) {
    $o = [LocalPsModule]::new(); return [LocalPsModule]::From($Name, $null, $version, [ref]$o)
  }
  static [LocalPsModule] Create([string]$Name, [string]$scope, [version]$version) {
    $o = [LocalPsModule]::new(); return [LocalPsModule]::From($Name, $scope, $version, [ref]$o)
  }
  static hidden [LocalPsModule] From([string]$Name, [string]$scope, [version]$version, [ref]$o) {
    if ($null -eq $o) { throw "reference is null" };
    $m = [LocalPsModule]::Find($Name, $scope, $version);
    if ($null -eq $m) { $m = [LocalPsModule]::new() }
    $o.value.GetType().GetProperties().ForEach({
        $v = $m.$($_.Name)
        if ($null -ne $v) {
          $o.value.$($_.Name) = $v
        }
      }
    )
    return $o.Value
  }
  static [LocalPsModule] Find([string]$Name) {
    [ValidateNotNullOrEmpty()][string]$Name = $Name
    if ($Name.Contains([string][Path]::DirectorySeparatorChar)) {
      $rName = [PsModuleBase]::GetResolvedPath($Name)
      $bName = [Path]::GetDirectoryName($rName)
      if ([IO.Directory]::Exists($rName)) {
        return [LocalPsModule]::Find($bName, [IO.Directory]::GetParent($rName))
      }
    }
    return [LocalPsModule]::Find($Name, "", $null)
  }
  static [LocalPsModule] Find([string]$Name, [string]$scope) {
    return [LocalPsModule]::Find($Name, $scope, $null)
  }
  static [LocalPsModule] Find([string]$Name, [version]$version) {
    return [LocalPsModule]::Find($Name, "", $version)
  }
  static [LocalPsModule] Find([string]$Name, [IO.DirectoryInfo]$ModuleBase) {
    [ValidateNotNullOrWhiteSpace()][string]$Name = $Name
    [ValidateNotNullOrEmpty()][IO.DirectoryInfo]$ModuleBase = $ModuleBase
    $result = [LocalPsModule]::new(); $result.Scope = 'LocalMachine'
    $ModulePsd1 = ($ModuleBase.GetFiles().Where({ $_.Name -like "$Name*" -and $_.Extension -eq '.psd1' }))[0]
    if ($null -eq $ModulePsd1) { return $result }
    $result.Info = Read-ModuleData -File $ModulePsd1.FullName
    $result.Name = $ModulePsd1.BaseName
    $result.Psd1 = $ModulePsd1
    $result.Path = if ($result.Psd1.Directory.Name -as [version] -is [version]) { $result.Psd1.Directory.Parent } else { $result.Psd1.Directory }
    $result.Exists = $ModulePsd1.Exists
    $result.Version = $result.Info.ModuleVersion -as [version]
    $result.IsReadOnly = $ModulePsd1.IsReadOnly
    return $result
  }
  static [LocalPsModule] Find([string]$Name, [string]$scope, [version]$version) {
    $Module = $null; [ValidateNotNullOrWhiteSpace()][string]$Name = $Name
    $PsModule_Paths = $([LocalPsModule]::GetModulePaths($(if ([string]::IsNullOrWhiteSpace($scope)) { "LocalMachine" }else { $scope })).ForEach({ [IO.DirectoryInfo]::New("$_") }).Where({ $_.Exists })).GetDirectories().Where({ $_.Name -eq $Name });
    if ($PsModule_Paths.count -gt 0) {
      $Get_versionDir = [scriptblock]::Create('param([IO.DirectoryInfo[]]$direcrory) return ($direcrory | ForEach-Object { $_.GetDirectories() | Where-Object { $_.Name -as [version] -is [version] } })')
      $has_versionDir = $Get_versionDir.Invoke($PsModule_Paths).count -gt 0
      $ModulePsdFiles = $PsModule_Paths.ForEach({
          if ($has_versionDir) {
            [string]$MaxVersion = ($Get_versionDir.Invoke([IO.DirectoryInfo]::New("$_")) | Select-Object @{l = 'version'; e = { $_.BaseName -as [version] } } | Measure-Object -Property version -Maximum).Maximum
            [IO.FileInfo]::New([IO.Path]::Combine("$_", $MaxVersion, $_.BaseName + '.psd1'))
          } else {
            [IO.FileInfo]::New([IO.Path]::Combine("$_", $_.BaseName + '.psd1'))
          }
        }
      ).Where({ $_.Exists })
      $Req_ModulePsd1 = $(if ($null -eq $version) {
          $ModulePsdFiles | Sort-Object -Property version -Descending | Select-Object -First 1
        } else {
          $ModulePsdFiles | Where-Object { $(Read-ModuleData -File $_.FullName -Property ModuleVersion) -eq $version }
        }
      )
      $Module = [LocalPsModule]::Find($Req_ModulePsd1.Name, $Req_ModulePsd1.Directory)
    }
    return $Module
  }
  static [string[]] GetModulePaths() {
    return [LocalPsModule]::GetModulePaths($null)
  }
  static [string[]] GetModulePaths([string]$iscope) {
    [string[]]$_Module_Paths = [Environment]::GetEnvironmentVariable('PSModulePath').Split([IO.Path]::PathSeparator)
    if ([string]::IsNullOrWhiteSpace($iscope)) { return $_Module_Paths }; [InstallScope]$iscope = $iscope
    if (!(Get-Variable -Name IsWindows -ErrorAction Ignore) -or $(Get-Variable IsWindows -ValueOnly)) {
      $psv = Get-Variable PSVersionTable -ValueOnly
      $allUsers_path = Join-Path -Path $env:ProgramFiles -ChildPath $(if ($psv.ContainsKey('PSEdition') -and $psv.PSEdition -eq 'Core') { 'PowerShell' } else { 'WindowsPowerShell' })
      if ("$iScope" -eq 'CurrentUser') { $_Module_Paths = $_Module_Paths.Where({ $_ -notlike "*$($allUsers_path | Split-Path)*" -and $_ -notlike "*$env:SystemRoot*" }) }
    } else {
      $allUsers_path = Split-Path -Path ([Platform]::SelectProductNameForDirectory('SHARED_MODULES')) -Parent
      if ("$iScope" -eq 'CurrentUser') { $_Module_Paths = $_Module_Paths.Where({ $_ -notlike "*$($allUsers_path | Split-Path)*" -and $_ -notlike "*/var/lib/*" }) }
    }
    return $_Module_Paths
  }
  [void] Delete() {
    Remove-Item $this.Path -Recurse -Force -ErrorAction Ignore
  }
}

class PsModuleBase {
  static [bool] SaveModuledata([string]$stringsKey, [Object]$value) {
    return $null
  }
  static [bool] ValidadePsd1File([IO.FileInFo]$File) {
    return [PsModuleBase]::ValidadePsd1File($File, $false)
  }
  static [bool] ValidadePsd1File([IO.DirectoryInfo]$Parent) {
    $File = [IO.Path]::Combine($Parent, (Get-Culture).Name, "$([IO.DirectoryInfo]::New($Parent).BaseName).strings.psd1");
    return [PsModuleBase]::ValidadePsd1File($File)
  }
  static [bool] ValidadePsd1File([IO.FileInFo]$File, [bool]$throwOnFailure) {
    $e = [IO.File]::Exists($File.FullName)
    if (!$e -and $throwOnFailure) { throw [IO.FileNotFoundException]::new("File $($File.FullName) was not found. Make sure the module is Installed and try again") }
    $v = $e -and ($File.Extension -eq ".psd1")
    if (!$v -and $throwOnFailure) {
      throw [System.ArgumentException]::new("File '$File' is not valid. Please provide a valid path/to/<modulename>.Strings.psd1", 'Path')
    }
    return $v
  }
  #region    IO
  static [Object] ReadModuledata([string]$ModuleName) {
    return [PsModuleBase]::ReadModuledata($ModuleName, '')
  }
  static [Object] ReadModuledata([string]$ModuleName, [string]$key) {
    [ValidateNotNullOrWhiteSpace()][string]$ModuleName = $ModuleName
    $m = (Get-Module $ModuleName -ListAvailable -Verbose:$false).ModuleBase
    $f = [IO.FileInfo]::new([IO.Path]::Combine($m, "en-US", "$ModuleName.strings.psd1"))
    [void][PsModuleBase]::ValidadePsd1File($f, $true)
    $c = [IO.File]::ReadAllText($f.FullName)
    if ([string]::IsNullOrWhiteSpace($c)) { throw [IO.InvalidDataException]::new("File $f") }
    $r = [ScriptBlock]::Create("$c").Invoke()
    if ($null -eq $r) { return $null }
    return (![string]::IsNullOrWhiteSpace($key) ? $r.$key : $r)
  }
  static [string] GetRelativePath([string]$RelativeTo, [string]$Path) {
    # $RelativeTo : The source path the result should be relative to. This path is always considered to be a directory.
    # $Path : The destination path.
    $result = [string]::Empty
    $Drive = $Path -replace "^([^\\/]+:[\\/])?.*", '$1'
    if ($Drive -ne ($RelativeTo -replace "^([^\\/]+:[\\/])?.*", '$1')) {
      Write-Verbose "Paths on different drives"
      return $Path # no commonality, different drive letters on windows
    }
    $RelativeTo = $RelativeTo -replace "^[^\\/]+:[\\/]", [IO.Path]::DirectorySeparatorChar
    $Path = $Path -replace "^[^\\/]+:[\\/]", [IO.Path]::DirectorySeparatorChar
    $RelativeTo = [IO.Path]::GetFullPath($RelativeTo).TrimEnd('\/') -replace "^[^\\/]+:[\\/]", [IO.Path]::DirectorySeparatorChar
    $Path = [IO.Path]::GetFullPath($Path) -replace "^[^\\/]+:[\\/]", [IO.Path]::DirectorySeparatorChar

    $commonLength = 0
    while ($Path[$commonLength] -eq $RelativeTo[$commonLength]) {
      $commonLength++
    }
    if ($commonLength -eq $RelativeTo.Length -and $RelativeTo.Length -eq $Path.Length) {
      Write-Verbose "Equal Paths"
      return "." # The same paths
    }
    if ($commonLength -eq 0) {
      Write-Verbose "Paths on different drives?"
      return $Drive + $Path # no commonality, different drive letters on windows
    }

    Write-Verbose "Common base: $commonLength $($RelativeTo.Substring(0,$commonLength))"
    # In case we matched PART of a name, like C:/Users/Joel and C:/Users/Joe
    while ($commonLength -gt $RelativeTo.Length -and ($RelativeTo[$commonLength] -ne [IO.Path]::DirectorySeparatorChar)) {
      $commonLength--
    }

    Write-Verbose "Common base: $commonLength $($RelativeTo.Substring(0,$commonLength))"
    # create '..' segments for segments past the common on the "$RelativeTo" path
    if ($commonLength -lt $RelativeTo.Length) {
      $result = @('..') * @($RelativeTo.Substring($commonLength).Split([IO.Path]::DirectorySeparatorChar).Where{ $_ }).Length -join ([IO.Path]::DirectorySeparatorChar)
    }
    return (@($result, $Path.Substring($commonLength).TrimStart([IO.Path]::DirectorySeparatorChar)).Where{ $_ } -join ([IO.Path]::DirectorySeparatorChar))
  }
  static [string] GetResolvedPath([string]$Path) {
    return [PsModuleBase]::GetResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
  }
  static [string] GetResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
    $paths = $session.Path.GetResolvedPSPathFromPSPath($Path);
    if ($paths.Count -gt 1) {
      throw [IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} is ambiguous", $Path))
    } elseif ($paths.Count -lt 1) {
      throw [IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} not Found", $Path))
    }
    return $paths[0].Path
  }
  static [string] GetUnResolvedPath([string]$Path) {
    return [PsModuleBase]::GetunResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
  }
  static [string] GetUnResolvedPath([SessionState]$session, [string]$Path) {
    return $session.Path.GetUnresolvedProviderPathFromPSPath($Path)
  }
  static [IO.DirectoryInfo] GetDataPath([string]$appName, [string]$SubdirName) {
    $_Host_OS = [PsModuleBase]::GetHostOs()
    $dataPath = if ($_Host_OS -eq 'Windows') {
      [DirectoryInfo]::new([IO.Path]::Combine($Env:HOME, "AppData", "Roaming", $appName, $SubdirName))
    } elseif ($_Host_OS -in ('Linux', 'MacOSX')) {
      [DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
    } elseif ($_Host_OS -eq 'Unknown') {
      try {
        [DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
      } catch {
        Write-Warning "Could not resolve chat data path"
        Write-Warning "HostOS = '$_Host_OS'. Could not resolve data path."
        [Directory]::CreateTempSubdirectory(($SubdirName + 'Data-'))
      }
    } else {
      throw [InvalidOperationException]::new('Could not resolve data path. GetHostOs FAILED!')
    }
    if (!$dataPath.Exists) { [PsModuleBase]::CreateFolder($dataPath) }
    return $dataPath
  }
  static [DirectoryInfo] CreateFolder([string]$Path) {
    return [PsModuleBase]::CreateFolder([DirectoryInfo]::new($Path))
  }
  static [DirectoryInfo] CreateFolder([DirectoryInfo]$Path) {
    [ValidateNotNullOrEmpty()][DirectoryInfo]$Path = $Path
    $nF = @(); $p = $Path; while (!$p.Exists) { $nF += $p; $p = $p.Parent }
    [Array]::Reverse($nF); $nF | ForEach-Object { $_.Create() }
    return Get-Item $Path
  }
  #endregion IO

  #region    CodeSec
  static [void] AddSignature([string]$File) {
    $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
    [PsModuleBase]::SetAuthenticodeSignature($File, $cert)
  }
  static [void] SetAuthenticodeSignature($FilePath, $Certificate) {
    $params = @{
      FilePath        = $FilePath
      Certificate     = $Certificate
      TimestampServer = "http://timestamp.digicert.com"
    }
    $result = Set-AuthenticodeSignature @params
    if ($result.Status -ne "Valid") {
      throw "Failed to sign $FilePath. Status: $($result.Status)"
    }
  }
  static [string] ExportCertificate([string]$CertPath, [string]$ExportPath, [SecureString]$Password) {
    # .SYNOPSIS
    # Export your signing key and certificate to a .pfx file
    # .DESCRIPTION
    # If you have a private key and certificate on your computer,
    # malicious programs might be able to sign scripts on your behalf, which authorizes PowerShell to run them.
    # To prevent automated signing on your behalf, use
    # [PsModuleBase]::ExportCertificate to export your signing key and certificate to a .pfx file.
    $cert = Get-ChildItem -Path $CertPath
    Export-PfxCertificate -Cert $cert -FilePath $ExportPath -Password $Password
    return $ExportPath
  }

  static [void] ImportCertificate([string]$PfxPath, [SecureString]$Password) {
    Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $Password
  }

  static [bool] VerifySignature([string]$FilePath) {
    $signature = Get-AuthenticodeSignature -FilePath $FilePath
    return $signature.Status -eq "Valid"
  }

  static [void] RemoveSignature([string]$FilePath) {
    $content = Get-Content -Path $FilePath -Raw
    $newContent = $content -replace '# SIG # Begin signature block[\s\S]*# SIG # End signature block', ''
    Set-Content -Path $FilePath -Value $newContent
  }

  static [void] SignDirectory([string]$DirectoryPath, [string]$CertPath, [string]$Filter = "*.ps1") {
    $cert = Get-ChildItem -Path $CertPath
    Get-ChildItem -Path $DirectoryPath -Filter $Filter -Recurse | ForEach-Object {
      [PsModuleBase]::SetAuthenticodeSignature($_.FullName, $cert)
    }
  }
  static [string] CreatedataUUID([Tuple[string, string, string, string]]$Info) {
    # Creates a custom guid based on 4 input string values
    $shash = [System.Text.StringBuilder]::new()
    $c_arr = [byte[]][SHA256CryptoServiceProvider]::HashData([Text.Encoding]::UTF8.GetBytes($Info.ToString().Replace(', ', ':')))
    $c_arr.ForEach({ [void]$shash.Append($_.ToString("x2")) })
    $s_256 = $shash.ToString().Substring(0, 32) -replace '(.{8})(.{4})(.{4})(.{4})(.{12})', '$1-$2-$3-$4-$5'
    return [System.Guid]::new($s_256)
  }
  static [X509Certificate2] GetCodeSigningCert() {
    return Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
  }
  #endregion CodeSec

  #region    ObjectUtils
  static [string[]] ListProperties([System.Object]$Obj) {
    return [PsModuleBase]::ListProperties($Obj, '')
  }
  static [string[]] ListProperties([System.Object]$Obj, [string]$Prefix = '') {
    $Properties = @()
    $Obj.PSObject.Properties | ForEach-Object {
      $PropertyName = $_.Name
      $FullPropertyName = if ([string]::IsNullOrEmpty($Prefix)) {
        $PropertyName
      } else {
        "$Prefix,$PropertyName"
      }
      $PropertyValue = $_.Value
      $propertyType = $_.TypeNameOfValue
      # $BaseType = $($propertyType -as 'type').BaseType.FullName
      if ($propertyType -is [System.ValueType]) {
        Write-Verbose "vt <= $propertyType"
        $Properties += $FullPropertyName
      } elseif ($propertyType -is [System.Object]) {
        Write-Verbose "ob <= $propertyType"
        $Properties += [PsModuleBase]::ListProperties($PropertyValue, $FullPropertyName)
      }
    }
    return $Properties
  }
  static [Object[]] ExcludeProperties($Object) {
    return [PsModuleBase]::ExcludeProperties($Object, [searchParams]::new())
  }
  static [Object[]] ExcludeProperties($Object, [string[]]$PropstoExclude) {
    $sp = [searchParams]::new(); $sp.PropstoExclude + $PropstoExclude
    return [PsModuleBase]::ExcludeProperties($Object, $sp)
  }
  static [Object[]] ExcludeProperties($Object, [searchParams]$SearchOptions) {
    $DefaultTypeProps = @()
    if ($SearchOptions.SkipDefaults) {
      try {
        $DefaultTypeProps = @( $Object.GetType().GetProperties() | Select-Object -ExpandProperty Name -ErrorAction Stop )
      } Catch {
        $null
      }
    }
    $allPropstoExclude = @( $SearchOptions.PropstoExclude + $DefaultTypeProps ) | Select-Object -Unique
    return $Object.psobject.properties | Where-Object { $allPropstoExclude -notcontains $_.Name }
  }
  static [PSObject] RecurseObject($Object, [PSObject]$Output) {
    return [PsModuleBase]::RecurseObject($Object, '$Object', $Output, 0)
  }
  static [PSObject] RecurseObject($Object, [string[]]$Path, [PSObject]$Output, [int]$Depth) {
    $Depth++
    #Get the children we care about, and their names
    $Children = [PsModuleBase]::ExcludeProperties($Object);
    #Loop through the children properties.
    foreach ($Child in $Children) {
      $ChildName = $Child.Name
      $ChildValue = $Child.Value
      # Handle special characters...
      $FriendlyChildName = $(if ($ChildName -match '[^a-zA-Z0-9_]') {
          "'$ChildName'"
        } else {
          $ChildName
        }
      )
      $IsInInclude = ![PsModuleBase]::SearchOptions.PropstoInclude -or @([PsModuleBase]::SearchOptions.PropstoInclude).Where({ $ChildName -like $_ })
      $IsInValue = ![PsModuleBase]::SearchOptions.Value -or (@([PsModuleBase]::SearchOptions.Value).Where({ $ChildValue -like $_ }).Count -gt 0)
      if ($IsInInclude -and $IsInValue -and $Depth -le [PsModuleBase]::SearchOptions.MaxDepth) {
        $ThisPath = @( $Path + $FriendlyChildName ) -join "."
        $Output | Add-Member -MemberType NoteProperty -Name $ThisPath -Value $ChildValue
      }
      if ($null -eq $ChildValue) {
        continue
      }
      if (($ChildValue.GetType() -eq $Object.GetType() -and $ChildValue -is [datetime]) -or ($ChildName -eq "SyncRoot" -and !$ChildValue)) {
        Write-Debug "Skipping $ChildName with type $($ChildValue.GetType().FullName)"
        continue
      }
      # Check for arrays by checking object type (this is a fix for arrays with 1 object) otherwise check the count of objects
      $IsArray = $(if (($ChildValue.GetType()).basetype.Name -eq "Array") {
          $true
        } else {
          @($ChildValue).count -gt 1
        }
      )
      $count = 0
      #Set up the path to this node and the data...
      $CurrentPath = @( $Path + $FriendlyChildName ) -join "."

      #Get the children's children we care about, and their names.  Also look for signs of a hashtable like type
      $ChildrensChildren = [PsModuleBase]::ExcludeProperties($ChildValue)
      $HashKeys = if ($ChildValue.Keys -and $ChildValue.Values) {
        $ChildValue.Keys
      } else {
        $null
      }
      if ($(@($ChildrensChildren).count -ne 0 -or $HashKeys) -and $Depth -lt [PsModuleBase]::SearchOptions.MaxDepth) {
        #This handles hashtables.  But it won't recurse...
        if ($HashKeys) {
          foreach ($key in $HashKeys) {
            $Output | Add-Member -MemberType NoteProperty -Name "$CurrentPath['$key']" -Value $ChildValue["$key"]
            $Output = [PsModuleBase]::RecurseObject($ChildValue["$key"], "$CurrentPath['$key']", $Output, $depth)
          }
        } else {
          if ($IsArray) {
            foreach ($item in @($ChildValue)) {
              $Output = [PsModuleBase]::RecurseObject($item, "$CurrentPath[$count]", $Output, $depth)
              $Count++
            }
          } else {
            $Output = [PsModuleBase]::RecurseObject($ChildValue, $CurrentPath, $Output, $depth)
          }
        }
      }
    }
    return $Output
  }
  static [hashtable[]] FindHashKeyValue($PropertyName, $Ast) {
    return [PsModuleBase]::FindHashKeyValue($PropertyName, $Ast, @())
  }
  static [hashtable[]] FindHashKeyValue($PropertyName, $Ast, [string[]]$CurrentPath) {
    if ($PropertyName -eq ($CurrentPath -Join '.') -or $PropertyName -eq $CurrentPath[ - 1]) {
      return $Ast | Add-Member NoteProperty HashKeyPath ($CurrentPath -join '.') -PassThru -Force | Add-Member NoteProperty HashKeyName ($CurrentPath[ - 1]) -PassThru -Force
    }; $r = @()
    if ($Ast.PipelineElements.Expression -is [System.Management.Automation.Language.HashtableAst]) {
      $KeyValue = $Ast.PipelineElements.Expression
      ForEach ($KV in $KeyValue.KeyValuePairs) {
        $result = [PsModuleBase]::FindHashKeyValue($PropertyName, $KV.Item2, @($CurrentPath + $KV.Item1.Value))
        if ($null -ne $result) {
          $r += $result
        }
      }
    }
    return $r
  }
  static [string] EscapeSpecialCharacters([string]$str) {
    if ([string]::IsNullOrWhiteSpace($str)) {
      return $str
    } else {
      [string]$ParsedText = $str
      if ($ParsedText.ToCharArray() -icontains "'") {
        $ParsedText = $ParsedText -replace "'", "''"
      }
      return $ParsedText
    }
  }
  static [Hashtable] RegexMatch([regex]$Regex, [RegularExpressions.Match]$Match) {
    if (!$Match.Groups[0].Success) {
      throw New-Object System.ArgumentException('Match does not contain any captures.', 'Match')
    }
    $h = @{}
    foreach ($name in $Regex.GetGroupNames()) {
      if ($name -eq 0) {
        continue
      }
      $h.$name = $Match.Groups[$name].Value
    }
    return $h
  }
  static [string] RegexEscape([string]$LiteralText) {
    if ([string]::IsNullOrEmpty($LiteralText)) { $LiteralText = [string]::Empty }
    return [regex]::Escape($LiteralText);
  }
  static [bool] IsValidHex([string]$Text) {
    return [regex]::IsMatch($Text, '^#?([a-f0-9]{6}|[a-f0-9]{3})$')
  }
  static [bool] IsValidHex([byte[]]$bytes) {
    # .Example
    # $bytes = [byte[]](0x00, 0x1F, 0x2A, 0xFF)
    foreach ($byte in $bytes) {
      if ($byte -lt 0x00 -or $byte -gt 0xFF) {
        return $false
      }
    } return $true
  }
  static [bool] IsValidBase64([string]$string) {
    return $(
      [regex]::IsMatch([string]$string, '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$') -and
      ![string]::IsNullOrWhiteSpace([string]$string) -and !$string.Length % 4 -eq 0 -and !$string.Contains(" ") -and
      !$string.Contains(" ") -and !$string.Contains("`t") -and !$string.Contains("`n")
    )
  }
  static [void] ValidatePolybius([string]$Text, [string]$Key, [string]$Action) {
    if ($Text -notmatch "^[a-z ]*$" -and ($Action -ne 'Decrypt')) {
      throw('Text must only have alphabetical characters');
    }
    if ($Key.Length -ne 25) {
      throw('Key must be 25 characters in length');
    }
    if ($Key -notmatch "^[a-z]*$") {
      throw('Key must only have alphabetical characters');
    }
    for ($i = 0; $i -lt 25; $i++) {
      for ($j = 0; $j -lt 25; $j++) {
        if (($Key[$i] -eq $Key[$j]) -and ($i -ne $j)) {
          throw('Key must have no repeating letters');
        }
      }
    }
  }
  static [void] ValidatePath([string]$path) {
    $InvalidPathChars = [IO.Path]::GetInvalidPathChars()
    $InvalidCharsRegex = "[{0}]" -f [regex]::Escape($InvalidPathChars)
    if ($Path -match $InvalidCharsRegex) {
      throw [InvalidEnumArgumentException]::new("The path string contains invalid characters.")
    }
  }
  #endregion ObjectUtils

  #region    RuntimeInfo
  static [bool] IsAdmin() {
    $HostOs = [PsModuleBase]::GetHostOs()
    $isAdmn = switch ($HostOs) {
      "Windows" { (New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator); break }
      "Linux" { (& id -u) -eq 0; break }
      "MacOSX" { Write-Warning "MacOSX !! idk how to solve this one!"; $false; break }
      Default {
        Write-Warning "[ModuleManager]::IsAdmin? : OSPlatform $((Get-Variable 'PSVersionTable' -ValueOnly).Platform) | $HostOs is not yet supported"
        throw "UNSUPPORTED_OS"
      }
    }
    return $isAdmn
  }
  static [string] GetRuntimeUUID() {
    return [PsModuleBase]::CreatedataUUID([Tuple[string, string, string, string]]::new(
        [Environment]::MachineName,
        [RuntimeInformation]::OSDescription,
        [RuntimeInformation]::OSArchitecture,
        [Environment]::ProcessorCount
      )
    )
  }
  static [PSCustomObject] GetIpInfo() {
    $info = $null; $gist = "https://api.github.com/gists/d1985ebe22fe07cc191c9458b3a2bdbc"
    try {
      $info = [scriptblock]::Create($(
        (Invoke-RestMethod -Verbose:$false -ea Ignore -SkipHttpErrorCheck -Method Get $gist).files.'IpInfo.ps1'.content
        ) + ';[Ipinfo]::getInfo()'
      ).Invoke()
    } catch {
      $info = [PSCustomObject]@{
        country_name = "US"
        location     = [PSCustomObject]@{
          geoname_id = "Ohio"
        }
        city         = "Florida"
      }
    }
    return $info
  }
  static [string] GetHostOs() {
    #TODO: refactor so that it returns one of these: [Enum]::GetNames([System.PlatformID])
    return $(switch ($true) {
        $([RuntimeInformation]::IsOSPlatform([OSPlatform]::Windows)) { "Windows"; break }
        $([RuntimeInformation]::IsOSPlatform([OSPlatform]::FreeBSD)) { "FreeBSD"; break }
        $([RuntimeInformation]::IsOSPlatform([OSPlatform]::Linux)) { "Linux"; break }
        $([RuntimeInformation]::IsOSPlatform([OSPlatform]::OSX)) { "MacOSX"; break }
        Default {
          "UNKNOWN"
        }
      }
    )
  }
  #endregion RuntimeInfo
}
#endregion Classes

# Types that will be available to users when they import the module.
$typestoExport = @(
  [PsModuleBase], [LocalPsModule], [InstallScope], [ModuleSource], [PSRepoItem], [PSGalleryItem],
  [ModuleItem], [ModuleFile], [ModuleItemType], [SearchParams], [ModuleFolder]
)
$TypeAcceleratorsClass = [PsObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
foreach ($Type in $typestoExport) {
  if ($Type.FullName -in $TypeAcceleratorsClass::Get.Keys) {
    $Message = @(
      "Unable to register type accelerator '$($Type.FullName)'"
      'Accelerator already exists.'
    ) -join ' - '
    "TypeAcceleratorAlreadyExists $Message" | Write-Debug
  }
}
# Add type accelerators for every exportable type.
foreach ($Type in $typestoExport) {
  $TypeAcceleratorsClass::Add($Type.FullName, $Type)
}
# Remove type accelerators when the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
  foreach ($Type in $typestoExport) {
    $TypeAcceleratorsClass::Remove($Type.FullName)
  }
}.GetNewClosure();

$scripts = @();
$Public = Get-ChildItem "$PSScriptRoot/Public" -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
$scripts += Get-ChildItem "$PSScriptRoot/Private" -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
$scripts += $Public

foreach ($file in $scripts) {
  Try {
    if ([string]::IsNullOrWhiteSpace($file.fullname)) { continue }
    . "$($file.fullname)"
  } Catch {
    Write-Warning "Failed to import function $($file.BaseName): $_"
    $host.UI.WriteErrorLine($_)
  }
}

$Param = @{
  Function = $Public.BaseName
  Cmdlet   = '*'
  Alias    = '*'
  Verbose  = $false
}
Export-ModuleMember @Param
