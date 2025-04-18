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
  hidden [string[]] $Values
  [int]$MaxDepth = 10
}

class ModuleItem {
  [ValidateNotNullOrWhiteSpace()][string]$Name
  [string[]]$Attributes = @()
  [FileSystemInfo]$value
  static [ReadOnlyCollection[string]]$DefaultNames = [ModuleItem]::GetDefaultNames()

  ModuleItem([string]$name, $value) {
    $this.Name = $name; $this.value = $value
    $this.PsObject.properties.add([PsScriptProperty]::new('Exists', { return Test-Path -Path $this.value.FullName -ea Ignore }, { throw [SetValueException]::new('Exists is read-only') }))
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
    $this.PsObject.properties.add([PsScriptProperty]::new('Type', [scriptblock]::Create("return [ModuleItemType]::$Type"), [scriptblock]::Create("throw [SetValueException]::new('$Type is read-only')") ))
  }
  [string] ToString() { return $this.Name }
}
class ModuleFile : ModuleItem {
  ModuleFile([string]$Name, [string]$value) : base($Name, [FileInfo]::new($value)) { $this._init_("File") }
  ModuleFile([string]$Name, [FileInfo]$value) : base($name, $value) { $this._init_("File") }
}

# a custom config file helper class
class ConfigFile : MarshalByRefObject {
  hidden [string]$_suffix
  ConfigFile() {
    [void][ConfigFile]::From([Guid]::NewGuid().Guid, [ref]$this)
  }
  ConfigFile([string]$fileName) {
    [void][ConfigFile]::From($fileName, [ref]$this)
  }
  ConfigFile([IO.FileInfo]$File) {
    [void][ConfigFile]::From($File.FullName, "", [ref]$this)
  }
  ConfigFile([PSCustomObject]$object) {
    [void][ConfigFile]::From($object.Path, $object.Suffix, [ref]$this)
  }
  ConfigFile([string]$fileName, [string]$suffix) {
    [void][ConfigFile]::From($fileName, $suffix, [ref]$this)
  }
  static [ConfigFile] Create([string]$fileName) {
    return [ConfigFile]::new($fileName)
  }
  static [ConfigFile] Create([string]$fileName, [string]$suffix) {
    return [ConfigFile]::new($fileName, $suffix)
  }
  static hidden [ConfigFile] From([string]$fileName, [ref]$o) {
    return [ConfigFile]::From($fileName, "-config", $o)
  }
  static hidden [ConfigFile] From([string]$fileName, [string]$suffix, [ref]$o) {
    $n = ''; $f = ''; [void][ConfigFile]::IsValidFilePath($fileName, $true);
    [ValidateNotNullOrWhiteSpace()][string]$n = [PsModuleBase]::GetUnResolvedPath((![string]::IsNullOrWhiteSpace($suffix) ? ($fileName + $suffix) : $fileName));
    [ValidateNotNullOrWhiteSpace()][string]$f = [IO.File]::Exists($n) ? $n : ($n.EndsWith(".json") ? $n : "$n.json")
    $o.Value.PsObject.Properties.Add([PSScriptProperty]::new('FullName', [scriptblock]::Create("return '$f'"), { Param([string]$value) $this.set_fullName($value) }))
    $o.Value.PsObject.Properties.Add([PSScriptProperty]::new('Directory', { return [DirectoryInfo](Split-Path $this.FullName -ea Ignore) }, { Param([string]$value) $this.SetDirectory($value) }))
    $o.Value.PsObject.Properties.Add([PSScriptProperty]::new('BaseName', { return [IO.Path]::GetFileNameWithoutExtension($this.FullName) }))
    $o.Value.PsObject.Properties.Add([PSScriptProperty]::new('Name', { return [IO.Path]::GetFileName($this.FullName) }, { Param([string]$value) $this.Rename(([string]::IsNullOrWhiteSpace([IO.Path]::GetExtension($value)) ? "$value.json" : $value), $false) }))
    $o.Value.PsObject.Properties.Add([PSScriptProperty]::new('Extension', { return [IO.Path]::GetExtension($this.FullName) }, { Param([string]$value) [ValidateNotNullOrWhiteSpace()][string]$value = $value; $e = $value.StartsWith(".") ? $value : ".$value"; $this.Rename(('{0}{1}' -f $this.BaseName, $e), $false) }))
    $o.Value.PsObject.Properties.Add([PSScriptProperty]::new('Exists', { return [IO.File]::Exists($this.FullName) })); $o.Value.SetSuffix($suffix);
    return $o.Value
  }
  [void] Delete() { [IO.File]::Delete($this.FullName) }
  [void] Decrypt() { [IO.File]::Decrypt($this.FullName) }
  [void] Encrypt() {
    # TODO: use [PsModuleBase]::ProtectFile(string Path ...
    [IO.File]::Encrypt($this.FullName)
  }
  [string] GetSuffix() {
    return $this.BaseName.EndsWith($this._suffix) ? $this._suffix : ''
  }
  [void] SetSuffix([string]$value) {
    if (![string]::IsNullOrWhiteSpace($value) -and ![ConfigFile]::IsValidFilePath($value)) {
      # ie: empty string is allowed
      throw [ArgumentNullException]::new("Please provide a valid suffix.")
    }
    $cs = $this.GetSuffix();
    if (!$this.BaseName.EndsWith($value)) { $this.Name = $this.Name.Replace(($cs + $this.Extension), ($value + $this.Extension)) }
    $this._suffix = $value;
  }
  [void] SetDirectory([string]$value) {
    $_fdir = [PsModuleBase]::GetUnResolvedPath($value)
    if (![IO.Path]::IsPathFullyQualified($_fdir)) {
      throw [System.ArgumentException]::new("Please provide a valid directory path")
    }
    ($_fdir -ne "$($this.Directory)" -and $this.Exists) ? $this.MoveTo($_fdir) : $this.PsObject.Properties.Add([PSScriptProperty]::new('FullName', [scriptblock]::Create("return '$([IO.Path]::Combine($_fdir, $this.Name))'"), { Param([string]$value) $this.set_fullName($value) }))
  }
  [void] Rename([string]$nn) { $this.Rename($nn, $false) }
  [void] Rename([string]$nn, [bool]$savefile) {
    [void][ConfigFile]::IsValidFilePath($nn, $true)
    if ($savefile) { $this.Save() };
    $nf = ''; [ValidateNotNullOrWhiteSpace()][string]$nf = $this.Exists ? (Rename-Item -Path $this.FullName -NewName $nn -Force -Verbose:$false -PassThru) : ([IO.Path]::Combine((Split-Path $this.FullName), $nn))
    if ($?) { $this.set_fullName($nf) }
  }
  static [bool] IsValidFilePath([string]$fileName) {
    return [ConfigFile]::IsValidFilePath($fileName, $false)
  }
  static [bool] IsValidFilePath([string]$fileName, [bool]$throwOnFailure) {
    if ([string]::IsNullOrWhiteSpace($fileName) -and $throwOnFailure) { throw [ArgumentNullException]::new("Please provide a valid filePath.") }
    $c = [string[]][char[]]$fileName
    $v = [IO.Path]::IsPathFullyQualified($fileName); if (!$v) {
      $i = [string[]][IO.Path]::GetInvalidFileNameChars()
      $v = $c.Where({ $_ -in $i }).count -eq 0
    }
    $v = $v -and ($c.Where({ $_ -in ([IO.Path]::GetInvalidPathChars()) }).count -eq 0)
    if (!$v -and $throwOnFailure) { throw [ArgumentException]::new("Invalid filePath. See [Path]::GetInvalidFileNameChars() and [Path]::GetInvalidPathChars()") }
    return $v
  }
  [FileInfo] CopyTo([string]$destFileName) {
    return $this.CopyTo($destFileName, $false)
  }
  [FileInfo] CopyTo([string]$destFileName, [bool]$overwrite) {
    [void][ConfigFile]::IsValidFilePath($destFileName, $true); $this.Save()
    return Copy-Item -Path $this.FullName -Destination ([PsModuleBase]::GetUnResolvedPath($destFileName)) -Force:$overwrite -PassThru
  }
  [void] Save() {
    $this.Save($this.ToJson())
  }
  [void] Save([string]$content) {
    [ValidateNotNullOrWhiteSpace()][string]$content = $content
    if (!$this.Exists) { $s = [IO.File]::Create($this.FullName); $s.Close(); $s.Dispose() }
    [IO.File]::WriteAllText($this.FullName, $content)
  }
  [FileInfo] MoveTo([string]$destDirName) {
    return $this.MoveTo($destDirName, $false)
  }
  [FileInfo] MoveTo([string]$destDirName, [bool]$overwrite) {
    [void][ConfigFile]::IsValidFilePath($destDirName, $true); $this.Save()
    [FileInfo]$nf = Move-Item -Path $this.FullName -Destination ([PsModuleBase]::GetUnResolvedPath($destDirName)) -Force:$overwrite -PassThru
    if ($?) { $this.set_fullName($nf) }
    return $nf
  }
  hidden [void] set_fullName([string]$value) {
    $nf = ''; [ValidateNotNullOrWhiteSpace()][string]$nf = [PsModuleBase]::GetUnResolvedPath($value)
    $this.SetDirectory((Split-Path $nf -ea Stop));
    $this.PsObject.Properties.Add([PSScriptProperty]::new('FullName', [scriptblock]::Create("return '$nf'"), { Param([string]$value) $this.set_fullName($value) }))
  }
  [string] ReadAllText() {
    return [IO.File]::ReadAllText($this.FullName)
  }
  [IEnumerable[string]] ReadLines() {
    return [IO.File]::ReadLines($this.FullName)
  }
  [byte[]] ReadAllBytes() {
    return [IO.File]::ReadAllBytes($this.FullName)
  }
  [string[]] ReadAllLines() {
    return [IO.File]::ReadAllLines($this.FullName)
  }
  [Hashtable] ToHashtable() {
    return @{
      Path   = $this.FullName
      Suffix = $this.GetSuffix()
    }
  }
  [void] Import([string]$FilePath) {
    $o = ConvertFrom-Json([IO.File]::ReadAllText([PsModuleBase]::GetResolvedPath($FilePath)))
    [ConfigFile]::new($o.Path, $o.Suffix).PsObject.Properties.Where({ $_.IsSettable }).ForEach({ $this.$_.Name = $_.value })
  }
  [string] ToJson() {
    return ConvertTo-Json($this.ToHashtable())
  }
  [string] ToClixml() {
    return [PSSerializer]::Serialize($this)
  }
  [string] ToString() {
    return $this.FullName
  }
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

class LocalPsModule : System.Management.Automation.IValidateSetValuesGenerator {
  [ValidateNotNullOrEmpty()][FileInfo]$Psd1
  [ValidateNotNullOrEmpty()][version]$version
  [ValidateNotNullOrWhiteSpace()][string]$Name
  [ValidateNotNullOrEmpty()][IO.DirectoryInfo]$Path
  [bool]$HasVersiondirs = $false
  static hidden [int]$ret = 0
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
    if ($null -eq $o) { throw [ArgumentException]::new("reference is null") };
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
  static [void] Install([string]$Name, [string]$Version) {
    # There are issues with pester 5.4.1 syntax, so I'll keep using -SkipPublisherCheck.
    # https://stackoverflow.com/questions/51508982/pester-sample-script-gets-be-is-not-a-valid-should-operator-on-windows-10-wo
    if ($Version -eq 'latest') {
      Install-Module -Name $Name -SkipPublisherCheck:$($Name -eq 'Pester')
    } else {
      Install-Module -Name $Name -RequiredVersion $Version -SkipPublisherCheck:$($Name -eq 'Pester')
    }
  }
  static [void] Update([string]$Name, [string]$Version) {
    try {
      if ($Version -eq 'latest') {
        Update-Module -Name $Name
      } else {
        Update-Module -Name $Name -RequiredVersion $Version
      }
    } catch {
      if ([LocalPsModule]::ret -lt 1 -and $_.ErrorRecord.Exception.Message -eq "Module '$Name' was not installed by using Install-Module, so it cannot be updated.") {
        Get-Module $Name | Remove-Module -Force -ErrorAction Ignore; [LocalPsModule]::ret++
        [LocalPsModule]::Update($Name, $Version)
      }
    }
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
  static [string] GetInstallPath([string]$Name, [string]$ReqVersion) {
    $p = [IO.DirectoryInfo][IO.Path]::Combine(
      $(if (!(Get-Variable -Name IsWindows -ErrorAction Ignore) -or $(Get-Variable IsWindows -ValueOnly)) {
          $_versionTable = Get-Variable PSVersionTable -ValueOnly
          $module_folder = if ($_versionTable.ContainsKey('PSEdition') -and $_versionTable.PSEdition -eq 'Core') { 'PowerShell' } else { 'WindowsPowerShell' }
          Join-Path -Path $([System.Environment]::GetFolderPath('MyDocuments')) -ChildPath $module_folder
        } else {
          Split-Path -Path ([System.Management.Automation.Platform]::SelectProductNameForDirectory('USER_MODULES')) -Parent
        }
      ), 'Modules'
    )
    if (![string]::IsNullOrWhiteSpace($ReqVersion)) {
      return [IO.Path]::Combine($p.FullName, $Name, $ReqVersion)
    } else {
      return [IO.Path]::Combine($p.FullName, $Name)
    }
  }
  [string[]] GetValidValues() {
    return ([string[]][LocalPsModule]::GetModulePaths() | Select-Object @{l = 'paths'; e = { [IO.Directory]::EnumerateDirectories($_) } }).paths | Split-Path -Leaf -ea Ignore
  }
  [void] Delete() {
    Remove-Item $this.Path -Recurse -Force -ErrorAction Ignore
  }
}

class PsModuleBase {
  #region Properties & Configuration Management
  static [string] $ConfigFolder
  static [string] $certFolder
  static [hashtable] $config = @{
    CertThumbprint   = ''
    CertFriendlyName = 'PsModuleBase Certificate'
    CertSubject      = ''
  }

  PsModuleBase() {
    # Determine OS-appropriate application data folder
    $appDataPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ApplicationData)
    if ((Get-Variable IsLinux).Value -or (Get-Variable IsMacOS).Value) {
      # Use a .config style path on Linux/macOS if preferred, or stick to ApplicationData mapping
      # Example: $appDataPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('UserProfile'), '.config')
      # For simplicity, we'll use the .NET mapping provided by ApplicationData for now.
    }

    [PsModuleBase]::ConfigFolder = [System.IO.Path]::Combine($appDataPath, "PowerShell", "PsModuleBase")
    [PsModuleBase]::certFolder = [System.IO.Path]::Combine([PsModuleBase]::ConfigFolder, 'certs')

    # Ensure directories exist
    if (!([System.IO.Directory]::Exists([PsModuleBase]::ConfigFolder))) {
      $null = [System.IO.Directory]::CreateDirectory([PsModuleBase]::ConfigFolder)
    }
    if (!([System.IO.Directory]::Exists([PsModuleBase]::certFolder))) {
      $null = [System.IO.Directory]::CreateDirectory([PsModuleBase]::certFolder)
    }

    # Load configuration if it exists
    $configPath = [System.IO.Path]::Combine([PsModuleBase]::ConfigFolder, 'config.clixml')
    if ([System.IO.File]::Exists($configPath)) {
      $prev_verbose = Get-Variable VerbosePreference -ValueOnly
      $prev_debug = Get-Variable DebugPreference -ValueOnly
      try {
        $VerbosePreference = 'SilentlyContinue'
        $DebugPreference = 'SilentlyContinue'
        [PsModuleBase]::config = Import-Clixml -Path $configPath
      } catch {
        Write-Warning "Failed to load PsModuleBase configuration from '$configPath': $($_.Exception.Message)"
      } finally {
        $VerbosePreference = $prev_verbose
        $DebugPreference = $prev_debug
      }
    }
  }
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
  hidden static [void] SaveConfiguration() {
    $configPath = [System.IO.Path]::Combine([PsModuleBase]::ConfigFolder, 'config.clixml')
    try {
      # Suppress verbose/debug output from Export-Clixml if not desired
      $prev_verbose = Get-Variable VerbosePreference -ValueOnly
      $prev_debug = Get-Variable DebugPreference -ValueOnly
      $VerbosePreference = 'SilentlyContinue'
      $DebugPreference = 'SilentlyContinue'
      [PsModuleBase]::config | Export-Clixml -Path $configPath -Force
    } catch {
      Write-Error "Failed to save PsModuleBase configuration to '$configPath': $($_.Exception.Message)"
      throw # Rethrow to indicate failure
    } finally {
      $VerbosePreference = $prev_verbose
      $DebugPreference = $prev_debug
    }
  }
  #endregion

  static [X509Certificate2[]] GetCertificate([bool]$CurrentOnly = $false) {
    # .SYNOPSIS
    #     Retrieves PsModuleBase certificates from the current user's personal store.
    # .DESCRIPTION
    #     Retrieves X509Certificate2 objects configured for use with PsModuleBase based on stored configuration (Thumbprint, Subject, or Friendly Name).
    # .PARAMETER CurrentOnly
    #     Specifies to return only the most current (latest expiry) matching certificate.
    # .OUTPUTS
    #     System.Security.Cryptography.X509Certificates.X509Certificate2[]
    $store = $null
    $certificates = [System.Collections.Generic.List[X509Certificate2]]::new()
    try {
      $store = [X509Store]::new([StoreName]::My, [StoreLocation]::CurrentUser)
      $store.Open([OpenFlags]::ReadOnly)

      # Define the filter criteria based on configuration
      $configThumbprint = [PsModuleBase]::config.CertThumbprint
      $configSubject = [PsModuleBase]::config.CertSubject
      $configFriendlyName = [PsModuleBase]::config.CertFriendlyName

      foreach ($cert in $store.Certificates) {
        $match = $false
        if ($configThumbprint -and $cert.Thumbprint -eq $configThumbprint) { $match = $true }
        elseif ($configSubject -and $cert.Subject -eq $configSubject) { $match = $true }
        elseif ($configFriendlyName -and $cert.FriendlyName -eq $configFriendlyName) { $match = $true }
        # Fallback if no specific config set, find any cert with the default friendly name
        elseif (!$configThumbprint -and !$configSubject -and !$configFriendlyName -and $cert.FriendlyName -eq 'PsModuleBase Certificate') { $match = $true }

        if ($match) {
          $certificates.Add($cert)
        }
      }
    } catch {
      Write-Error "Error accessing certificate store: $($_.Exception.Message)"
      # Return empty array on error
      return @()
    } finally {
      if ($null -ne $store) { $store.Close() }
    }

    $sortedCerts = $certificates | Sort-Object -Property NotAfter -Descending

    if ($CurrentOnly) {
      return @($sortedCerts | Select-Object -First 1)
    } else {
      return @($sortedCerts)
    }
  }

  static [X509Certificate2] CreateCertificate(
    # .SYNOPSIS
    #     Generate a new self-signed certificate for PsModuleBase use.
    # .DESCRIPTION
    #     Generates a new self-signed RSA certificate suitable for PsModuleBase (DigitalSignature, DataEncipherment)
    #     and stores it in the current user's personal certificate store.
    #     Relies on the New-SelfSignedCertificate cmdlet, which requires PowerShell 5.1+ on Windows or PowerShell Core 7+ cross-platform.
    # .PARAMETER Name
    #     The subject name for the certificate (e.g., 'CN=user@domain.com, O=PsModuleBase'). This becomes the CN part.
    # .PARAMETER YearsValid
    #     How many years the certificate should be valid for. Defaults to 20.
    # .PARAMETER FriendlyName
    #     The friendly name to assign. Defaults to 'PsModuleBase Certificate'.
    # .OUTPUTS
    #     System.Security.Cryptography.X509Certificates.X509Certificate2
    [string]$Name,
    [int]$YearsValid = 20,
    [string]$FriendlyName = 'PsModuleBase Certificate'
  ) {
    if (!$Name) {
      throw [System.ArgumentNullException]::new('Name', 'Certificate subject name cannot be empty.')
    }

    $subjectName = "CN=$Name, O=PsModuleBase" # Enforce OU for easier identification
    $notAfter = [datetime]::Now.AddYears($YearsValid)

    try {
      # Using the cmdlet here as it's the most straightforward way in PS cross-platform for self-signed.
      # For a pure .NET SDK, a library like BouncyCastle would be needed for generation.
      $cert = New-SelfSignedCertificate -KeyUsage DigitalSignature, DataEncipherment -Subject $subjectName -CertStoreLocation Cert:\CurrentUser\My -NotAfter $notAfter -FriendlyName $FriendlyName -KeyAlgorithm RSA -KeyLength 2048 -ErrorAction Stop
      return $cert
    } catch {
      Write-Error "Failed to create self-signed certificate: $($_.Exception.Message)"
      throw # Rethrow
    }
  }
  static [void] SetCurrentUserCertificate([string]$InputStr) {
    # .SYNOPSIS
    #     Configures the primary certificate PsModuleBase should use for signing/identifying the user.
    # .DESCRIPTION
    #     Updates the PsModuleBase configuration to identify the user's primary certificate by Thumbprint, FriendlyName, or Subject.
    #     The certificate selected by FriendlyName or Subject will be the one with the latest expiration date if multiple match.
    $newConfig = @{
      CertThumbprint   = ''
      CertFriendlyName = ''
      CertSubject      = ''
    }
    # Basic validation: Ensure at least one identifier is provided
    switch ($true) {
      ([PsModuleBase]::IsThumbprint($InputStr)) {
        $newConfig.CertThumbprint = $InputStr.ToUpperInvariant()
        break
      }
      ([PsModuleBase]::IsFriendlyName($InputStr)) {
        $newConfig.CertFriendlyName = $InputStr
        break
      }
      ([PsModuleBase]::IsSubject($InputStr)) {
        $newConfig.CertSubject = $InputStr
        break
      }
      Default {
        throw [System.ArgumentException]::new("Must specify one of Thumbprint, FriendlyName, or Subject.")
      }
    }
    [PsModuleBase]::config = $newConfig
    [PsModuleBase]::SaveConfiguration()
    Write-Verbose "PsModuleBase configuration updated."
  }
  static [bool] IsThumbprint([string]$InputStr) {
    return [Regex]::IsMatch($InputStr, '^[0-9A-Fa-f]{40}$')
  }
  static [bool] IsSubject([string]$InputStr) {
    # Checks for common DN attribute types followed by '='. This is an approximation.
    # Adjust the list (CN|O|OU|...) as needed for common attributes you expect.
    # Using \b ensures these are whole words (prevents matching 'ACNP=')
    # Matches if *any* part looks like a DN component.
    return $InputStr -match '\b(CN|O|OU|L|S|C|E|SN|G|I|DC|STREET)\s*='
    # Alternative simpler (but potentially less accurate) check: just look for an equals sign
    # return $InputStr -match '='
  }
  static [bool] IsFriendlyName([string]$InputStr) {
    # A friendly name is assumed if it's not empty, not a thumbprint, and not a subject.
    return (![string]::IsNullOrWhiteSpace($InputStr)) -and (![PsModuleBase]::IsThumbprint($InputStr)) -and (![PsModuleBase]::IsSubject($InputStr))
  }

  static [string] ExportCertificatePublicKey() {
    # .SYNOPSIS
    #     Exports the public key information of the current user's certificate.
    # .DESCRIPTION
    #     Retrieves the current user's active PsModuleBase certificate, extracts its public key information (raw certificate data),
    #     and formats it as a JSON string suitable for sharing with contacts.
    # .OUTPUTS
    #     String (JSON formatted contact data)

    # Get the single, most current certificate configured for the user
    $cert = @([PsModuleBase]::GetCertificate($true))[0]
    if (!$cert) {
      throw "No active PsModuleBase certificate found for the current user. Use New-PsCertificate or Set-PsCertificate first."
    }

    $certBytes = $cert.Export([X509ContentType]::Cert) # Use Export for raw data

    $data = @{
      # Extract CN cleanly, assuming format "CN=Name, O=PsModuleBase"
      Name = $cert.SubjectName.Name -replace '^CN=|, O=PsModuleBase$'
      Cert = [System.Convert]::ToBase64String($certBytes)
    }

    # ConvertTo-Json depth might need adjustment if complex objects were used, but simple hashtable is fine.
    return $data | ConvertTo-Json -Depth 3
  }

  static [PSCustomObject[]] GetContact([string]$Name = '*') {
    # .SYNOPSIS
    #     Get a list of saved PsModuleBase contacts.
    # .DESCRIPTION
    #     Retrieves contact information (including their public certificate) stored locally. Contacts are needed to encrypt data for recipients.
    # .PARAMETER Name
    #     The name or thumbprint of the contact to filter by (supports wildcards for name). Defaults to '*'.
    # .OUTPUTS
    #     PSCustomObject[] (PsModuleBase.Contact objects)
    $contacts = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
      # Iterate through files in the certs folder
      # Use EnumerateFiles for potentially better performance on large directories
      foreach ($filePath in [System.IO.Directory]::EnumerateFiles([PsModuleBase]::certFolder, '*.clixml')) {
        $prev_verbose = Get-Variable VerbosePreference -ValueOnly
        $prev_debug = Get-Variable DebugPreference -ValueOnly
        try {
          $VerbosePreference = 'SilentlyContinue'
          $DebugPreference = 'SilentlyContinue'

          $contact = Import-Clixml -Path $filePath

          # Add type name if missing (robustness)
          if ($contact.PSObject.TypeNames -notcontains 'PsModuleBase.Contact') {
            $contact.PSObject.TypeNames.Insert(0, 'PsModuleBase.Contact')
          }

          # Filter based on Name (wildcard) or Thumbprint (exact)
          if (($contact.Name -like $Name) -or ($contact.Thumbprint -like $Name)) {
            # Perform a quick sanity check on the deserialized object
            if ($contact.Name -and $contact.Thumbprint -and $contact.Certificate -is [X509Certificate2]) {
              $contacts.Add($contact)
            } else {
              Write-Warning "Skipping invalid contact file: $filePath"
            }
          }
        } catch {
          Write-Warning "Failed to import contact file '$filePath': $($_.Exception.Message)"
        } finally {
          $VerbosePreference = $prev_verbose
          $DebugPreference = $prev_debug
        }
      }
    } catch {
      Write-Error "Error reading contacts directory '$([PsModuleBase]::certFolder)': $($_.Exception.Message)"
    }

    # Return unique contacts (in case both name.clixml and thumbprint.clixml exist)
    # Sort by name for consistent output
    return @($contacts | Sort-Object -Property Name, Thumbprint -Unique)
  }

  static [PSCustomObject] ImportContactData(
    # .SYNOPSIS
    #     Imports contact information from a JSON string or file.
    # .DESCRIPTION
    #     Parses JSON data containing a contact's name and public certificate (Base64 encoded),
    #     validates the certificate (optionally checking trust), and saves it locally for later use in encryption.
    #     Saves the contact information twice: once as '<Name>.clixml' and once as '<Thumbprint>.clixml' for easy lookup.
    # .PARAMETER JsonData
    #     The JSON string containing the contact information (usually from Export-PsCertificate).
    # .PARAMETER TrustedOnly
    #     If $true, verifies that the contact's certificate chains to a trusted root authority. Defaults to $false (allowing self-signed).
    # .OUTPUTS
    #     PSCustomObject (The imported PsModuleBase.Contact object)
    [string]$JsonData,
    [bool]$TrustedOnly = $false
  ) {
    if (!$JsonData) {
      throw [System.ArgumentNullException]::new('JsonData', 'Input JSON data cannot be empty.')
    }

    $jsonContent = $null
    try {
      $jsonContent = $JsonData | ConvertFrom-Json -ErrorAction Stop
    } catch {
      throw [System.ArgumentException]::new("Invalid JSON data provided: $($_.Exception.Message)", $_.Exception)
    }

    if (!$jsonContent.Name -or !$jsonContent.Cert) {
      throw [System.ArgumentException]::new('Invalid JSON structure - ensure the data has "Name" and "Cert" properties (generated via Export-PsCertificate).')
    }

    $certificate = $null
    try {
      $bytes = [System.Convert]::FromBase64String($jsonContent.Cert)
      # Use constructor that doesn't require private key password
      $certificate = [X509Certificate2]::new($bytes)
    } catch {
      throw [System.ArgumentException]::new("Invalid certificate data for contact '$($jsonContent.Name)': $($_.Exception.Message)", $_.Exception)
    }

    # Verify trust if requested
    if ($TrustedOnly) {
      $chain = [X509Chain]::new()
      # Basic chain validation (adjust policy checks as needed)
      $chain.ChainPolicy.RevocationMode = [X509RevocationMode]::Online
      $chain.ChainPolicy.VerificationFlags = [X509VerificationFlags]::NoFlag # Adjust as needed
      if (!$chain.Build($certificate)) {
        $statusInfo = ($chain.ChainStatus | ForEach-Object StatusInformation) -join '; '
        throw [System.Security.SecurityException]::new("Certificate for '$($jsonContent.Name)' (Subject: $($certificate.Subject), Thumbprint: $($certificate.Thumbprint)) is not trusted. Chain status: $statusInfo")
      }
      Write-Verbose "Certificate for $($jsonContent.Name) passed trust validation."
    }

    $certData = [PSCustomObject]@{
      PSTypeName  = 'PsModuleBase.Contact'
      Name        = $jsonContent.Name
      Thumbprint  = $certificate.Thumbprint.ToUpperInvariant() # Consistent casing
      NotAfter    = $certificate.NotAfter
      Certificate = $certificate # Store the full cert object
    }

    # Sanitize name for file system
    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $safeName = $certData.Name -replace "[$invalidChars]", '_'

    # Define export paths
    $exportPathByName = [System.IO.Path]::Combine([PsModuleBase]::certFolder, "$safeName.clixml")
    $exportPathByThumb = [System.IO.Path]::Combine([PsModuleBase]::certFolder, "$($certData.Thumbprint).clixml")

    try {
      # Suppress Export-Clixml output streams
      $prev_verbose = Get-Variable VerbosePreference -ValueOnly
      $prev_debug = Get-Variable DebugPreference -ValueOnly
      $VerbosePreference = 'SilentlyContinue'
      $DebugPreference = 'SilentlyContinue'

      # Use -Force to overwrite existing contacts with the same name/thumbprint
      $certData | Export-Clixml -Path $exportPathByName -Force
      $certData | Export-Clixml -Path $exportPathByThumb -Force

      Write-Verbose "Contact '$($certData.Name)' ($($certData.Thumbprint)) saved successfully."
      return $certData
    } catch {
      Write-Error "Failed to save contact '$($certData.Name)' to '$([PsModuleBase]::certFolder)': $($_.Exception.Message)"
      throw # Rethrow
    } finally {
      $VerbosePreference = $prev_verbose
      $DebugPreference = $prev_debug
    }
  }

  static [void] RemoveContact([string[]]$Identity) {
    # .SYNOPSIS
    #     Remove a contact (or contacts) from the local store.
    # .DESCRIPTION
    #     Finds contacts matching the provided name(s) or thumbprint(s) and deletes their associated .clixml files from the configuration directory.
    # .PARAMETER Identity
    #     An array of contact names or thumbprints to remove. Wildcards are NOT supported here; use Get-PsContact first if needed.
    if (!$Identity) { return } # Nothing to do

    foreach ($id in $Identity) {
      $contactsToRemove = @([PsModuleBase]::GetContact($id)) # Find contacts matching the exact name or thumbprint

      if (!$contactsToRemove) {
        Write-Warning "Contact '$id' not found, skipping removal."
        continue
      }

      foreach ($contact in $contactsToRemove) {
        # Sanitize name for file system matching
        $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''
        $safeName = $contact.Name -replace "[$invalidChars]", '_'

        $pathByName = Join-Path -Path [PsModuleBase]::certFolder -ChildPath "$safeName.clixml"
        $pathByThumb = Join-Path -Path [PsModuleBase]::certFolder -ChildPath "$($contact.Thumbprint).clixml"

        $removed = $false
        try {
          if ([System.IO.File]::Exists($pathByName)) {
            [System.IO.File]::Delete($pathByName)
            Write-Verbose "Removed contact file: $pathByName"
            $removed = $true
          }
          if ([System.IO.File]::Exists($pathByThumb)) {
            [System.IO.File]::Delete($pathByThumb)
            Write-Verbose "Removed contact file: $pathByThumb"
            $removed = $true
          }
          if ($removed) {
            Write-Verbose "Successfully removed contact '$($contact.Name)' ($($contact.Thumbprint))."
          } else {
            Write-Warning "Could not find files for contact '$($contact.Name)' ($($contact.Thumbprint)) to remove."
          }
        } catch {
          Write-Error "Error removing files for contact '$($contact.Name)': $($_.Exception.Message)"
          # Continue to next contact even if one fails
        }
      }
    }
  }

  #region Encryption/Decryption Methods (Originals with minor .NET adjustments)

  # Helper to get RSA keys safely
  hidden static [RSA] GetRsaPublicKey([X509Certificate2]$Certificate) {
    $rsa = $Certificate.GetRSAPublicKey()
    if ($null -eq $rsa) { throw "Certificate (Thumbprint: $($Certificate.Thumbprint)) does not contain an RSA public key." }
    return $rsa
  }
  hidden static [RSA] GetRsaPrivateKey([X509Certificate2]$Certificate) {
    if (!$Certificate.HasPrivateKey) { throw "Certificate (Thumbprint: $($Certificate.Thumbprint)) does not have an associated private key accessible." }
    $rsa = $Certificate.GetRSAPrivateKey()
    if ($null -eq $rsa) { throw "Failed to retrieve RSA private key for certificate (Thumbprint: $($Certificate.Thumbprint)). Check key permissions." }
    return $rsa
  }

  <# Internal Use / Called by Protect-Document #>
  static [string] ProtectFile(
    [string]$Path,
    [X509Certificate2]$OwnCertificate,
    # Contact object expected from Get-PsContact
    [PSCustomObject]$Contact,
    [string]$OutPath, # Optional: Directory to write output file
    [switch]$PassThru # If true, return JSON string instead of writing file
  ) {
    if (!([System.IO.File]::Exists($Path))) { throw [System.IO.FileNotFoundException]::new("Input file not found.", $Path) }
    if ($OutPath -and !([System.IO.Directory]::Exists($OutPath))) { throw [System.IO.DirectoryNotFoundException]::new("Output directory not found.", $OutPath) }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $publicKey = [PsModuleBase]::GetRsaPublicKey($Contact.Certificate)
    $privateKey = [PsModuleBase]::GetRsaPrivateKey($OwnCertificate) # Signing key

    $bytesEncrypted = $publicKey.Encrypt($bytes, [RSAEncryptionPadding]::Pkcs1)
    $bytesSignature = $privateKey.SignData($bytesEncrypted, [HashAlgorithmName]::SHA512, [RSASignaturePadding]::Pkcs1)

    $fileName = [System.IO.Path]::GetFileName($Path)
    $data = [ordered]@{ # Use ordered hashtable for consistent JSON output
      Name            = $fileName
      Recipient       = $Contact.Name
      Type            = 'File'
      SignThumbprint  = $OwnCertificate.Thumbprint.ToUpperInvariant()
      CryptThumbprint = $Contact.Certificate.Thumbprint.ToUpperInvariant()
      Data            = [System.Convert]::ToBase64String($bytesEncrypted)
      Signature       = [System.Convert]::ToBase64String($bytesSignature)
    }

    $jsonData = $data | ConvertTo-Json -Depth 3

    if ($PassThru) {
      return $jsonData
    }

    $outputFileName = "$fileName.json"
    $finalOutputPath = if ($OutPath) {
      [System.IO.Path]::Combine($OutPath, $outputFileName)
    } else {
      [System.IO.Path]::ChangeExtension($Path, '.json') # Place next to original
    }

    try {
      [System.IO.File]::WriteAllText($finalOutputPath, $jsonData, [System.Text.Encoding]::UTF8)
      # Use Write-Host for user feedback consistent with original functions
      Write-Host "Protected file created at: $finalOutputPath"
      return $jsonData # Return the JSON data even when writing file
    } catch {
      Write-Error "Failed to write protected file to '$finalOutputPath': $($_.Exception.Message)"
      throw
    }
  }

  <# Internal Use / Called by Protect-Document #>
  static [string] ProtectContent(
    [string]$Content,
    [string]$Name,
    [X509Certificate2]$OwnCertificate,
    # Contact object expected from Get-PsContact
    [PSCustomObject]$Contact
  ) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $publicKey = [PsModuleBase]::GetRsaPublicKey($Contact.Certificate)
    $privateKey = [PsModuleBase]::GetRsaPrivateKey($OwnCertificate) # Signing key

    $bytesEncrypted = $publicKey.Encrypt($bytes, [RSAEncryptionPadding]::Pkcs1)
    $bytesSignature = $privateKey.SignData($bytesEncrypted, [HashAlgorithmName]::SHA512, [RSASignaturePadding]::Pkcs1)

    $data = [ordered]@{ # Use ordered hashtable for consistent JSON output
      Name            = $Name
      Recipient       = $Contact.Name
      Type            = 'Content'
      SignThumbprint  = $OwnCertificate.Thumbprint.ToUpperInvariant()
      CryptThumbprint = $Contact.Certificate.Thumbprint.ToUpperInvariant()
      Data            = [System.Convert]::ToBase64String($bytesEncrypted)
      Signature       = [System.Convert]::ToBase64String($bytesSignature)
    }
    return $data | ConvertTo-Json -Depth 3
  }

  <# Internal Use / Called by Unprotect-Document #>
  static [string] UnprotectDataset(
    [string]$JsonContent,
    [string]$OutDirectory, # Directory to write output file, mandatory for Type=File
    $Cmdlet # Pass calling cmdlet for WriteError context
  ) {
    $c = $null
    try {
      $c = $JsonContent | ConvertFrom-Json -ErrorAction Stop
    } catch {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId InvalidJson -Category InvalidData -Message "Failed to parse input JSON: $($_.Exception.Message)" -TargetObject $JsonContent -Exception $_.Exception) )
      return $null # Return null/empty on failure
    }

    # Validate basic structure
    if (!($c.Name -and $c.Type -and $c.SignThumbprint -and $c.CryptThumbprint -and $c.Data -and $c.Signature)) {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId MissingJsonProperties -Category InvalidData -Message "Input JSON is missing required properties (Name, Type, SignThumbprint, CryptThumbprint, Data, Signature)." -TargetObject $c) )
      return $null
    }

    # --- Certificate Retrieval using .NET Store ---
    $recipientCert = $null
    $senderCert = $null # This comes from saved Contacts
    $store = $null
    try {
      # Find Recipient Cert (current user's private key needed)
      $store = [X509Store]::new([StoreName]::My, [StoreLocation]::CurrentUser)
      $store.Open([OpenFlags]::ReadOnly)
      $results = $store.Certificates.Find([X509FindType]::FindByThumbprint, $c.CryptThumbprint, $false) # false = only valid certs? check documentation. Usually true. Let's try false for broader match first.
      if ($results.Count -gt 0) {
        # Ensure it has a private key we can access
        $recipientCert = $results | Where-Object { $_.HasPrivateKey } | Sort-Object -Property NotAfter -Descending | Select-Object -First 1
      }
    } catch {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId StoreAccessError -Category ResourceUnavailable -Message "Error accessing certificate store: $($_.Exception.Message)" -TargetObject $c.CryptThumbprint -Exception $_.Exception) )
      return $null
    } finally {
      if ($null -ne $store) { $store.Close() }
    }

    if (!$recipientCert) {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId DecryptionCertNotFound -Category ObjectNotFound -Message "Cannot find usable certificate with private key matching thumbprint '$($c.CryptThumbprint)' in the CurrentUser\My store to decrypt data: $($c.Name)" -TargetObject $c) )
      return $null
    }
    Write-Verbose "Using certificate '$($recipientCert.Subject)' for decryption."

    # Find Sender Cert (from saved contacts)
    $senderContact = @([PsModuleBase]::GetContact($c.SignThumbprint) | Sort-Object NotAfter -Descending | Select-Object -First 1)[0]
    if (!$senderContact) {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId VerificationCertNotFound -Category ObjectNotFound -Message "Cannot find contact certificate matching signing thumbprint '$($c.SignThumbprint)' to verify the sender: $($c.Name). Import the sender's contact information first." -TargetObject $c) )
      return $null
    }
    $senderCert = $senderContact.Certificate
    Write-Verbose "Using contact certificate '$($senderCert.Subject)' for signature verification."

    # --- Decryption and Verification ---
    $bytesData = $null
    $bytesSignature = $null
    try {
      $bytesData = [System.Convert]::FromBase64String($c.Data)
      $bytesSignature = [System.Convert]::FromBase64String($c.Signature)
    } catch {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId InvalidBase64 -Category InvalidData -Message "Invalid Base64 format for data or signature: $($c.Name)" -TargetObject $c -Exception $_.Exception) )
      return $null
    }

    # Verify Signature First
    $senderPK = [PsModuleBase]::GetRsaPublicKey($senderCert)
    $isFromSender = $false
    try {
      $isFromSender = $senderPK.VerifyData($bytesData, $bytesSignature, [HashAlgorithmName]::SHA512, [RSASignaturePadding]::Pkcs1)
    } catch {
      # Catch potential crypto exceptions during verification
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId VerificationCryptoError -Category InvalidData -Message "Cryptographic error during signature verification for '$($c.Name)': $($_.Exception.Message)" -TargetObject $c -Exception $_.Exception) )
      return $null
    }
    if (!$isFromSender) {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId InvalidSignature -Category SecurityError -Message "Invalid signature! Data '$($c.Name)' could not be verified to originate from sender with certificate '$($senderCert.Subject)' (Thumbprint: $($senderCert.Thumbprint))!" -TargetObject $c) )
      return $null
    }
    Write-Verbose "Signature verified successfully for '$($c.Name)'."

    # Decrypt Data
    $recipientSK = [PsModuleBase]::GetRsaPrivateKey($recipientCert) # Private key
    $decryptedBytes = $null
    try {
      $decryptedBytes = $recipientSK.Decrypt($bytesData, [RSAEncryptionPadding]::Pkcs1)
    } catch {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId DecryptionFailed -Category InvalidData -Message "Error decrypting data! '$($c.Name)' could not be decrypted with certificate '$($recipientCert.Subject)' (Thumbprint: $($recipientCert.Thumbprint)): $($_.Exception.Message)" -TargetObject $c -Exception $_.Exception) )
      return $null
    }
    Write-Verbose "Data decrypted successfully for '$($c.Name)'."

    # --- Output Handling ---
    if ($c.Type -eq 'Content') {
      $content = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
      if ($OutDirectory) {
        # Write to file if OutDirectory is specified for content
        if (!([System.IO.Directory]::Exists($OutDirectory))) {
          $Cmdlet.WriteError( (New-ErrorRecord -ErrorId OutDirNotFoundContent -Category InvalidArgument -Message "Output directory '$OutDirectory' not found for writing decrypted content '$($c.Name)'." -TargetObject $c) )
          return $null # Stop processing this item
        }
        $exportPath = [System.IO.Path]::Combine($OutDirectory, $c.Name)
        try {
          [System.IO.File]::WriteAllText($exportPath, $content, [System.Text.Encoding]::UTF8)
          Write-Host "Unprotected content written to file: $exportPath"
        } catch {
          $Cmdlet.WriteError( (New-ErrorRecord -ErrorId WriteContentFileError -Category WriteError -Message "Error writing unprotected content file '$exportPath': $($_.Exception.Message)" -TargetObject $exportPath -Exception $_.Exception) )
          # Return the content anyway? Or null? Let's return null as the file write failed.
          return $null
        }
      }
      return $content # Return string content
    } elseif ($c.Type -eq 'File') {
      if (!$OutDirectory) {
        # This check should ideally happen in the calling function, but double-check here.
        $Cmdlet.WriteError( (New-ErrorRecord -ErrorId OutDirMissingFile -Category InvalidArgument -Message "Invalid state: Encrypted data indicates Type 'File' but no OutDirectory was provided to UnprotectDataset for '$($c.Name)'." -TargetObject $c) )
        return $null
      }
      if (!([System.IO.Directory]::Exists($OutDirectory))) {
        $Cmdlet.WriteError( (New-ErrorRecord -ErrorId OutDirNotFoundFile -Category InvalidArgument -Message "Output directory '$OutDirectory' not found for writing decrypted file '$($c.Name)'." -TargetObject $c) )
        return $null
      }

      $exportPath = [System.IO.Path]::Combine($OutDirectory, $c.Name)
      try {
        [System.IO.File]::WriteAllBytes($exportPath, $decryptedBytes)
        Write-Host "Unprotected file written to: $exportPath"
        return $exportPath # Return the path to the created file
      } catch {
        $Cmdlet.WriteError( (New-ErrorRecord -ErrorId WriteFileError -Category WriteError -Message "Error writing unprotected file '$exportPath': $($_.Exception.Message)" -TargetObject $exportPath -Exception $_.Exception) )
        return $null # Return null on file write failure
      }
    } else {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId UnknownDataType -Category InvalidData -Message "Unknown data Type '$($c.Type)' encountered in protected data '$($c.Name)'." -TargetObject $c) )
      return $null
    }
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
  [ModuleItem], [ModuleFile], [ConfigFile], [ModuleItemType], [SearchParams], [ModuleFolder]
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
