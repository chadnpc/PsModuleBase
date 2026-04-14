# [PsModuleBase](https://www.powershellgallery.com/packages/PsModuleBase)

Provides basic Module structure and utility functions

[![Downloads](https://img.shields.io/powershellgallery/dt/PsModuleBase.svg?style=flat&logo=powershell&color=blue)](https://www.powershellgallery.com/packages/PsModuleBase)

## Usage

```PowerShell
Install-Module PsModuleBase
```

then

```PowerShell
Import-Module PsModuleBase
```

The `PsModuleBase` class acts as a foundational utility class for PowerShell module development. It provides a robust set of static methods for handling cross-platform file I/O, runtime environment checks, object recursion, and data validation.

By inheriting from this class, your custom PowerShell classes gain immediate access to these utilities without needing to instantiate an object.

## 1. Inheriting `PsModuleBase`

In PowerShell, when a class inherits from a base class, it inherits all its properties and methods—including static ones. You can access these static methods either by referencing the base class directly (`[PsModuleBase]::MethodName()`) or through your derived class (`[MyClass]::MethodName()`).

### Example: Basic Inheritance
```powershell
class MyCustomModule : PsModuleBase {

    # Example method using inherited static methods
    static [void] SetupEnvironment() {
        # 1. Check the operating system
        $os = [MyCustomModule]::GetHostOs()
        Write-Host "Running on: $os"

        # 2. Check for Administrator/Root privileges
        if (-not [MyCustomModule]::IsAdmin()) {
            throw "This module requires administrative privileges."
        }

        # 3. Create a cross-platform application data folder
        $dataPath = [MyCustomModule]::GetDataPath("MyCustomModule", "Logs")
        Write-Host "Log directory setup at: $($dataPath.FullName)"
    }
}
```

## 2. Static Methods Reference

The static methods are divided into several logical categories:

### A. Runtime & Environment Information
These methods provide context about the machine running the script, ensuring cross-platform compatibility.

*   **`[bool] IsAdmin()`**
    Checks if the current session is running with elevated privileges (Administrator on Windows, `root` on Linux).
*   **`[string] GetHostOs()`**
    Returns the current operating system as a string. Possible values: `"Windows"`, `"Linux"`, `"MacOSX"`, `"FreeBSD"`, or `"UNKNOWN"`.
*   **`[string] GetRuntimeUUID()`**
    Generates a unique identifier (UUID) based on the machine's hardware and OS configuration (MachineName, OSDescription, Architecture, and ProcessorCount).
*   **`[PSCustomObject] GetIpInfo()`**
    Fetches the machine's external IP and geographical information via a REST API call. ex:
    ```PowerShell
     [PsModuleBase]::GetIpInfo() | ConvertTo-Json
     {
      "country_name": "US",
      "location": {
        "geoname_id": "Ohio"
      },
      "city": "Florida"
    }
    ```

**Usage in a Derived Class:**
```powershell
class NetworkTool : PsModuleBase {
    static [void] DisplaySystemInfo() {
        $uuid = [NetworkTool]::GetRuntimeUUID()
        $ipData = [NetworkTool]::GetIpInfo()
        Write-Host "System UUID: $uuid - Location: $($ipData.city), $($ipData.country_name)"
    }
}
```

### B. File System & I/O (Paths & Folders)
Methods to safely handle paths, resolve provider paths, and manage directories across different operating systems.

*   **`[IO.DirectoryInfo] GetDataPath([string]$appName, [string]$SubdirName)`**
    Safely resolves and creates an application data path. On Windows, it uses `AppData\Roaming`; on Linux/Mac, it uses a path relative to the `PSModulePath`.
*   **`[string] GetRelativePath([string]$RelativeTo, [string]$Path)`**
    Calculates the relative path from a source directory to a destination path.
*   **`[string] GetResolvedPath([string]$Path)`**
    Safely resolves a relative PowerShell path (e.g., `.\folder`) to a full physical system path.
*   **`[DirectoryInfo] CreateFolder([string]$Path)`**
    Recursively creates a directory path, similar to `mkdir -p` or `New-Item -Force`.
*   **`[void] HideFolder([string]$Path)`**
    Applies `Hidden` and `System` attributes to a specified folder (Primarily for Windows).

**or in a Derived Class:**
```powershell
class ConfigManager : PsModuleBase {
    static [void] InitializeConfig([string]$configName) {
        # Safely resolve path
        $fullPath = [ConfigManager]::GetResolvedPath(".\$configName")

        # Calculate relative path back to root
        $relPath = [ConfigManager]::GetRelativePath("C:\AppRoot", $fullPath)

        # Setup cross-platform app data
        $appData = [ConfigManager]::GetDataPath("MyApp", "Settings")
        [ConfigManager]::HideFolder($appData.FullName)
    }
}
```

### C. Validation Utilities
Quick validation checks for strings, paths, and encodings.

*   **`[bool] IsValidBase64([string]$string)`**
    Strictly verifies if a string is a valid Base64 encoded string.
*   **`[bool] IsValidHex([string]$Text)`** / **`[bool] IsValidHex([byte[]]$bytes)`**
    Checks if a string is a valid hex color code (e.g., `#FFFFFF` or `FFF`), or validates byte arrays.
*   **`[void] ValidatePath([string]$path)`**
    Throws an exception if the provided path contains invalid characters based on the OS.

### D. Object Manipulation & Recursion
Advanced methods to parse, inspect, and manipulate generic objects and properties.

*   **`[string[]] ListProperties([System.Object]$Obj, [string]$Prefix)`**
    Recursively returns a string array of all nested property names within an object.
*   **`[PSObject] RecurseObject($Object, ...)`**
    Recursively flattens or inspects an object down to a specified `$Depth`, useful for deeply nested JSON or PSCustomObjects.
*   **`[Object[]] ExcludeProperties($Object, [string[]]$PropstoExclude)`**
    Strips out specific properties from a PowerShell object based on a list of names.

**or in a Derived Class:**
```powershell
class DataParser : PsModuleBase {
    static [void] AnalyzePayload($jsonPayload) {
        $obj = $jsonPayload | ConvertFrom-Json

        # Get all properties recursively
        $allProps = [DataParser]::ListProperties($obj)

        # Filter out sensitive data
        $safeData = [DataParser]::ExcludeProperties($obj, @("Password", "Token"))
    }
}
```

### E. Module Localization & PSD1 Data
Methods built specifically to read localized string data for PowerShell modules.

*   **`[bool] ValidadePsd1File([IO.FileInfo]$File)`**
    Validates if a file exists and ends in `.psd1`.
*   **`[Object] ReadModuledata([string]$ModuleName, [string]$key)`**
    Reads and evaluates a `<ModuleName>.strings.psd1` file from the `en-US` subdirectory of the module, returning either the whole hashtable or a specific key.


## 3. Configuration Properties

Because `PsModuleBase` initializes static variables upon being loaded, inheriting classes also have access to these configuration endpoints:

*   **`[PsModuleBase]::ConfigFolder`**: The absolute path to the generic PowerShell AppData configuration folder.
*   **`[PsModuleBase]::certFolder`**: A dedicated subdirectory for certificates.
*   **`[PsModuleBase]::config`**: A generic configuration hashtable that automatically tries to hydrate itself from a `config.clixml` file during module load.

**Example Accessing Properties:**
```powershell
class AuthManager : PsModuleBase {
    static [string] GetCertPath() {
        # Using the base class static properties directly
        $certDir = [AuthManager]::certFolder
        return Join-Path -Path $certDir -ChildPath "auth.pfx"
    }
}
```

## License

This project is licensed under the [WTFPL License](LICENSE).
