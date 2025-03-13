function Get-ModuleReadmeText {
  [CmdletBinding()]
  param (
    [Parameter(Position = 0, Mandatory = $false)]
    [Alias('n')][AllowNull()]
    [string]$ModuleName
  )

  process {
    if ([string]::IsNullOrWhiteSpace($ModuleName)) {
      return [Encoding]::UTF8.GetString([Convert]::FromBase64String("CiMgWzxNb2R1bGVOYW1lPl0oaHR0cHM6Ly93d3cucG93ZXJzaGVsbGdhbGxlcnkuY29tL3BhY2thZ2VzLzxNb2R1bGVOYW1lPikKCvCflKUgQmxhemluZ2x5IGZhc3QgUG93ZXJTaGVsbCB0aGluZ3kgdGhhdCBzdG9ua3MgdXAgeW91ciB0ZXJtaW5hbCBnYW1lLgoKWyFbQnVpbGQgTW9kdWxlXShodHRwczovL2dpdGh1Yi5jb20vY2hhZG5wYy88TW9kdWxlTmFtZT4vYWN0aW9ucy93b3JrZmxvd3MvYnVpbGRfbW9kdWxlLnlhbWwvYmFkZ2Uuc3ZnKV0oaHR0cHM6Ly9naXRodWIuY29tL2NoYWRucGMvPE1vZHVsZU5hbWU+L2FjdGlvbnMvd29ya2Zsb3dzL2J1aWxkX21vZHVsZS55YW1sKQpbIVtEb3dubG9hZHNdKGh0dHBzOi8vaW1nLnNoaWVsZHMuaW8vcG93ZXJzaGVsbGdhbGxlcnkvZHQvPE1vZHVsZU5hbWU+LnN2Zz9zdHlsZT1mbGF0JmxvZ289cG93ZXJzaGVsbCZjb2xvcj1ibHVlKV0oaHR0cHM6Ly93d3cucG93ZXJzaGVsbGdhbGxlcnkuY29tL3BhY2thZ2VzLzxNb2R1bGVOYW1lPikKCiMjIFVzYWdlCgpgYGBQb3dlclNoZWxsCkluc3RhbGwtTW9kdWxlIDxNb2R1bGVOYW1lPgpgYGAKCnRoZW4KCmBgYFBvd2VyU2hlbGwKSW1wb3J0LU1vZHVsZSA8TW9kdWxlTmFtZT4KIyBkbyBzdHVmZiBoZXJlLgpgYGAKCiMjIExpY2Vuc2UKClRoaXMgcHJvamVjdCBpcyBsaWNlbnNlZCB1bmRlciB0aGUgW1dURlBMIExpY2Vuc2VdKExJQ0VOU0UpLgo="));
    } else {
      throw [System.NotImplementedException]::new("WIP")
    }
  }
}