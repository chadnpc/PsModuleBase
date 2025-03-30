function Get-ModuleLicenseText {
  [CmdletBinding()][OutputType([string])]
  param (
    [Parameter(Position = 0, Mandatory = $false)]
    [Alias('n')][AllowNull()]
    [string]$ModuleName
  )

  begin {
    $txt = [string]::Empty
  }

  process {
    if ([string]::IsNullOrWhiteSpace($ModuleName)) {
      trap {
        Write-Warning "Failed to decode license text, lets get it fom web"
        $url = 'http://sam.zoy.org/wtfpl/COPYING'
        $req = Invoke-WebRequest $url -Verbose:$false -SkipHttpErrorCheck -ea Ignore
        if ($req.StatusCode -eq 200) {
          $TXT = [string]$req.Content
          if (![string]::IsNullOrWhiteSpace($TXT)) {
            $txt = $TXT.Replace('2004 Sam Hocevar <sam@hocevar.net>', "$([datetime]::Now.Year) $(Get-AuthorName) <$(Get-AuthorEmail)>")
          } else {
            Write-Warning "Got empty LICENSE from $url"
          }
        } else {
          Write-Warning "Failed to fetch LICENSE"
        }
      }
      $txt = [Encoding]::UTF8.GetString([Convert]::FromBase64String("ICAgICAgICAgICAgRE8gV0hBVCBUSEUgRlVDSyBZT1UgV0FOVCBUTyBQVUJMSUMgTElDRU5TRQ0KICAgICAgICAgICAgICAgICAgICBWZXJzaW9uIDIsIERlY2VtYmVyIDIwMDQNCg0KIDxDb3B5cmlnaHQ+DQoNCiBFdmVyeW9uZSBpcyBwZXJtaXR0ZWQgdG8gY29weSBhbmQgZGlzdHJpYnV0ZSB2ZXJiYXRpbSBvciBtb2RpZmllZA0KIGNvcGllcyBvZiB0aGlzIGxpY2Vuc2UgZG9jdW1lbnQsIGFuZCBjaGFuZ2luZyBpdCBpcyBhbGxvd2VkIGFzIGxvbmcNCiBhcyB0aGUgbmFtZSBpcyBjaGFuZ2VkLg0KDQogICAgICAgICAgICBETyBXSEFUIFRIRSBGVUNLIFlPVSBXQU5UIFRPIFBVQkxJQyBMSUNFTlNFDQogICBURVJNUyBBTkQgQ09ORElUSU9OUyBGT1IgQ09QWUlORywgRElTVFJJQlVUSU9OIEFORCBNT0RJRklDQVRJT04NCg0KICAwLiBZb3UganVzdCBETyBXSEFUIFRIRSBGVUNLIFlPVSBXQU5UIFRPLg0KDQo="));
    } else {
      throw [System.NotImplementedException]::new("WIP")
    }
  }

  end {
    return $txt
  }
}