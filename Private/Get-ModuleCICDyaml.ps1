function Get-ModuleCICDyaml {
  [CmdletBinding()][OutputType([string])]
  param (
    [Parameter(Position = 0, Mandatory = $false)]
    [Alias('n')][AllowNull()]
    [string]$ModuleName
  )

  process {
    if ([string]::IsNullOrWhiteSpace($ModuleName)) {
      return [Encoding]::UTF8.GetString([Convert]::FromBase64String("77u/bmFtZTogQnVpbGQgTW9kdWxlCm9uOiBbd29ya2Zsb3dfZGlzcGF0Y2hdCmRlZmF1bHRzOgogIHJ1bjoKICAgIHNoZWxsOiBwd3NoCgpqb2JzOgogIGJ1aWxkOgogICAgbmFtZTogUnVucyBvbgogICAgcnVucy1vbjogJHt7IG1hdHJpeC5vcyB9fQogICAgc3RyYXRlZ3k6CiAgICAgIGZhaWwtZmFzdDogZmFsc2UKICAgICAgbWF0cml4OgogICAgICAgIG9zOiBbd2luZG93cy1sYXRlc3QsIG1hY09TLWxhdGVzdF0KICAgIHN0ZXBzOgogICAgICAtIHVzZXM6IGFjdGlvbnMvY2hlY2tvdXRAdjMKICAgICAgLSBuYW1lOiBCdWlsZAogICAgICAgIHJ1bjogLi9idWlsZC5wczEgLVRhc2sgVGVzdA=="));
    } else {
      throw [System.NotImplementedException]::new("WIP")
    }
  }
}