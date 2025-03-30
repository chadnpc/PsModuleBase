function Get-ModuleCodereviewyaml {
  [CmdletBinding()][OutputType([string])]
  param (
    [Parameter(Position = 0, Mandatory = $false)]
    [Alias('n')][AllowNull()]
    [string]$ModuleName
  )

  process {
    if ([string]::IsNullOrWhiteSpace($ModuleName)) {
      return [Encoding]::UTF8.GetString([Convert]::FromBase64String("bmFtZTogQ29kZSBSZXZpZXcKcGVybWlzc2lvbnM6CiAgY29udGVudHM6IHJlYWQKICBwdWxsLXJlcXVlc3RzOiB3cml0ZQoKb246CiAgcHVsbF9yZXF1ZXN0OgogICAgdHlwZXM6IFtvcGVuZWQsIHJlb3BlbmVkLCBzeW5jaHJvbml6ZV0KCmpvYnM6CiAgdGVzdDoKICAgIHJ1bnMtb246IHVidW50dS1sYXRlc3QKICAgIHN0ZXBzOgogICAgICAtIHVzZXM6IGFuYzk1L0NoYXRHUFQtQ29kZVJldmlld0B2MS4wLjEyCiAgICAgICAgZW52OgogICAgICAgICAgR0lUSFVCX1RPS0VOOiAke3sgc2VjcmV0cy5HSVRIVUJfVE9LRU4gfX0KICAgICAgICAgIE9QRU5BSV9BUElfS0VZOiAke3sgc2VjcmV0cy5PUEVOQUlfQVBJX0tFWSB9fQogICAgICAgICAgTEFOR1VBR0U6IEVuZ2xpc2gKICAgICAgICAgIE9QRU5BSV9BUElfRU5EUE9JTlQ6IGh0dHBzOi8vYXBpLm9wZW5haS5jb20vdjEKICAgICAgICAgIE1PREVMOiBncHQtNG8gIyBodHRwczovL3BsYXRmb3JtLm9wZW5haS5jb20vZG9jcy9tb2RlbHMKICAgICAgICAgIFBST01QVDogUGxlYXNlIGNoZWNrIGlmIHRoZXJlIGFyZSBhbnkgY29uZnVzaW9ucyBvciBpcnJlZ3VsYXJpdGllcyBpbiB0aGUgZm9sbG93aW5nIGNvZGUgZGlmZgogICAgICAgICAgdG9wX3A6IDEKICAgICAgICAgIHRlbXBlcmF0dXJlOiAxCiAgICAgICAgICBtYXhfdG9rZW5zOiAxMDAwMAogICAgICAgICAgTUFYX1BBVENIX0xFTkdUSDogMTAwMDAgIyBpZiB0aGUgcGF0Y2gvZGlmZiBsZW5ndGggaXMgbGFyZ2UgdGhhbiBNQVhfUEFUQ0hfTEVOR1RILCB3aWxsIGJlIGlnbm9yZWQgYW5kIHdvbid0IHJldmlldy4="));
    } else {
      throw [System.NotImplementedException]::new('WIP')
    }
  }
}