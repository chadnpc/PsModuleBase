function Get-ModulePublishyaml {
  [CmdletBinding()][OutputType([string])]
  param (
    [Parameter(Position = 0, Mandatory = $false)]
    [Alias('n')][AllowNull()]
    [string]$ModuleName
  )

  process {
    if ([string]::IsNullOrWhiteSpace($ModuleName)) {
      return [Encoding]::UTF8.GetString([Convert]::FromBase64String("bmFtZTogR2l0SHViIHJlbGVhc2UgYW5kIFB1Ymxpc2gKb246IFt3b3JrZmxvd19kaXNwYXRjaF0KZGVmYXVsdHM6CiAgcnVuOgogICAgc2hlbGw6IHB3c2gKam9iczoKICB1cGxvYWQtcGVzdGVyLXJlc3VsdHM6CiAgICBuYW1lOiBSdW4gUGVzdGVyIGFuZCB1cGxvYWQgcmVzdWx0cwogICAgcnVucy1vbjogdWJ1bnR1LWxhdGVzdAogICAgc3RlcHM6CiAgICAgIC0gdXNlczogYWN0aW9ucy9jaGVja291dEB2MwogICAgICAtIG5hbWU6IFRlc3Qgd2l0aCBQZXN0ZXIKICAgICAgICBzaGVsbDogcHdzaAogICAgICAgIHJ1bjogLi9UZXN0LU1vZHVsZS5wczEKICAgICAgLSBuYW1lOiBVcGxvYWQgdGVzdCByZXN1bHRzCiAgICAgICAgdXNlczogYWN0aW9ucy91cGxvYWQtYXJ0aWZhY3RAdjMKICAgICAgICB3aXRoOgogICAgICAgICAgbmFtZTogdWJ1bnR1LVVuaXQtVGVzdHMKICAgICAgICAgIHBhdGg6IFVuaXQuVGVzdHMueG1sCiAgICBpZjogJHt7IGFsd2F5cygpIH19CiAgcHVibGlzaC10by1nYWxsZXJ5OgogICAgbmFtZTogUHVibGlzaCB0byBQb3dlclNoZWxsIEdhbGxlcnkKICAgIHJ1bnMtb246IHVidW50dS1sYXRlc3QKICAgIHN0ZXBzOgogICAgICAtIHVzZXM6IGFjdGlvbnMvY2hlY2tvdXRAdjMKICAgICAgLSBuYW1lOiBQdWJsaXNoCiAgICAgICAgZW52OgogICAgICAgICAgR2l0SHViUEFUOiAke3sgc2VjcmV0cy5HaXRIdWJQQVQgfX0KICAgICAgICAgIE5VR0VUQVBJS0VZOiAke3sgc2VjcmV0cy5OVUdFVEFQSUtFWSB9fQogICAgICAgIHJ1bjogLi9idWlsZC5wczEgLVRhc2sgRGVwbG95"));
    } else {
      throw [System.NotImplementedException]::new('WIP')
    }
  }
}