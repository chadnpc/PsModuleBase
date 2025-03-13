﻿function Get-ModuleDelWorkflowsyaml {
  [CmdletBinding()][OutputType([string])]
  param (
    [Parameter(Position = 0, Mandatory = $false)]
    [Alias('n')][AllowNull()]
    [string]$ModuleName
  )

  process {
    if ([string]::IsNullOrWhiteSpace($ModuleName)) {
      # The b64str length is getting out of hand!!
      # TODO" Use compressed base85 (https://github.com/chadnpc/Encodkit) instead of base64
      return [Encoding]::UTF8.GetString([Convert]::FromBase64String("bmFtZTogRGVsZXRlIG9sZCB3b3JrZmxvdyBydW5zCm9uOgogIHdvcmtmbG93X2Rpc3BhdGNoOgogICAgaW5wdXRzOgogICAgICBkYXlzOgogICAgICAgIGRlc2NyaXB0aW9uOiAnRGF5cy13b3J0aCBvZiBydW5zIHRvIGtlZXAgZm9yIGVhY2ggd29ya2Zsb3cnCiAgICAgICAgcmVxdWlyZWQ6IHRydWUKICAgICAgICBkZWZhdWx0OiAnMCcKICAgICAgbWluaW11bV9ydW5zOgogICAgICAgIGRlc2NyaXB0aW9uOiAnTWluaW11bSBydW5zIHRvIGtlZXAgZm9yIGVhY2ggd29ya2Zsb3cnCiAgICAgICAgcmVxdWlyZWQ6IHRydWUKICAgICAgICBkZWZhdWx0OiAnMScKICAgICAgZGVsZXRlX3dvcmtmbG93X3BhdHRlcm46CiAgICAgICAgZGVzY3JpcHRpb246ICdOYW1lIG9yIGZpbGVuYW1lIG9mIHRoZSB3b3JrZmxvdyAoaWYgbm90IHNldCwgYWxsIHdvcmtmbG93cyBhcmUgdGFyZ2V0ZWQpJwogICAgICAgIHJlcXVpcmVkOiBmYWxzZQogICAgICBkZWxldGVfd29ya2Zsb3dfYnlfc3RhdGVfcGF0dGVybjoKICAgICAgICBkZXNjcmlwdGlvbjogJ0ZpbHRlciB3b3JrZmxvd3MgYnkgc3RhdGU6IGFjdGl2ZSwgZGVsZXRlZCwgZGlzYWJsZWRfZm9yaywgZGlzYWJsZWRfaW5hY3Rpdml0eSwgZGlzYWJsZWRfbWFudWFsbHknCiAgICAgICAgcmVxdWlyZWQ6IHRydWUKICAgICAgICBkZWZhdWx0OiAiQUxMIgogICAgICAgIHR5cGU6IGNob2ljZQogICAgICAgIG9wdGlvbnM6CiAgICAgICAgICAtICJBTEwiCiAgICAgICAgICAtIGFjdGl2ZQogICAgICAgICAgLSBkZWxldGVkCiAgICAgICAgICAtIGRpc2FibGVkX2luYWN0aXZpdHkKICAgICAgICAgIC0gZGlzYWJsZWRfbWFudWFsbHkKICAgICAgZGVsZXRlX3J1bl9ieV9jb25jbHVzaW9uX3BhdHRlcm46CiAgICAgICAgZGVzY3JpcHRpb246ICdSZW1vdmUgcnVucyBiYXNlZCBvbiBjb25jbHVzaW9uOiBhY3Rpb25fcmVxdWlyZWQsIGNhbmNlbGxlZCwgZmFpbHVyZSwgc2tpcHBlZCwgc3VjY2VzcycKICAgICAgICByZXF1aXJlZDogdHJ1ZQogICAgICAgIGRlZmF1bHQ6ICJBTEwiCiAgICAgICAgdHlwZTogY2hvaWNlCiAgICAgICAgb3B0aW9uczoKICAgICAgICAgIC0gIkFMTCIKICAgICAgICAgIC0gIlVuc3VjY2Vzc2Z1bDogYWN0aW9uX3JlcXVpcmVkLGNhbmNlbGxlZCxmYWlsdXJlLHNraXBwZWQiCiAgICAgICAgICAtIGFjdGlvbl9yZXF1aXJlZAogICAgICAgICAgLSBjYW5jZWxsZWQKICAgICAgICAgIC0gZmFpbHVyZQogICAgICAgICAgLSBza2lwcGVkCiAgICAgICAgICAtIHN1Y2Nlc3MKICAgICAgZHJ5X3J1bjoKICAgICAgICBkZXNjcmlwdGlvbjogJ0xvZ3Mgc2ltdWxhdGVkIGNoYW5nZXMsIG5vIGRlbGV0aW9ucyBhcmUgcGVyZm9ybWVkJwogICAgICAgIHJlcXVpcmVkOiBmYWxzZQoKam9iczoKICBkZWxfcnVuczoKICAgIHJ1bnMtb246IHVidW50dS1sYXRlc3QKICAgIHBlcm1pc3Npb25zOgogICAgICBhY3Rpb25zOiB3cml0ZQogICAgICBjb250ZW50czogcmVhZAogICAgc3RlcHM6CiAgICAgIC0gbmFtZTogRGVsZXRlIHdvcmtmbG93IHJ1bnMKICAgICAgICB1c2VzOiBNYXR0cmFrcy9kZWxldGUtd29ya2Zsb3ctcnVuc0B2MgogICAgICAgIHdpdGg6CiAgICAgICAgICB0b2tlbjogJHt7IGdpdGh1Yi50b2tlbiB9fQogICAgICAgICAgcmVwb3NpdG9yeTogJHt7IGdpdGh1Yi5yZXBvc2l0b3J5IH19CiAgICAgICAgICByZXRhaW5fZGF5czogJHt7IGdpdGh1Yi5ldmVudC5pbnB1dHMuZGF5cyB9fQogICAgICAgICAga2VlcF9taW5pbXVtX3J1bnM6ICR7eyBnaXRodWIuZXZlbnQuaW5wdXRzLm1pbmltdW1fcnVucyB9fQogICAgICAgICAgZGVsZXRlX3dvcmtmbG93X3BhdHRlcm46ICR7eyBnaXRodWIuZXZlbnQuaW5wdXRzLmRlbGV0ZV93b3JrZmxvd19wYXR0ZXJuIH19CiAgICAgICAgICBkZWxldGVfd29ya2Zsb3dfYnlfc3RhdGVfcGF0dGVybjogJHt7IGdpdGh1Yi5ldmVudC5pbnB1dHMuZGVsZXRlX3dvcmtmbG93X2J5X3N0YXRlX3BhdHRlcm4gfX0KICAgICAgICAgIGRlbGV0ZV9ydW5fYnlfY29uY2x1c2lvbl9wYXR0ZXJuOiA+LQogICAgICAgICAgICAke3sKICAgICAgICAgICAgICBzdGFydHNXaXRoKGdpdGh1Yi5ldmVudC5pbnB1dHMuZGVsZXRlX3J1bl9ieV9jb25jbHVzaW9uX3BhdHRlcm4sICdVbnN1Y2Nlc3NmdWw6JykKICAgICAgICAgICAgICAmJiAnYWN0aW9uX3JlcXVpcmVkLGNhbmNlbGxlZCxmYWlsdXJlLHNraXBwZWQnCiAgICAgICAgICAgICAgfHwgZ2l0aHViLmV2ZW50LmlucHV0cy5kZWxldGVfcnVuX2J5X2NvbmNsdXNpb25fcGF0dGVybgogICAgICAgICAgICB9fQogICAgICAgICAgZHJ5X3J1bjogJHt7IGdpdGh1Yi5ldmVudC5pbnB1dHMuZHJ5X3J1biB9fQ=="));
    } else {
      throw [System.NotImplementedException]::new('WIP')
    }
  }
}