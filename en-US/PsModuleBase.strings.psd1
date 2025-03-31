
@{
  ModuleName          = 'PsModuleBase'
  ModuleVersion       = '0.1.2'
  ReleaseNotes        = '# Release Notes

- Version_0.1.2
- Functions ...
- Optimizations
'
  DefaultModuleSchema = @{
    Files   = @{
      Path             = './{mName}.psd1'
      Tester           = './Test-Module.ps1'
      Builder          = './build.ps1'
      License          = './LICENSE'
      Readme           = './README.md'
      Manifest         = './{mName}.psd1'
      LocalData        = "./$((Get-Culture).Name)/{mName}.strings.psd1"
      rootLoader       = './{mName}.psm1'
      ScriptAnalyzer   = './PSScriptAnalyzerSettings.psd1'
      ModuleTest       = './Tests/{mName}.Module.Tests.ps1'
      FeatureTest      = './Tests/{mName}.Features.Tests.ps1'
      IntegrationTest  = './Tests/{mName}.Integration.Tests.ps1'
      DelWorkflowsyaml = './.github/workflows/delete_old_workflow_runs.yaml'
      Codereviewyaml   = './.github/workflows/codereview.yaml'
      Publishyaml      = './.github/workflows/publish.yaml'
      GitIgnore        = './.gitignore'
      CICDyaml         = './.github/workflows/build_module.yaml'
      DotEnv           = './.env'
      # Add more here
    }
    Folders = @{
      root      = './'
      tests     = './Tests'
      public    = './Public'
      private   = './Private'
      LocalData = "./$((Get-Culture).Name)" # The purpose of this folder is to store localized content for your module, such as help files, error messages, or any other text that needs to be displayed in different languages.
      workflows = './.github/workflows'
      # Add more here. you can access them like: $this.Folders.Where({ $_.Name -eq "root" }).value.FullName
    }
  }
}
