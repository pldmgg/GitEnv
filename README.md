[![Build status](https://ci.appveyor.com/api/projects/status/github/pldmgg/GitEnv?branch=master&svg=true)](https://ci.appveyor.com/project/pldmgg/GitEnv/branch/master)


# GitEnv
Functions to enhance git experience on Windows.

## Getting Started

```powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the GitEnv folder to a module path (e.g. $env:USERPROFILE\Documents\WindowsPowerShell\Modules\)
# Or, with PowerShell 5 or later or PowerShellGet:
    Install-Module GitEnv

# Import the module.
    Import-Module GitEnv    # Alternatively, Import-Module <PathToModuleFolder>

# Get commands in the module
    Get-Command -Module GitEnv

# Get help
    Get-Help <GitEnv Function> -Full
    Get-Help about_GitEnv
```

## Examples

### Scenario 1

```powershell
$GitAuthParams = @{
    GitHubUserName = "pldmgg"
    GitHubEmail = "pldmgg@mykolab.com"
    AuthMethod = "https"
    PersonalAccessToken = "2345678dsfghjk4567890"
}

Configure-GitCmdLine @GitAuthParams
```

### Scenario 2

```powershell
$TestGitAuthParams = @{
    GitHubUserName = "pldmgg"
    AuthMethod = "https"
    PersonalAccessToken = "2345678dsfghjk4567890"
}

Test-GitAuthentication @TestGitAuthParams
```

### Scenario 3

```powershell
$CloneRepoParams = @{
    GitRepoParentDirectory = "$HOME\Documents\GitRepos"
    GitHubUserName = "pldmgg"
    GitHubEmail = "pldmgg@mykolab.com"
    PersonalAccessToken = "2345678dsfghjk4567890"
    CloneAllRepos = $True
}

Clone-GitRepo @CloneRepoParams
```

## Notes

* PSGallery: https://www.powershellgallery.com/packages/GitEnv
