<#
    .SYNOPSIS
        Create a new Git Repo on github.com.

    .DESCRIPTION
        See Synopsis.

    .PARAMETER NewRepoLocalPath
        TODO
    
    .PARAMETER NewRepoDescription
        TODO

    .PARAMETER GitIgnoreContent
        TODO

    .PARAMETER PublicOrPrivate
        TODO

    .PARAMETER GitHubUserName
        TODO

    .PARAMETER GitHubEmail
        TODO

    .PARAMETER AuthMethod
        TODO

    .PARAMETER ExistingSSHPrivateKeyPath
        TODO

    .PARAMETER PersonalAccessToken
        TODO
    
    .EXAMPLE
        # Launch PowerShell and...

        $NewRepoParams = @{
            GitHubUserName = "pldmgg"
            GitHubEmail = "pldmgg@mykolab.com"
            PersonalAccessToken = "2345678dsfghjk4567890"
            NewRepoLocalPath = "$HOME\Documents\GitRepos\MyProject"
            NewRepoDescription = "Does some really cool stuff"
            PublicOrPrivate = "Private"
        }

        New-GitRepo @NewRepoParams

#>
function New-GitRepo {
    [CmdletBinding(DefaultParameterSetName="https")]
    Param (
        [Parameter(Mandatory=$False)]
        [string]$NewRepoLocalPath = $($(Get-Location).Path),

        [Parameter(Mandatory=$True)]
        [string]$NewRepoDescription,

        [Parameter(Mandatory=$False)]
        [string]$GitIgnoreContent,

        [Parameter(Mandatory=$True)]
        [ValidateSet("Public","Private")]
        [string]$PublicOrPrivate,

        [Parameter(Mandatory=$False)]
        [string]$GitHubUserName = "pldmgg",

        [Parameter(Mandatory=$False)]
        [string]$GitHubEmail = "pldmgg@mykolab.com",

        [Parameter(Mandatory=$False)]
        [ValidateSet("https")]
        [string]$AuthMethod = "https",

        [Parameter(
            Mandatory=$False,
            ParameterSetName='ssh'
        )]
        [string]$ExistingSSHPrivateKeyPath,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='http'
        )]
        [securestring]$PersonalAccessToken
    )

    if (!$GitHubUserName) {
        $GitHubUserName = Read-Host -Prompt "Please enter your GitHub Username"
    }
    if (!$AuthMethod) {
        $AuthMethod = Read-Host -Prompt "Please select the Authentication Method you would like to use. [https/ssh]"
    }

    if ($AuthMethod -eq "https") {
        if (!$PersonalAccessToken) {
            $PersonalAccessToken = Read-Host -Prompt "Please enter the GitHub Personal Access Token you would like to use for https authentication." -AsSecureString
        }

        # Convert SecureString to PlainText
        $PersonalAccessTokenPT = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PersonalAccessToken))
    }
    if ($AuthMethod -eq "ssh") {
        if (!$ExistingSSHPrivateKeyPath) {
            if (!$(Test-Path "$HOME\.ssh\github_rsa")) {
                $ExistingSSHPrivateKeyPath = Read-Host -Prompt "Please enter the full path to your github_rsa ssh private key."
            }
        }
        if (!$(Test-Path $ExistingSSHPrivateKeyPath)) {
            Write-Error "Unable to find path to existing Private Key '$ExistingSSHPrivateKeyPath'! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($env:GitCmdLineConfigured -ne "True" -or ![bool]$(Get-Command git -ErrorAction SilentlyContinue)) {
        $ConfigGitCmdLineSplatParams = @{
            GitHubUserName      = $GitHubUserName
            GitHubEmail         = $GitHubEmail
            AuthMethod          = $AuthMethod
        }
        if ($AuthMethod -eq "https") {
            $ConfigGitCmdLineSplatParams.Add("PersonalAccessToken",$PersonalAccessToken)
        }
        if ($AuthMethod -eq "ssh") {
            $ConfigGitCmdLineSplatParams.Add("ExistingSSHPrivateKeyPath",$ExistingSSHPrivateKeyPath)
        }

        Configure-GitCmdLine @ConfigGitCmdLineSplatParams
    }

    $NewRepoName = $NewRepoLocalPath | Split-Path -Leaf

    if ($AuthMethod -eq "https") {
        $Headers = @{
            Authorization = "token $PersonalAccessTokenPT"
        }
        $PublicAndPrivateRepos = $(Invoke-RestMethod -Headers $Headers -Uri "https://api.github.com/user/repos").Name
        
        # Make Sure $NewRepoName is Unique
        $FinalNewRepoName = NewUniqueString -ArrayOfStrings $PublicAndPrivateRepos -PossibleNewUniqueString $NewRepoName
    }
    if ($AuthMethod -eq "ssh") {
        #Placeholder
    }

    if ($FinalNewRepoName -ne $NewRepoName) {
        Write-Warning "A repo with the Name '$NewRepoName' already exists! Final Repo Name will be '$FinalNewRepoName'"
        $ContinuePrompt = Read-Host -Prompt "Are you sure you want to create a new Git Repos with the name '$FinalNewRepoName'? [Yes\No]"
        while ($ContinuePrompt -notmatch "Yes|yes|Y|y|No|no|N|n") {
            Write-Host "'$ContinuePrompt' is not a valid option. Please enter 'Yes' or 'No'" -ForegroundColor Yellow
            $ContinuePrompt = Read-Host -Prompt "Are you sure you want to create a new Git Repos with the name '$FinalNewRepoName'? [Yes\No]"
        }

        if ($ContinuePrompt -notmatch "Yes|yes|Y|y") {
            Write-Error "User chose not to proceed. Halting!"
            $global:FunctionResult = "1"
            return
        }

        $FinalNewRepoLocalPath = "$($NewRepoLocalPath | Split-Path -Parent)\$FinalNewRepoName"
    }
    else {
        $FinalNewRepoLocalPath = $NewRepoLocalPath
    }

    if (!$(Test-Path $FinalNewRepoLocalPath)) {
        $null = New-Item -Type Directory -Path $FinalNewRepoLocalPath -Force
    }

    Push-Location $FinalNewRepoLocalPath

    $ReadMeDefaultContent = @"
[![Build status](https://ci.appveyor.com/api/projects/status/github/$GitHubUserName/$FinalNewRepoName?branch=master&svg=true)](https://ci.appveyor.com/project/$GitHubUserName/sudo/branch/master)


# $FinalNewRepoName
<Synopsis>

## Getting Started

``````powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the $FinalNewRepoName folder to a module path (e.g. `$env:USERPROFILE\Documents\WindowsPowerShell\Modules\)
# Or, with PowerShell 5 or later or PowerShellGet:
    Install-Module $FinalNewRepoName

# Import the module.
    Import-Module $FinalNewRepoName    # Alternatively, Import-Module <PathToModuleFolder>

# Get commands in the module
    Get-Command -Module $FinalNewRepoName

# Get help
    Get-Help <$FinalNewRepoName Function> -Full
    Get-Help about_$FinalNewRepoName
``````

## Examples

### Scenario 1

``````powershell
powershell code
``````

## Notes

* PSGallery: 
"@
    Set-Content -Value $ReadMeDefaultContent -Path .\README.md

    if ($GitIgnoreContent) {
        Set-Content -Value $GitIgnoreContent -Path .\.gitignore
    }

    if ($AuthMethod -eq "https") {
        # More info on JSON Options: https://developer.github.com/v3/repos/#create
        if ($PublicOrPrivate -eq "Public") {
            $PrivateBool = "false"
        }
        else {
            $PrivateBool = "true"
        }
        
        $jsonRequest = @(
            '{'
            "    `"name`": `"$FinalNewRepoName`","
            "    `"description`": `"$NewRepoDescription`","
            "    `"private`": `"$PrivateBool`""
            '}'
        )

        try {
            $JsonCompressed = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
        $NewRepoCreationResult = Invoke-RestMethod -Uri "https://api.github.com/user/repos" -Headers $Headers -Body $JsonCompressed -Method Post
        
        git init
        git add -A
        git commit -am "first commit"
        git remote add origin "https://github.com/$GitHubUserName/$FinalNewRepoName.git"
        git push -u origin master
    }
}
