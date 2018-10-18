[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue
$ThisModule = $(Get-Item $PSCommandPath).BaseName

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

[System.Collections.Arraylist]$ModulesToInstallAndImport = @()
if (Test-Path "$PSScriptRoot\module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot\module.requirements.psd1"
    #$ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
    $($ModuleManifestData.GetEnumerator()) | foreach {
        if ($_.Key -ne "PSDependOptions") {
            $PSObj = [pscustomobject]@{
                Name    = $_.Key
                Version = $_.Value.Version
            }
            $null = $ModulesToInstallAndImport.Add($PSObj)
        }
    }
}

if ($ModulesToInstallAndImport.Count -gt 0) {
    foreach ($ModuleItem in $ModulesToInstallAndImport) {
        if ($($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") -and $ModuleItem.Name -eq "WinSSH") {
            continue
        }

        if (!$(Get-Module -ListAvailable $ModuleItem.Name -ErrorAction SilentlyContinue)) {Install-Module $ModuleItem.Name}

        if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
            # Make sure the Module Manifest file name and the Module Folder name are exactly the same case
            $env:PSModulePath -split ':' | foreach {
                Get-ChildItem -Path $_ -Directory | Where-Object {$_ -match $ModuleItem.Name}
            } | foreach {
                $ManifestFileName = $(Get-ChildItem -Path $_ -Recurse -File | Where-Object {$_.Name -match "$($ModuleItem.Name)\.psd1"}).BaseName
                if (![bool]$($_.Name -cmatch $ManifestFileName)) {
                    Rename-Item $_ $ManifestFileName
                }
            }
        }

        if (!$(Get-Module $ModuleItem.Name -ErrorAction SilentlyContinue)) {Import-Module $ModuleItem.Name}
    }
}

<#
[System.Collections.Arraylist]$ModulesToInstallAndImport = @()
if (Test-Path "$PSScriptRoot\module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot\module.requirements.psd1"
    #$ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
    $($ModuleManifestData.GetEnumerator()) | foreach {
        $PSObj = [pscustomobject]@{
            Name    = $_.Key
            Version = $_.Value.Version
        }
        $null = $ModulesToinstallAndImport.Add($PSObj)
    }
}

if ($ModulesToInstallAndImport.Count -gt 0) {
    # NOTE: If you're not sure if the Required Module is Locally Available or Externally Available,
    # add it the the -RequiredModules string array just to be certain
    $InvModDepSplatParams = @{
        RequiredModules                     = $ModulesToInstallAndImport
        InstallModulesNotAvailableLocally   = $True
        ErrorAction                         = "SilentlyContinue"
        WarningAction                       = "SilentlyContinue"
    }
    $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
}
#>

# Public Functions


<#
    .SYNOPSIS
        Clone all of your Public or Private repos. Clone all of someone else's Public repos.

    .DESCRIPTION
        See Synopsis.

    .PARAMETER GitRepoParentDirectory
        TODO
    
    .PARAMETER GitHubUserName
        TODO

    .PARAMETER GitHubEmail
        TODO

    .PARAMETER PersonalAccessToken
        TODO

    .PARAMETER RemoteGitRepoName
        TODO

    .PARAMETER CloneAllPublicRepos
        TODO

    .PARAMETER CloneAllPrivateRepos
        TODO

    .PARAMETER CloneAllRepos
        TODO
    
    .EXAMPLE
        # Launch PowerShell and...

        $CloneRepoParams = @{
            GitRepoParentDirectory = "$HOME\Documents\GitRepos"
            GitHubUserName = "pldmgg"
            GitHubEmail = "pldmgg@mykolab.com"
            PersonalAccessToken = "2345678dsfghjk4567890"
            CloneAllRepos = $True
        }

        Clone-GitRepo @CloneRepoParams

#>
function Clone-GitRepo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $GitRepoParentDirectory = $(Read-Host -Prompt "Please enter the full path to the directory that will contain the cloned Git repository."),

        [Parameter(Mandatory=$False)]
        [string]$GitHubUserName = $(Read-Host -Prompt "Please enter the GitHub UserName associated with the repo you would like to clone"),

        [Parameter(Mandatory=$False)]
        [string]$GitHubEmail,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PrivateRepos'
        )]
        $PersonalAccessToken,

        [Parameter(Mandatory=$False)]
        $RemoteGitRepoName,

        [Parameter(Mandatory=$False)]
        [switch]$CloneAllPublicRepos,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PrivateRepos'
        )]
        [switch]$CloneAllPrivateRepos,

        [Parameter(Mandatory=$False)]
        [switch]$CloneAllRepos
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    if ($PersonalAccessToken) {
        if ($PersonalAccessToken.GetType().FullName -eq "System.Security.SecureString") {
            # Convert SecureString to PlainText
            $PersonalAccessToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PersonalAccessToken))
        }
    }
    
    # Make sure we have access to the git command
    if ($env:github_shell -ne $true -or !$(Get-Command git -ErrorAction SilentlyContinue)) {
        if (!$GitHubUserName) {
            $GitHubUserName = Read-Host -Prompt "Please enter your GitHub UserName"
        }
        if (!$GitHubEmail) {
            $GitHubEmail = Read-Host -Prompt "Please enter the GitHub Email address associated with $GitHubuserName"
        }
        $global:FunctionResult = "0"
        Configure-GitEnvironment -GitHubUserName $GitHubUserName -GitHubEmail $GitHubEmail
        if ($global:FunctionResult -eq "1") {
            Write-Verbose "The Configure-GitEnvironment function failed! Halting!"
            Write-Error "The Configure-GitEnvironment function failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if (!$(Test-Path $GitRepoParentDirectory)) {
        Write-Verbose "The path $GitRepoParentDirectory was not found! Halting!"
        Write-Error "The path $GitRepoParentDirectory was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($CloneAllRepos -and !$PersonalAccessToken) {
        Write-Host "Please note that if you would like to clone both Public AND Private repos, you must use the -PersonalAccessToken parameter with the -CloneAllRepos switch."
    }

    $BoundParamsArrayOfKVP = $PSBoundParameters.GetEnumerator() | foreach {$_}

    $PrivateReposParamSetCheck = $($BoundParamsArrayOfKVP.Key -join "") -match "PersonalAccessToken|CloneAllPrivateRepos|CloneAllRepos"
    $NoPrivateReposParamSetCheck = $($BoundParamsArrayOfKVP.Key -join "") -match "CloneAllPublicRepos"
    if ($RemoteGitRepoName -and !$PersonalAccessToken) {
        $NoPrivateReposParamSetCheck = $true
    }

    # For Params that are part of the PrivateRepos Parameter Set...
    if ($PrivateReposParamSetCheck -eq $true) {
        if ($($CloneAllPrivateRepos -and $CloneAllRepos) -or 
        $($CloneAllPrivateRepos -and $RemoteGitRepoName) -or
        $($CloneAllPrivateRepos -and $CloneAllPublicRepos) -or 
        $($CloneAllRepos -and $RemoteGitRepoName) -or
        $($CloneAllRepos -and $CloneAllPublicRepos) -or
        $($CloneAllPublicRepos -and $RemoteGitRepoName) )  {
            Write-Verbose "Please use *either* -CloneAllRepos *or* -CloneAllPrivateRepos *or* -RemoteGitRepoName *or* -CloneAllPublicRepos! Halting!"
            Write-Error "Please use *either* -CloneAllRepos *or* -CloneAllPrivateRepos *or* -RemoteGitRepoName *or* -CloneAllPublicRepos! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    # For Params that are part of the NoPrivateRepos Parameter Set...
    if ($NoPrivateReposParamSetCheck -eq $true) {
        if ($CloneAllPublicRepos -and $RemoteGitRepoName) {
            Write-Verbose "Please use *either* -CloneAllPublicRepos *or* -RemoteGitRepoName! Halting!"
            Write-Error "Please use *either* -CloneAllPublicRepos *or* -RemoteGitRepoName! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    Push-Location $GitRepoParentDirectory

    if ($PrivateReposParamSetCheck -eq $true) {
        if ($PersonalAccessToken) {
            $PublicAndPrivateRepoObjects = Invoke-RestMethod -Uri "https://api.github.com/user/repos?access_token=$PersonalAccessToken"
            $PrivateRepoObjects = $PublicAndPrivateRepoObjects | Where-Object {$_.private -eq $true}
            $PublicRepoObjects = $PublicAndPrivateRepoObjects | Where-Object {$_.private -eq $false}
        }
        else {
            $PublicRepoObjects = Invoke-RestMethod -Uri "https://api.github.com/users/$GitHubUserName/repos"
        }
        if ($PublicRepoObject.Count -lt 1) {
            if ($RemoteGitRepo) {
                Write-Verbose "$RemoteGitRepo is either private or does not exist..."
            }
            else {
                Write-Warning "No public repositories were found!"
            }
        }
        if ($PrivateRepoObjects.Count -lt 1) {
            Write-Verbose "No private repositories were found!"
        }
        if ($($PublicRepoObjects + $PrivateRepoObjects).Count -lt 1) {
            Write-Verbose "No public or private repositories were found! Halting!"
            Write-Error "No public or private repositories were found! Halting!"
            Pop-Location
            $global:FunctionResult = "1"
            return
        }
        if ($RemoteGitRepoName) {
            if ($PrivateRepoObjects.Name -contains $RemoteGitRepoName) {
                $CloningOneOrMorePrivateRepos = $true
            }
        }
        if ($CloneAllPrivateRepos -or $($CloneAllRepos -and $PrivateRepoObjects -ne $null)) {
            $CloningOneOrMorePrivateRepos = $true
        }
        # If we're cloning a private repo, we're going to need Windows Credential Caching to avoid prompts
        if ($CloningOneOrMorePrivateRepos) {
            # Check the Windows Credential Store to see if we have appropriate credentials available already
            # If not, add them to the Windows Credential Store
            $FindCachedCredentials = Manage-WinCreds -ShoCred | Where-Object {
                $_.UserName -eq $GitHubUserName -and
                $_.Target -match "git"
            }
            if ($FindCachedCredentials.Count -gt 1) {
                Write-Warning "More than one set of stored credentials matches the UserName $GitHubUserName and contains the string 'git' in the Target property."
                Write-Host "Options are as follows:"
                # We do NOT want the Password for any creds displayed in STDOUT...
                # ...And it's possible that the GitHub PersonalAccessToken could be found in EITHER the Target Property OR the
                # Password Property
                $FindCachedCredentialsSansPassword = $FindCachedCredentials | foreach {
                    $PotentialPersonalAccessToken = $($_.Target | Select-String -Pattern "https://.*?@git").Matches.Value -replace "https://","" -replace "@git",""
                    if ($PotentialPersonalAccessToken -notmatch $GitHubUserName) {
                        $_.Target = $_.Target -replace $PotentialPersonalAccessToken,"<redacted>"
                        $_.PSObject.Properties.Remove('Password')
                        $_
                    }
                }
                for ($i=0; $i -lt $FindCachedCredentialsSansPassword.Count; $i++) {
                    "`nOption $i)"
                    $($($FindCachedCredentialsSansPassword[$i] | fl *) | Out-String).Trim()
                }
                $CachedCredentialChoice = Read-Host -Prompt "Please enter the Option Number that corresponds with the credentials you would like to use [0..$($FindCachedCredentials.Count-1)]"
                if ($(0..$($FindCachedCredentials.Count-1)) -notcontains $CachedCredentialChoice) {
                    Write-Verbose "Option Number $CachedCredentialChoice is not a valid Option Number! Halting!"
                    Write-Error "Option Number $CachedCredentialChoice is not a valid Option Number! Halting!"
                    Pop-Location
                    $global:FunctionResult = "1"
                    return
                }
                
                if (!$PersonalAccessToken) {
                    if ($FindCachedCredentials[$CachedCredentialChoice].Password -notmatch "oauth") {
                        $PersonalAccessToken = $FindCachedCredentials[$CachedCredentialChoice].Password
                    }
                    else {
                        $PersonalAccessToken = $($FindCachedCredentials[$CachedCredentialChoice].Target | Select-String -Pattern "https://.*?@git").Matches.Value -replace "https://","" -replace "@git",""
                    }
                }
            }
            if ($FindCachedCredentials.Count -eq $null -and $FindCachedCredentials -ne $null) {
                if (!$PersonalAccessToken) {
                    if ($FindCachedCredentials.Password -notmatch "oauth") {
                        $PersonalAccessToken = $FindCachedCredentials[$CachedCredentialChoice].Password
                    }
                    else {
                        $PersonalAccessToken = $($FindCachedCredentials.Target | Select-String -Pattern "https://.*?@git").Matches.Value -replace "https://","" -replace "@git",""
                    }
                }
            }
            if ($FindCachedCredentials -eq $null) {
                $CurrentGitConfig = git config --list
                if ($CurrentGitConfig -notcontains "credential.helper=wincred") {
                    git config --global credential.helper wincred
                }
                if (!$PersonalAccessToken) {
                    $PersonalAccessToken = Read-Host -Prompt "Please enter your GitHub Personal Access Token." -AsSecureString
                }

                # Alternate Params for GitHub https auth
                <#
                $ManageStoredCredsParams = @{
                    Target  = "git:https://$PersonalAccessToken@github.com"
                    User    = $PersonalAccessToken
                    Pass    = 'x-oauth-basic'
                    Comment = "Saved By Manage-WinCreds.ps1"
                }
                #>
                $ManageStoredCredsParams = @{
                    Target  = "git:https://$GitHubUserName@github.com"
                    User    = $GitHubUserName
                    Pass    = $PersonalAccessToken
                    Comment = "Saved By Manage-WinCreds.ps1"
                }
                Manage-WinCreds -AddCred @ManageStoredCredsParams
            }
        }

        if ($CloneAllPrivateRepos) {
            foreach ($RepoObject in $PrivateRepoObjects) {
                if (!$(Test-Path "$GitRepoParentDirectory\$($RepoObject.Name)")) {
                    if ($CloningOneOrMorePrivateRepos) {
                        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                        $ProcessInfo.WorkingDirectory = $GitRepoParentDirectory
                        $ProcessInfo.FileName = "git"
                        $ProcessInfo.RedirectStandardError = $true
                        $ProcessInfo.RedirectStandardOutput = $true
                        $ProcessInfo.UseShellExecute = $false
                        $ProcessInfo.Arguments = "clone $($RepoObject.html_url)"
                        $Process = New-Object System.Diagnostics.Process
                        $Process.StartInfo = $ProcessInfo
                        $Process.Start() | Out-Null
                        # Below $FinishedInAlottedTime returns boolean true/false
                        $FinishedInAlottedTime = $Process.WaitForExit(15000)
                        if (!$FinishedInAlottedTime) {
                            $Process.Kill()
                            Write-Verbose "git is prompting for UserName and Password, which means Credential Caching is not configured correctly! Halting!"
                            Write-Error "git is prompting for UserName and Password, which means Credential Caching is not configured correctly! Halting!"
                            Pop-Location
                            $global:FunctionResult = "1"
                            return
                        }
                        $stdout = $Process.StandardOutput.ReadToEnd()
                        $stderr = $Process.StandardError.ReadToEnd()
                        $AllOutput = $stdout + $stderr
                        Write-Host "##### BEGIN git clone Console Output #####"
                        Write-Host "$AllOutput"
                        Write-Host "##### END git clone Console Output #####"
                        
                    }
                }
                else {
                    Write-Verbose "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    Write-Error "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    $global:FunctionResult = "1"
                    break
                }
            }
        }
        if ($CloneAllPublicRepos) {
            foreach ($RepoObject in $PublicRepoObjects) {
                if (!$(Test-Path "$GitRepoParentDirectory\$($RepoObject.Name)")) {
                    git clone $RepoObject.html_url
                }
                else {
                    Write-Verbose "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    Write-Error "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    $global:FunctionResult = "1"
                    break
                }
            }
        }
        if ($CloneAllRepos) {
            foreach ($RepoObject in $($PublicRepoObjects + $PrivateRepoObjects)) {
                if (!$(Test-Path "$GitRepoParentDirectory\$($RepoObject.Name)")) {
                    if ($CloningOneOrMorePrivateRepos) {
                        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                        $ProcessInfo.WorkingDirectory = $GitRepoParentDirectory
                        $ProcessInfo.FileName = "git"
                        $ProcessInfo.RedirectStandardError = $true
                        $ProcessInfo.RedirectStandardOutput = $true
                        $ProcessInfo.UseShellExecute = $false
                        $ProcessInfo.Arguments = "clone $($RepoObject.html_url)"
                        $Process = New-Object System.Diagnostics.Process
                        $Process.StartInfo = $ProcessInfo
                        $Process.Start() | Out-Null
                        # Below $FinishedInAlottedTime returns boolean true/false
                        $FinishedInAlottedTime = $Process.WaitForExit(15000)
                        if (!$FinishedInAlottedTime) {
                            $Process.Kill()
                            Write-Verbose "git is prompting for UserName and Password, which means Credential Caching is not configured correctly! Halting!"
                            Write-Error "git is prompting for UserName and Password, which means Credential Caching is not configured correctly! Halting!"
                            Pop-Location
                            $global:FunctionResult = "1"
                            return
                        }
                        $stdout = $Process.StandardOutput.ReadToEnd()
                        $stderr = $Process.StandardError.ReadToEnd()
                        $AllOutput = $stdout + $stderr
                        Write-Host "##### BEGIN git clone Console Output #####"
                        Write-Host "$AllOutput"
                        Write-Host "##### END git clone Console Output #####"
                        
                    }
                    else {
                        git clone $RepoObject.html_url
                    }
                }
                else {
                    Write-Verbose "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    Write-Error "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    Pop-Location
                    $global:FunctionResult = "1"
                    break
                }
            }
        }
        if ($RemoteGitRepoName) {
            $RemoteGitRepoObject = $($PublicRepoObjects + $PrivateRepoObjects) | Where-Object {$_.Name -eq $RemoteGitRepoName}
            if ($RemoteGitRepoObject -eq $null) {
                Write-Verbose "Unable to find a public or private repository with the name $RemoteGitRepoName! Halting!"
                Write-Error "Unable to find a public or private repository with the name $RemoteGitRepoName! Halting!"
                Pop-Location
                $global:FunctionResult = "1"
                return
            }
            if (!$(Test-Path "$GitRepoParentDirectory\$($RemoteGitRepoObject.Name)")) {
                if ($CloningOneOrMorePrivateRepos) {
                    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $ProcessInfo.WorkingDirectory = $GitRepoParentDirectory
                    $ProcessInfo.FileName = "git"
                    $ProcessInfo.RedirectStandardError = $true
                    $ProcessInfo.RedirectStandardOutput = $true
                    $ProcessInfo.UseShellExecute = $false
                    $ProcessInfo.Arguments = "clone $($RemoteGitRepoObject.html_url)"
                    $Process = New-Object System.Diagnostics.Process
                    $Process.StartInfo = $ProcessInfo
                    $Process.Start() | Out-Null
                    # Below $FinishedInAlottedTime returns boolean true/false
                    $FinishedInAlottedTime = $Process.WaitForExit(15000)
                    if (!$FinishedInAlottedTime) {
                        $Process.Kill()
                        Write-Verbose "git is prompting for UserName and Password, which means Credential Caching is not configured correctly! Halting!"
                        Write-Error "git is prompting for UserName and Password, which means Credential Caching is not configured correctly! Halting!"
                        Pop-Location
                        $global:FunctionResult = "1"
                        return
                    }
                    $stdout = $Process.StandardOutput.ReadToEnd()
                    $stderr = $Process.StandardError.ReadToEnd()
                    $AllOutput = $stdout + $stderr
                    Write-Host "##### BEGIN git clone Console Output #####"
                    Write-Host "$AllOutput"
                    Write-Host "##### END git clone Console Output #####"
                    
                }
                else {
                    git clone $RemoteGitRepoObject.html_url
                }
            }
            else {
                Write-Verbose "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Halting!"
                Write-Error "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Halting!"
                Pop-Location
                $global:FunctionResult = "1"
                return
            }
        }
    }
    if ($NoPrivateReposParamSetCheck -eq $true) {
        $PublicRepoObjects = Invoke-RestMethod -Uri "https://api.github.com/users/$GitHubUserName/repos"
        if ($PublicRepoObjects.Count -lt 1) {
            Write-Verbose "No public repositories were found! Halting!"
            Write-Error "No public repositories were found! Halting!"
            Pop-Location
            $global:FunctionResult = "1"
            return
        }

        if ($CloneAllPublicRepos -or $CloneAllRepos) {
            foreach ($RepoObject in $PublicRepoObjects) {
                if (!$(Test-Path "$GitRepoParentDirectory\$($RepoObject.Name)")) {
                    git clone $RepoObject.html_url
                }
                else {
                    Write-Verbose "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    Write-Error "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    Pop-Location
                    $global:FunctionResult = "1"
                    break
                }
            }
        }
        if ($RemoteGitRepoName) {
            $RemoteGitRepoObject = $PublicRepoObjects | Where-Object {$_.Name -eq $RemoteGitRepoName}
            if ($RemoteGitRepoObject -eq $null) {
                Write-Verbose "Unable to find a public repository with the name $RemoteGitRepoName! Is it private? If so, use the -PersonalAccessToken parameter. Halting!"
                Write-Error "Unable to find a public repository with the name $RemoteGitRepoName! Is it private? If so, use the -PersonalAccessToken parameter. Halting!"
                Pop-Location
                $global:FunctionResult = "1"
                return
            }
            if (!$(Test-Path "$GitRepoParentDirectory\$($RemoteGitRepoObject.Name)")) {
                git clone $RemoteGitRepoObject.html_url
            }
            else {
                Write-Verbose "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Halting!"
                Write-Error "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Halting!"
                Pop-Location
                $global:FunctionResult = "1"
                return
            }
        }
    }

    Pop-Location

    ##### END Main Body #####

}


<#
    .SYNOPSIS
        Configures Git Command Line for the current PowerShell Session in the current local Git Repo  directory.

    .DESCRIPTION
        See Synopsis.

    .PARAMETER GitHubUserName
        TODO

    .PARAMETER GitHubEmail
        TODO

    .PARAMETER AuthMethod
        TODO

    .PARAMETER ExistingSSHPrivateKeyPath
        TODO

    .PARAMETER NewSSHKeyName
        TODO
    
    .PARAMETER NewSSHKeyPwd
        TODO

    .PARAMETER PersonalAccessToken
        TODO

    .EXAMPLE
        # Launch PowerShell and...

        $GitAuthParams = @{
            GitHubUserName = "pldmgg"
            GitHubEmail = "pldmgg@mykolab.com"
            AuthMethod = "https"
            PersonalAccessToken = "2345678dsfghjk4567890"
        }

        Configure-GitCmdLine @GitAuthParams

    .EXAMPLE
        # Launch PowerShell and...

        $GitAuthParams = @{
            GitHubUserName = "pldmgg"
            GitHubEmail = "pldmgg@mykolab.com"
            AuthMethod = "ssh"
            NewSSHKeyName "gitauth_rsa"
        }

        Configure-GitCmdLine @GitAuthParams

    .EXAMPLE
        # Launch PowerShell and...

        $GitAuthParams = @{
            GitHubUserName = "pldmgg"
            GitHubEmail = "pldmgg@mykolab.com"
            AuthMethod = "ssh"
            ExistingSSHPrivateKeyPath = "$HOME\.ssh\github_rsa" 
        }
        
        Configure-GitCmdLine @GitAuthParams

#>
function Configure-GitCmdLine {
    [CmdletBinding(DefaultParameterSetname='AuthSetup')]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$GitHubUserName = $(Read-Host -Prompt "Please enter your GitHub Username"),

        [Parameter(Mandatory=$False)]
        [string]$GitHubEmail = $(Read-Host -Prompt "Please the primary GitHub email address associated with $GitHubUserName"),

        [Parameter(Mandatory=$False)]
        [ValidateSet("https","ssh")]
        [string]$AuthMethod = $(Read-Host -Prompt "Please select the Authentication Method you would like to use. [https/ssh]"),

        [Parameter(
            Mandatory=$False,
            ParameterSetName='SSH Auth'
        )]
        [string]$ExistingSSHPrivateKeyPath,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='SSH Auth'
        )]
        [string]$NewSSHKeyName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='SSH Auth'
        )]
        $NewSSHKeyPwd,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='HTTPS Auth'
        )]
        [securestring]$PersonalAccessToken
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep ######

    $CurrentUser = $($([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name -split "\\")[-1]

    # Make sure git cmdline is installed
    if (![bool]$(Get-Command git -ErrorAction SilentlyContinue)) {
        $ExpectedGitPath = "C:\Program Files\Git\cmd"
        if ($($env:Path -split ";") -notcontains [regex]::Escape($ExpectedGitPath)) {
            if (Test-Path $ExpectedGitPath) {
                $env:Path = $ExpectedGitPath + ";" + $env:Path
            }
        }
    }
    if (![bool]$(Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find git.exe! Try installing with the 'Install-GitCmdLine' function. Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure global config for UserName and Email Address is configured
    git config --global user.name "$GitHubUserName"
    git config --global user.email "$GitHubEmail"

    if ($ExistingSSHPrivateKeyPath -or $NewSSHKeyName -or $NewSSHKeyPwd) {
        $AuthMethod = "ssh"
    }
    if ($PersonalAccessToken) {
        $AuthMethod = "https"
    }
    if (!$AuthMethod) {
        $AuthMethod = "ssh"
    }

    if ($AuthMethod -eq "https" -and $($ExistingSSHPrivateKeyPath -or $NewSSHKeyName -or $NewSSHKeyPwd)) {
        $ErrMsg = "The parameters -ExistingSSHPrivateKeyPath, -NewSSHKeyName, " +
        "and/or -NewSSHKeyPwd should only be used when -AuthMethod is `"ssh`"! Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }
    # NOTE: We do NOT need to force use of -ExistingSSHPrivateKeyPath or -NewSSHKeyName when -AuthMethod is "ssh"
    # because Setup-GitCmdLine function can handle things if neither are provided
    if ($AuthMethod -eq "https") {
        if (!$PersonalAccessToken) {
            $PersonalAccessToken = Read-Host -Prompt "Please enter the GitHub Personal Access Token you would like to use for https authentication." -AsSecureString
        }

        # Convert SecureString to PlainText
        $PersonalAccessTokenPT = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PersonalAccessToken))

        git config --global credential.helper wincred

        # Alternate Stored Credentials Format
        <#
        $ManageStoredCredsParams = @{
            Target  = "git:https://$PersonalAccessToken@github.com"
            User    = $PersonalAccessToken
            Pass    = 'x-oauth-basic'
            Comment = "Saved By Manage-WinCreds.ps1"
        }
        #>
        $ManageStoredCredsParams = @{
            Target  = "git:https://$GitHubUserName@github.com"
            User    = $GitHubUserName
            Pass    = $PersonalAccessTokenPT
            Comment = "Saved By Manage-WinCreds.ps1"
        }
        $null = Manage-WinCreds -AddCred @ManageStoredCredsParams

        # Test https OAuth2 authentication
        # More info here: https://channel9.msdn.com/Blogs/trevor-powershell/Automating-the-GitHub-REST-API-Using-PowerShell
        $GitHubAuthSuccess = Test-GitAuthentication -GitHubUserName $GitHubUserName -AuthMethod $AuthMethod -PersonalAccessToken $PersonalAccessToken
        if ($GitHubAuthSuccess) {
            $env:GitCmdLineConfigured = "True"
        }
    }
    if ($AuthMethod -eq "ssh") {
        if ($ExistingSSHPrivateKeyPath) {
            try {
                $ExistingSSHPrivateKeyPath = $(Resolve-Path $ExistingSSHPrivateKeyPath -ErrorAction Stop).Path
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            if (Test-Path "$HOME\.ssh\github_rsa") {
                $ExistingSSHPrivateKeyPath = "$HOME\.ssh\github_rsa"
            }
            else {
                if ($NewSSHKeyPwd) {
                    if ($NewSSHKeyPwd.GetType().FullName -eq "System.Security.SecureString") {
                        # Convert SecureString to PlainText
                        $NewSSHKeyPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewSSHKeyPwd))
                    }
                }
                if (!$NewSSHKeyName) {
                    $NewSSHKeyName = "github_rsa"
                }
                $SSHKeyGenPath = $(Get-ChildItem "C:\Program Files\Git" -Recurse -Filter "*ssh-keygen.exe").FullName
                $SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$HOME\.ssh\$NewSSHKeyName`" -q -N `"$NewSSHKeyPwd`" -C `"GitAuthFor$CurrentUser`""
                $SSHKeyGenArgumentsNoPwdString = "-t rsa -b 2048 -f `"$HOME\.ssh\$NewSSHKeyName`" -q -C `"GitAuthFor$CurrentUser`""

                if (!$(Test-Path "$HOME\.ssh")) {
                    New-Item -Type Directory -Path "$HOME\.ssh"
                }
            
                # Create new public/private keypair
                if ($NewSSHKeyPwd) {
                    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $ProcessInfo.WorkingDirectory = $($SSHKeyGenPath | Split-Path -Parent)
                    $ProcessInfo.FileName = $SSHKeyGenPath
                    $ProcessInfo.RedirectStandardError = $true
                    $ProcessInfo.RedirectStandardOutput = $true
                    $ProcessInfo.UseShellExecute = $false
                    $ProcessInfo.Arguments = $SSHKeyGenArgumentsString
                    $Process = New-Object System.Diagnostics.Process
                    $Process.StartInfo = $ProcessInfo
                    $Process.Start() | Out-Null
                    $stdout = $Process.StandardOutput.ReadToEnd()
                    $stderr = $Process.StandardError.ReadToEnd()
                    $AllOutput = $stdout + $stderr
            
                    if ($AllOutput -match "fail|error") {
                        Write-Error $AllOutput
                        Write-Error "The 'ssh-keygen command failed! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                else {
                    try {
                        if ($(Get-Module -ListAvailable).Name -notcontains 'WinSSH') {$null = Install-Module WinSSH -ErrorAction Stop}
                        if ($(Get-Module).Name -notcontains 'WinSSH') {$null = Import-Module WinSSH -ErrorAction Stop}
                        Import-Module "$($(Get-Module WinSSH).ModuleBase)\Await\Await.psd1" -ErrorAction Stop
                    }
                    catch {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }
            
                    # Make sure we don't have any other Await sessions running...
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        Write-Verbose $_.Exception.Message
                    }
            
                    Start-AwaitSession
                    Start-Sleep -Seconds 1
                    Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
                    $PSAwaitProcess = $($(Get-Process | ? {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
                    Start-Sleep -Seconds 1
                    Send-AwaitCommand "`$env:Path = '$env:Path'; Push-Location '$($SSHKeyGenPath | Split-Path -Parent)'"
                    Start-Sleep -Seconds 1
                    #Send-AwaitCommand "Invoke-Expression `"& '$SSHKeyGenPath' $SSHKeyGenArgumentsNoPwdString`""
                    Send-AwaitCommand ".\ssh-keygen.exe $SSHKeyGenArgumentsNoPwdString"
                    Start-Sleep -Seconds 2
                    # The below is the equivalent of pressing [ENTER] to proceed with the ssh-keygen.exe interactive prompt
                    Send-AwaitCommand ""
                    Start-Sleep -Seconds 2
                    # The below is the equivalent of pressing [ENTER] to proceed with the ssh-keygen.exe interactive prompt
                    Send-AwaitCommand ""
                    Start-Sleep -Seconds 1
                    $SSHKeyGenConsoleOutput = Receive-AwaitResponse
            
                    # If Stop-AwaitSession errors for any reason, it doesn't return control, so we need to handle in try/catch block
                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                $Counter = 0
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                    $Counter++
                                }
                            }
                        }
                    }
                }

                if (!$(Test-Path "$HOME\.ssh\$NewSSHKeyName")) {
                    Write-Error "ssh-keygen did not successfully create the public/private keypair! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    $ExistingSSHPrivateKeyPath = "$HOME\.ssh\$NewSSHKeyName"
                }
            }
        }

        $null = git config core.sshCommand "ssh -i $([regex]::Escape($ExistingSSHPrivateKeyPath)) -F /dev/null" 2>&1
        $env:GIT_SSH_COMMAND = "ssh -i $([regex]::Escape($ExistingSSHPrivateKeyPath))"

        # Check To Make Sure Online GitHub Account is aware of Existing Public Key
        $GitHubAuthSuccess = Test-GitAuthentication -GitHubUserName $GitHubUserName -AuthMethod $AuthMethod -ExistingSSHPrivateKeyPath $ExistingSSHPrivateKeyPath
        if (!$GitHubAuthSuccess) {
            Write-Host ""
            Write-Host "GitHub Authentication was successfully configured on the client machine, however, we were not able to successfully authenticate to GitHub using '$ExistingSSHPrivateKeyPath'"
            Write-Host "Please add '$HOME\.ssh\$ExistingSSHPrivateKeyPath.pub' to your GitHub Account via Web Browser by:"
            Write-Host "    1) Navigating to Settings"
            Write-Host "    2) In the user settings sidebar, click SSH and GPG keys."
            Write-Host "    3) Add SSH Key"
            Write-Host "    4) Enter a descriptive Title like: SSH Key for Paul-MacBookPro auth"
            Write-Host "    5) Paste your key into the Key field."
            Write-Host "    6) Click Add SSH key."
        }
        else {
            $env:GitCmdLineConfigured = "True"
        }
    }

    ##### END Main Body #####
}


<#
    .SYNOPSIS
        Install Git Command Line and add it to $env:Path and System PATH.

    .DESCRIPTION
        See Synopsis.
    
    .EXAMPLE
        # Launch PowerShell and...

        Install-GitCmdline

#>
function Install-GitCmdLine {
    [CmdletBinding()]
    Param ()

    Install-Program -ProgramName git -CommandName git
}


<#
    .SYNOPSIS
        Install the Git Desktop GUI app.

    .DESCRIPTION
        See Synopsis.
    
    .EXAMPLE
        # Launch PowerShell and...

        Install-GitDesktop

#>
function Install-GitDesktop {
    [CmdletBinding()]
    Param ()

    #Install-Program -ProgramName github-desktop
    Install-Program -ProgramName github-desktop -ResolveCommandPath:$False -UseChocolateyCmdLine
}


<#
    .Synopsis
        Provides access to Windows Credential Manager basic functionality for client scripts. Allows the user
        to add, delete, and show credentials within the Windows Credential Manager.

        Refactored From: https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Credentials-d44c3cde

        ****************** IMPORTANT ******************
        *
        * If you use this script from the PS console, you 
        * should ALWAYS pass the Target, User and Password
        * parameters using single quotes:
        * 
        *  .\CredMan.ps1 -AddCred -Target 'http://server' -User 'JoeSchmuckatelli' -Pass 'P@55w0rd!'
        * 
        * to prevent PS misinterpreting special characters 
        * you might use as PS reserved characters
        * 
        ****************** IMPORTANT ******************

    .Description
        See .SYNOPSIS

    .NOTES
        Original Author: Jim Harrison (jim@isatools.org)
        Date  : 2012/05/20
        Vers  : 1.5

    .PARAMETER AddCred
        This parameter is OPTIONAL.

        This parameter is a switch. Use it in conjunction with -Target, -User, and -Pass
        parameters to add a new credential or update existing credentials.

    .PARAMETER Comment
        This parameter is OPTIONAL.

        This parameter takes a string that represents additional information that you wish
        to place in the credentials comment field. Use with the -AddCred switch.

    .PARAMETER CredPersist
        This parameter is OPTIONAL, however, it has a default value of "ENTERPRISE".

        This parameter takes a string. Valid values are:
        "SESSION", "LOCAL_MACHINE", "ENTERPRISE"
        
        ENTERPRISE persistance means that the credentials will survive logoff and reboot.
        
    .PARAMETER CredType
        This parameter is OPTIONAL, however, it has a default value of "GENERIC".

        This parameter takes a string. Valid values are:
        "GENERIC", "DOMAIN_PASSWORD", "DOMAIN_CERTIFICATE",
        "DOMAIN_VISIBLE_PASSWORD", "GENERIC_CERTIFICATE", "DOMAIN_EXTENDED",
        "MAXIMUM", "MAXIMUM_EX"
        
        ****************** IMPORTANT ******************
        *
        * I STRONGLY recommend that you become familiar 
        * with http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        * before you create new credentials with -CredType other than "GENERIC"
        * 
        ****************** IMPORTANT ******************

    .PARAMETER DelCred
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to remove existing credentials. If more than one
        credential sets have the same -Target, you must use this switch in conjunction with the
        -CredType parameter.

    .PARAMETER GetCred
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to retrieve an existing credential. The
        -CredType parameter may be required to access the correct credential if more set
        of credentials have the same -Target.

    .PARAMETER Pass
        This parameter is OPTIONAL, however, it is MANDATORY if the -AddCred switch is used.

        This parameter takes a string that represents tha secret/password that you would like to store.

    .PARAMETER RunTests
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the function will run built-in Win32 CredMan
        functionality tests.

    .PARAMETER ShoCred
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the function will retrieve all credentials stored for
        the interactive user.

    .PARAMETER Target
        This parameter is OPTIONAL, however, it is MANDATORY unless the -ShoCred switch is used.

        This parameter takes a string that specifies the authentication target for the specified credentials
        If not specified, the value provided to the -User parameter is used.

    .PARAMETER User
        This parameter is OPTIONAL.

        This parameter takes a string that represents the credential's UserName.
        

    .LINK
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        http://stackoverflow.com/questions/7162604/get-cached-credentials-in-powershell-from-windows-7-credential-manager
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        http://blogs.msdn.com/b/peerchan/archive/2005/11/01/487834.aspx

    .EXAMPLE
        # Stores the credential for 'UserName' with a password of 'P@55w0rd!' for authentication against 'http://aserver' and adds a comment of 'cuziwanna'
        Manage-StoredCredentials -AddCred -Target 'http://aserver' -User 'UserName' -Password 'P@55w0rd!' -Comment 'cuziwanna'

    .EXAMPLE
        # Removes the credential used for the target 'http://aserver' as credentials type 'DOMAIN_PASSWORD'
        Manage-StoredCredentials -DelCred -Target 'http://aserver' -CredType 'DOMAIN_PASSWORD'

    .EXAMPLE
        # Retreives the credential used for the target 'http://aserver'
        Manage-StoredCredentials -GetCred -Target 'http://aserver'

    .EXAMPLE
        # Retrieves a summary list of all credentials stored for the interactive user
        Manage-StoredCredentials -ShoCred

    .EXAMPLE
        # Retrieves a detailed list of all credentials stored for the interactive user
        Manage-StoredCredentials -ShoCred -All

#>
function Manage-StoredCredentials {
    [CmdletBinding()]
    Param (
     [Parameter(Mandatory=$false)]
        [Switch] $AddCred,

     [Parameter(Mandatory=$false)]
        [Switch]$DelCred,
     
        [Parameter(Mandatory=$false)]
        [Switch]$GetCred,
     
        [Parameter(Mandatory=$false)]
        [Switch]$ShoCred,

     [Parameter(Mandatory=$false)]
        [Switch]$RunTests,
     
        [Parameter(Mandatory=$false)]
        [ValidateLength(1,32767) <# CRED_MAX_GENERIC_TARGET_NAME_LENGTH #>]
        [String]$Target,

     [Parameter(Mandatory=$false)]
        [ValidateLength(1,512) <# CRED_MAX_USERNAME_LENGTH #>]
        [String]$User,

     [Parameter(Mandatory=$false)]
        [ValidateLength(1,512) <# CRED_MAX_CREDENTIAL_BLOB_SIZE #>]
        [String]$Pass,

     [Parameter(Mandatory=$false)]
        [ValidateLength(1,256) <# CRED_MAX_STRING_LENGTH #>]
        [String]$Comment,

     [Parameter(Mandatory=$false)]
        [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
        "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
        [String]$CredType = "GENERIC",

     [Parameter(Mandatory=$false)]
        [ValidateSet("SESSION","LOCAL_MACHINE","ENTERPRISE")]
        [String]$CredPersist = "ENTERPRISE"
    )

    #region Pinvoke
    #region Inline C#
    [String] $PsCredmanUtils = @"
    using System;
    using System.Runtime.InteropServices;

    namespace PsUtils
    {
        public class CredMan
        {
            #region Imports
            // DllImport derives from System.Runtime.InteropServices
            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode)]
            private static extern bool CredDeleteW([In] string target, [In] CRED_TYPE type, [In] int reservedFlag);

            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode)]
            private static extern bool CredEnumerateW([In] string Filter, [In] int Flags, out int Count, out IntPtr CredentialPtr);

            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredFree")]
            private static extern void CredFree([In] IntPtr cred);

            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredReadW", CharSet = CharSet.Unicode)]
            private static extern bool CredReadW([In] string target, [In] CRED_TYPE type, [In] int reservedFlag, out IntPtr CredentialPtr);

            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredWriteW", CharSet = CharSet.Unicode)]
            private static extern bool CredWriteW([In] ref Credential userCredential, [In] UInt32 flags);
            #endregion

            #region Fields
            public enum CRED_FLAGS : uint
            {
                NONE = 0x0,
                PROMPT_NOW = 0x2,
                USERNAME_TARGET = 0x4
            }

            public enum CRED_ERRORS : uint
            {
                ERROR_SUCCESS = 0x0,
                ERROR_INVALID_PARAMETER = 0x80070057,
                ERROR_INVALID_FLAGS = 0x800703EC,
                ERROR_NOT_FOUND = 0x80070490,
                ERROR_NO_SUCH_LOGON_SESSION = 0x80070520,
                ERROR_BAD_USERNAME = 0x8007089A
            }

            public enum CRED_PERSIST : uint
            {
                SESSION = 1,
                LOCAL_MACHINE = 2,
                ENTERPRISE = 3
            }

            public enum CRED_TYPE : uint
            {
                GENERIC = 1,
                DOMAIN_PASSWORD = 2,
                DOMAIN_CERTIFICATE = 3,
                DOMAIN_VISIBLE_PASSWORD = 4,
                GENERIC_CERTIFICATE = 5,
                DOMAIN_EXTENDED = 6,
                MAXIMUM = 7,      // Maximum supported cred type
                MAXIMUM_EX = (MAXIMUM + 1000),  // Allow new applications to run on old OSes
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct Credential
            {
                public CRED_FLAGS Flags;
                public CRED_TYPE Type;
                public string TargetName;
                public string Comment;
                public DateTime LastWritten;
                public UInt32 CredentialBlobSize;
                public string CredentialBlob;
                public CRED_PERSIST Persist;
                public UInt32 AttributeCount;
                public IntPtr Attributes;
                public string TargetAlias;
                public string UserName;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            private struct NativeCredential
            {
                public CRED_FLAGS Flags;
                public CRED_TYPE Type;
                public IntPtr TargetName;
                public IntPtr Comment;
                public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
                public UInt32 CredentialBlobSize;
                public IntPtr CredentialBlob;
                public UInt32 Persist;
                public UInt32 AttributeCount;
                public IntPtr Attributes;
                public IntPtr TargetAlias;
                public IntPtr UserName;
            }
            #endregion

            #region Child Class
            private class CriticalCredentialHandle : Microsoft.Win32.SafeHandles.CriticalHandleZeroOrMinusOneIsInvalid
            {
                public CriticalCredentialHandle(IntPtr preexistingHandle)
                {
                    SetHandle(preexistingHandle);
                }

                private Credential XlateNativeCred(IntPtr pCred)
                {
                    NativeCredential ncred = (NativeCredential)Marshal.PtrToStructure(pCred, typeof(NativeCredential));
                    Credential cred = new Credential();
                    cred.Type = ncred.Type;
                    cred.Flags = ncred.Flags;
                    cred.Persist = (CRED_PERSIST)ncred.Persist;

                    long LastWritten = ncred.LastWritten.dwHighDateTime;
                    LastWritten = (LastWritten << 32) + ncred.LastWritten.dwLowDateTime;
                    cred.LastWritten = DateTime.FromFileTime(LastWritten);

                    cred.UserName = Marshal.PtrToStringUni(ncred.UserName);
                    cred.TargetName = Marshal.PtrToStringUni(ncred.TargetName);
                    cred.TargetAlias = Marshal.PtrToStringUni(ncred.TargetAlias);
                    cred.Comment = Marshal.PtrToStringUni(ncred.Comment);
                    cred.CredentialBlobSize = ncred.CredentialBlobSize;
                    if (0 < ncred.CredentialBlobSize)
                    {
                        cred.CredentialBlob = Marshal.PtrToStringUni(ncred.CredentialBlob, (int)ncred.CredentialBlobSize / 2);
                    }
                    return cred;
                }

                public Credential GetCredential()
                {
                    if (IsInvalid)
                    {
                        throw new InvalidOperationException("Invalid CriticalHandle!");
                    }
                    Credential cred = XlateNativeCred(handle);
                    return cred;
                }

                public Credential[] GetCredentials(int count)
                {
                    if (IsInvalid)
                    {
                        throw new InvalidOperationException("Invalid CriticalHandle!");
                    }
                    Credential[] Credentials = new Credential[count];
                    IntPtr pTemp = IntPtr.Zero;
                    for (int inx = 0; inx < count; inx++)
                    {
                        pTemp = Marshal.ReadIntPtr(handle, inx * IntPtr.Size);
                        Credential cred = XlateNativeCred(pTemp);
                        Credentials[inx] = cred;
                    }
                    return Credentials;
                }

                override protected bool ReleaseHandle()
                {
                    if (IsInvalid)
                    {
                        return false;
                    }
                    CredFree(handle);
                    SetHandleAsInvalid();
                    return true;
                }
            }
            #endregion

            #region Custom API
            public static int CredDelete(string target, CRED_TYPE type)
            {
                if (!CredDeleteW(target, type, 0))
                {
                    return Marshal.GetHRForLastWin32Error();
                }
                return 0;
            }

            public static int CredEnum(string Filter, out Credential[] Credentials)
            {
                int count = 0;
                int Flags = 0x0;
                if (string.IsNullOrEmpty(Filter) ||
                    "*" == Filter)
                {
                    Filter = null;
                    if (6 <= Environment.OSVersion.Version.Major)
                    {
                        Flags = 0x1; //CRED_ENUMERATE_ALL_CREDENTIALS; only valid is OS >= Vista
                    }
                }
                IntPtr pCredentials = IntPtr.Zero;
                if (!CredEnumerateW(Filter, Flags, out count, out pCredentials))
                {
                    Credentials = null;
                    return Marshal.GetHRForLastWin32Error(); 
                }
                CriticalCredentialHandle CredHandle = new CriticalCredentialHandle(pCredentials);
                Credentials = CredHandle.GetCredentials(count);
                return 0;
            }

            public static int CredRead(string target, CRED_TYPE type, out Credential Credential)
            {
                IntPtr pCredential = IntPtr.Zero;
                Credential = new Credential();
                if (!CredReadW(target, type, 0, out pCredential))
                {
                    return Marshal.GetHRForLastWin32Error();
                }
                CriticalCredentialHandle CredHandle = new CriticalCredentialHandle(pCredential);
                Credential = CredHandle.GetCredential();
                return 0;
            }

            public static int CredWrite(Credential userCredential)
            {
                if (!CredWriteW(ref userCredential, 0))
                {
                    return Marshal.GetHRForLastWin32Error();
                }
                return 0;
            }

            #endregion

            private static int AddCred()
            {
                Credential Cred = new Credential();
                string Password = "Password";
                Cred.Flags = 0;
                Cred.Type = CRED_TYPE.GENERIC;
                Cred.TargetName = "Target";
                Cred.UserName = "UserName";
                Cred.AttributeCount = 0;
                Cred.Persist = CRED_PERSIST.ENTERPRISE;
                Cred.CredentialBlobSize = (uint)Password.Length;
                Cred.CredentialBlob = Password;
                Cred.Comment = "Comment";
                return CredWrite(Cred);
            }

            private static bool CheckError(string TestName, CRED_ERRORS Rtn)
            {
                switch(Rtn)
                {
                    case CRED_ERRORS.ERROR_SUCCESS:
                        Console.WriteLine(string.Format("'{0}' worked", TestName));
                        return true;
                    case CRED_ERRORS.ERROR_INVALID_FLAGS:
                    case CRED_ERRORS.ERROR_INVALID_PARAMETER:
                    case CRED_ERRORS.ERROR_NO_SUCH_LOGON_SESSION:
                    case CRED_ERRORS.ERROR_NOT_FOUND:
                    case CRED_ERRORS.ERROR_BAD_USERNAME:
                        Console.WriteLine(string.Format("'{0}' failed; {1}.", TestName, Rtn));
                        break;
                    default:
                        Console.WriteLine(string.Format("'{0}' failed; 0x{1}.", TestName, Rtn.ToString("X")));
                        break;
                }
                return false;
            }

            /*
             * Note: the Main() function is primarily for debugging and testing in a Visual 
             * Studio session.  Although it will work from PowerShell, it's not very useful.
             */
            public static void Main()
            {
                Credential[] Creds = null;
                Credential Cred = new Credential();
                int Rtn = 0;

                Console.WriteLine("Testing CredWrite()");
                Rtn = AddCred();
                if (!CheckError("CredWrite", (CRED_ERRORS)Rtn))
                {
                    return;
                }
                Console.WriteLine("Testing CredEnum()");
                Rtn = CredEnum(null, out Creds);
                if (!CheckError("CredEnum", (CRED_ERRORS)Rtn))
                {
                    return;
                }
                Console.WriteLine("Testing CredRead()");
                Rtn = CredRead("Target", CRED_TYPE.GENERIC, out Cred);
                if (!CheckError("CredRead", (CRED_ERRORS)Rtn))
                {
                    return;
                }
                Console.WriteLine("Testing CredDelete()");
                Rtn = CredDelete("Target", CRED_TYPE.GENERIC);
                if (!CheckError("CredDelete", (CRED_ERRORS)Rtn))
                {
                    return;
                }
                Console.WriteLine("Testing CredRead() again");
                Rtn = CredRead("Target", CRED_TYPE.GENERIC, out Cred);
                if (!CheckError("CredRead", (CRED_ERRORS)Rtn))
                {
                    Console.WriteLine("if the error is 'ERROR_NOT_FOUND', this result is OK.");
                }
            }
        }
    }
"@
    #endregion

    $PsCredMan = $null
    try
    {
     $PsCredMan = [PsUtils.CredMan]
    }
    catch
    {
     #only remove the error we generate
     try {$Error.RemoveAt($Error.Count-1)} catch {Write-Verbose "No past errors yet..."}
    
    }
    if($null -eq $PsCredMan)
    {
     Add-Type $PsCredmanUtils
    }
    #endregion

    #region Internal Tools
    [HashTable] $ErrorCategory = @{0x80070057 = "InvalidArgument";
                                   0x800703EC = "InvalidData";
                                   0x80070490 = "ObjectNotFound";
                                   0x80070520 = "SecurityError";
                                   0x8007089A = "SecurityError"}

    function Get-CredType {
     Param (
      [Parameter(Mandatory=$true)]
            [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
            [String]$CredType
     )
     
     switch($CredType) {
      "GENERIC" {return [PsUtils.CredMan+CRED_TYPE]::GENERIC}
      "DOMAIN_PASSWORD" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_PASSWORD}
      "DOMAIN_CERTIFICATE" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_CERTIFICATE}
      "DOMAIN_VISIBLE_PASSWORD" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_VISIBLE_PASSWORD}
      "GENERIC_CERTIFICATE" {return [PsUtils.CredMan+CRED_TYPE]::GENERIC_CERTIFICATE}
      "DOMAIN_EXTENDED" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_EXTENDED}
      "MAXIMUM" {return [PsUtils.CredMan+CRED_TYPE]::MAXIMUM}
      "MAXIMUM_EX" {return [PsUtils.CredMan+CRED_TYPE]::MAXIMUM_EX}
     }
    }

    function Get-CredPersist {
     Param (
      [Parameter(Mandatory=$true)]
            [ValidateSet("SESSION","LOCAL_MACHINE","ENTERPRISE")]
            [String] $CredPersist
     )
     
     switch($CredPersist) {
      "SESSION" {return [PsUtils.CredMan+CRED_PERSIST]::SESSION}
      "LOCAL_MACHINE" {return [PsUtils.CredMan+CRED_PERSIST]::LOCAL_MACHINE}
      "ENTERPRISE" {return [PsUtils.CredMan+CRED_PERSIST]::ENTERPRISE}
     }
    }
    #endregion

    #region Dot-Sourced API
    function Del-Creds {
        <#
        .Synopsis
            Deletes the specified credentials

        .Description
            Calls Win32 CredDeleteW via [PsUtils.CredMan]::CredDelete

        .INPUTS
            See function-level notes

        .OUTPUTS
            0 or non-0 according to action success
            [Management.Automation.ErrorRecord] if error encountered

        .PARAMETER Target
            Specifies the URI for which the credentials are associated
          
        .PARAMETER CredType
            Specifies the desired credentials type; defaults to 
            "CRED_TYPE_GENERIC"
        #>

     Param (
      [Parameter(Mandatory=$true)]
            [ValidateLength(1,32767)]
            [String] $Target,

      [Parameter(Mandatory=$false)]
            [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
            [String] $CredType = "GENERIC"
     )
     
     [Int]$Results = 0
     try {
      $Results = [PsUtils.CredMan]::CredDelete($Target, $(Get-CredType $CredType))
     }
     catch {
      return $_
     }
     if(0 -ne $Results) {
      [String]$Msg = "Failed to delete credentials store for target '$Target'"
      [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
      [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
      return $ErrRcd
     }
     return $Results
    }

    function Enum-Creds {
        <#
        .Synopsis
          Enumerates stored credentials for operating user

        .Description
          Calls Win32 CredEnumerateW via [PsUtils.CredMan]::CredEnum

        .INPUTS
          
        .OUTPUTS
          [PsUtils.CredMan+Credential[]] if successful
          [Management.Automation.ErrorRecord] if unsuccessful or error encountered

        .PARAMETER Filter
          Specifies the filter to be applied to the query
          Defaults to [String]::Empty
          
        #>

     Param (
      [Parameter(Mandatory=$false)]
            [AllowEmptyString()]
            [String]$Filter = [String]::Empty
     )
     
     [PsUtils.CredMan+Credential[]]$Creds = [Array]::CreateInstance([PsUtils.CredMan+Credential], 0)
     [Int]$Results = 0
     try {
      $Results = [PsUtils.CredMan]::CredEnum($Filter, [Ref]$Creds)
     }
     catch {
      return $_
     }
     switch($Results) {
            0 {break}
            0x80070490 {break} #ERROR_NOT_FOUND
            default {
          [String]$Msg = "Failed to enumerate credentials store for user '$Env:UserName'"
          [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
          [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
          return $ErrRcd
            }
     }
     return $Creds
    }

    function Read-Creds {
        <#
        .Synopsis
            Reads specified credentials for operating user

        .Description
            Calls Win32 CredReadW via [PsUtils.CredMan]::CredRead

        .INPUTS

        .OUTPUTS
            [PsUtils.CredMan+Credential] if successful
            [Management.Automation.ErrorRecord] if unsuccessful or error encountered

        .PARAMETER Target
            Specifies the URI for which the credentials are associated
            If not provided, the username is used as the target
          
        .PARAMETER CredType
            Specifies the desired credentials type; defaults to 
            "CRED_TYPE_GENERIC"
        #>

     Param (
      [Parameter(Mandatory=$true)]
            [ValidateLength(1,32767)]
            [String]$Target,

      [Parameter(Mandatory=$false)]
            [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
            [String]$CredType = "GENERIC"
     )
     
        #CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
     if ("GENERIC" -ne $CredType -and 337 -lt $Target.Length) { 
      [String]$Msg = "Target field is longer ($($Target.Length)) than allowed (max 337 characters)"
      [Management.ManagementException]$MgmtException = New-Object Management.ManagementException($Msg)
      [Management.Automation.ErrorRecord]$ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, 666, 'LimitsExceeded', $null)
      return $ErrRcd
     }
     [PsUtils.CredMan+Credential]$Cred = New-Object PsUtils.CredMan+Credential
        [Int]$Results = 0
     try {
      $Results = [PsUtils.CredMan]::CredRead($Target, $(Get-CredType $CredType), [Ref]$Cred)
     }
     catch {
      return $_
     }
     
     switch($Results) {
            0 {break}
            0x80070490 {return $null} #ERROR_NOT_FOUND
            default {
          [String] $Msg = "Error reading credentials for target '$Target' from '$Env:UserName' credentials store"
          [Management.ManagementException]$MgmtException = New-Object Management.ManagementException($Msg)
          [Management.Automation.ErrorRecord]$ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
          return $ErrRcd
            }
     }
     return $Cred
    }

    function Write-Creds {
        <#
        .Synopsis
          Saves or updates specified credentials for operating user

        .Description
          Calls Win32 CredWriteW via [PsUtils.CredMan]::CredWrite

        .INPUTS

        .OUTPUTS
          [Boolean] true if successful
          [Management.Automation.ErrorRecord] if unsuccessful or error encountered

        .PARAMETER Target
          Specifies the URI for which the credentials are associated
          If not provided, the username is used as the target
          
        .PARAMETER UserName
          Specifies the name of credential to be read
          
        .PARAMETER Password
          Specifies the password of credential to be read
          
        .PARAMETER Comment
          Allows the caller to specify the comment associated with 
          these credentials
          
        .PARAMETER CredType
          Specifies the desired credentials type; defaults to 
          "CRED_TYPE_GENERIC"

        .PARAMETER CredPersist
          Specifies the desired credentials storage type;
          defaults to "CRED_PERSIST_ENTERPRISE"
        #>

     Param (
      [Parameter(Mandatory=$false)]
            [ValidateLength(0,32676)]
            [String]$Target,

      [Parameter(Mandatory=$true)]
            [ValidateLength(1,512)]
            [String]$UserName,

      [Parameter(Mandatory=$true)]
            [ValidateLength(1,512)]
            [String]$Password,

      [Parameter(Mandatory=$false)]
            [ValidateLength(0,256)]
            [String]$Comment = [String]::Empty,

      [Parameter(Mandatory=$false)]
            [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
            [String]$CredType = "GENERIC",

      [Parameter(Mandatory=$false)]
            [ValidateSet("SESSION","LOCAL_MACHINE","ENTERPRISE")]
            [String]$CredPersist = "ENTERPRISE"
     )

     if ([String]::IsNullOrEmpty($Target)) {
      $Target = $UserName
     }
        #CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
     if ("GENERIC" -ne $CredType -and 337 -lt $Target.Length) {
      [String] $Msg = "Target field is longer ($($Target.Length)) than allowed (max 337 characters)"
      [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
      [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, 666, 'LimitsExceeded', $null)
      return $ErrRcd
     }
        if ([String]::IsNullOrEmpty($Comment)) {
            $Comment = [String]::Format("Last edited by {0}\{1} on {2}",$Env:UserDomain,$Env:UserName,$Env:ComputerName)
        }
     [String]$DomainName = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
     [PsUtils.CredMan+Credential]$Cred = New-Object PsUtils.CredMan+Credential
     
        switch($Target -eq $UserName -and 
        $("CRED_TYPE_DOMAIN_PASSWORD" -eq $CredType -or "CRED_TYPE_DOMAIN_CERTIFICATE" -eq $CredType)) {
      $true  {$Cred.Flags = [PsUtils.CredMan+CRED_FLAGS]::USERNAME_TARGET}
      $false  {$Cred.Flags = [PsUtils.CredMan+CRED_FLAGS]::NONE}
     }
     $Cred.Type = Get-CredType $CredType
     $Cred.TargetName = $Target
     $Cred.UserName = $UserName
     $Cred.AttributeCount = 0
     $Cred.Persist = Get-CredPersist $CredPersist
     $Cred.CredentialBlobSize = [Text.Encoding]::Unicode.GetBytes($Password).Length
     $Cred.CredentialBlob = $Password
     $Cred.Comment = $Comment

     [Int] $Results = 0
     try {
      $Results = [PsUtils.CredMan]::CredWrite($Cred)
     }
     catch {
      return $_
     }

     if(0 -ne $Results) {
      [String] $Msg = "Failed to write to credentials store for target '$Target' using '$UserName', '$Password', '$Comment'"
      [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
      [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
      return $ErrRcd
     }
     return $Results
    }

    #endregion

    #region Cmd-Line functionality
    function CredManMain {
    #region Adding credentials
     if ($AddCred) {
      if([String]::IsNullOrEmpty($User) -or [String]::IsNullOrEmpty($Pass)) {
       Write-Host "You must supply a user name and password (target URI is optional)."
       return
      }
      # may be [Int32] or [Management.Automation.ErrorRecord]
      [Object]$Results = Write-Creds $Target $User $Pass $Comment $CredType $CredPersist
      if (0 -eq $Results) {
       [Object]$Cred = Read-Creds $Target $CredType
       if ($null -eq $Cred) {
        Write-Host "Credentials for '$Target', '$User' was not found."
        return
       }
       if ($Cred -is [Management.Automation.ErrorRecord]) {
        return $Cred
       }

                New-Variable -Name "AddedCredentialsObject" -Value $(
                    [pscustomobject][ordered]@{
                        UserName    = $($Cred.UserName)
                        Password    = $($Cred.CredentialBlob)
                        Target      = $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
                        Updated     = "$([String]::Format('{0:yyyy-MM-dd HH:mm:ss}', $Cred.LastWritten.ToUniversalTime())) UTC"
                        Comment     = $($Cred.Comment)
                    }
                )

       return $AddedCredentialsObject
      }
      # will be a [Management.Automation.ErrorRecord]
      return $Results
     }
    #endregion 

    #region Removing credentials
     if ($DelCred) {
      if (-not $Target) {
       Write-Host "You must supply a target URI."
       return
      }
      # may be [Int32] or [Management.Automation.ErrorRecord]
      [Object]$Results = Del-Creds $Target $CredType 
      if (0 -eq $Results) {
       Write-Host "Successfully deleted credentials for '$Target'"
       return
      }
      # will be a [Management.Automation.ErrorRecord]
      return $Results
     }
    #endregion

    #region Reading selected credential
     if ($GetCred) {
      if(-not $Target) {
       Write-Host "You must supply a target URI."
       return
      }
      # may be [PsUtils.CredMan+Credential] or [Management.Automation.ErrorRecord]
      [Object]$Cred = Read-Creds $Target $CredType
      if ($null -eq $Cred) {
       Write-Host "Credential for '$Target' as '$CredType' type was not found."
       return
      }
      if ($Cred -is [Management.Automation.ErrorRecord]) {
       return $Cred
      }

            New-Variable -Name "AddedCredentialsObject" -Value $(
                [pscustomobject][ordered]@{
                    UserName    = $($Cred.UserName)
                    Password    = $($Cred.CredentialBlob)
                    Target      = $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
                    Updated     = "$([String]::Format('{0:yyyy-MM-dd HH:mm:ss}', $Cred.LastWritten.ToUniversalTime())) UTC"
                    Comment     = $($Cred.Comment)
                }
            )

            return $AddedCredentialsObject
     }
    #endregion

    #region Reading all credentials
     if ($ShoCred) {
      # may be [PsUtils.CredMan+Credential[]] or [Management.Automation.ErrorRecord]
      [Object]$Creds = Enum-Creds
      if ($Creds -split [Array] -and 0 -eq $Creds.Length) {
       Write-Host "No Credentials found for $($Env:UserName)"
       return
      }
      if ($Creds -is [Management.Automation.ErrorRecord]) {
       return $Creds
      }

            $ArrayOfCredObjects = @()
      foreach($Cred in $Creds) {
                New-Variable -Name "AddedCredentialsObject" -Value $(
                    [pscustomobject][ordered]@{
                        UserName    = $($Cred.UserName)
                        Password    = $($Cred.CredentialBlob)
                        Target      = $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
                        Updated     = "$([String]::Format('{0:yyyy-MM-dd HH:mm:ss}', $Cred.LastWritten.ToUniversalTime())) UTC"
                        Comment     = $($Cred.Comment)
                    }
                ) -Force

                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Alias" -Value "$($Cred.TargetAlias)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "AttribCnt" -Value "$($Cred.AttributeCount)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Attribs" -Value "$($Cred.Attributes)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Flags" -Value "$($Cred.Flags)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "PwdSize" -Value "$($Cred.CredentialBlobSize)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Storage" -Value "$($Cred.Persist)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Type" -Value "$($Cred.Type)"

                $ArrayOfCredObjects +=, $AddedCredentialsObject
      }
      return $ArrayOfCredObjects
     }
    #endregion

    #region Run basic diagnostics
     if($RunTests) {
      [PsUtils.CredMan]::Main()
     }
    #endregion
    }
    #endregion

    CredManMain
}


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


<#
    .SYNOPSIS
        Test to make sure ssh or https authentication is working.

    .DESCRIPTION
        See Synopsis.
    
    .PARAMETER GitHubUserName
        TODO

    .PARAMETER AuthMethod
        TODO

    .PARAMETER ExistingSSHPrivateKeyPath
        TODO

    .PARAMETER PersonalAccessToken
        TODO
    
    .EXAMPLE
        # Launch PowerShell and...

        $TestGitAuthParams = @{
            GitHubUserName = "pldmgg"
            AuthMethod = "https"
            PersonalAccessToken = "2345678dsfghjk4567890"
        }

        Test-GitAuthentication @TestGitAuthParams

#>
function Test-GitAuthentication {
    [CmdletBinding(DefaultParameterSetName='ssh')]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$GitHubUserName,

        [Parameter(Mandatory=$True)]
        [ValidateSet("https","ssh")]
        [string]$AuthMethod,

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

        $SSHKeyGenPath = $(Get-ChildItem "C:\Program Files\Git" -Recurse -Filter "*ssh-keygen.exe").FullName
        if (!$SSHKeyGenPath) {
            Write-Error "Unable to fing git CmdLine instance of ssh-keygen.exe! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $SSHExePath = $(Get-ChildItem "C:\Program Files\Git" -Recurse -Filter "ssh.exe").FullName
        if (!$SSHExePath) {
            Write-Error "Unable to fing git CmdLine instance of ssh.exe! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Check To Make Sure Online GitHub Account is aware of Existing Public Key
        $PubSSHKeys = Invoke-Restmethod -Uri "https://api.github.com/users/$GitHubUserName/keys"
        $tempfileLocations = @()
        foreach ($PubKeyObject in $PubSSHKeys) {
            $tmpFile = [IO.Path]::GetTempFileName()
            $PubKeyObject.key | Out-File $tmpFile -Encoding ASCII

            $tempfileLocations +=, $tmpFile
        }
        $SSHPubKeyFingerPrintsFromGitHub = foreach ($TempPubSSHKeyFile in $tempfileLocations) {
            $PubKeyFingerPrintPrep = & "$SSHKeyGenPath" -E md5 -lf "$TempPubSSHKeyFile"
            $PubKeyFingerPrint = $($PubKeyFingerPrintPrep -split " ")[1] -replace "MD5:",""
            $PubKeyFingerPrint
        }
        # Cleanup Temp Files
        foreach ($TempPubSSHKeyFile in $tempfileLocations) {
            Remove-Item $TempPubSSHKeyFile
        }

        $GitHubOnlineIsAware = @()
        foreach ($fingerprint in $SSHPubKeyFingerPrintsFromGitHub) {
            $ExistingSSHPubKeyPath = "$ExistingSSHPrivateKeyPath.pub"
            $LocalPubKeyFingerPrintPrep = & "$SSHKeyGenPath" -E md5 -lf "$ExistingSSHPubKeyPath"
            $LocalPubKeyFingerPrint = $($LocalPubKeyFingerPrintPrep -split " ")[1] -replace "MD5:",""
            if ($fingerprint -eq $LocalPubKeyFingerPrint) {
                $GitHubOnlineIsAware +=, $fingerprint
            }
        }

        if ($GitHubOnlineIsAware.Count -gt 0) {
            Write-Host "GitHub Online Account is aware of existing public key $ExistingSSHPubKeyPath. Testing the connection..." -ForegroundColor Green

            $null = git config core.sshCommand "ssh -i $([regex]::Escape($ExistingSSHPrivateKeyPath)) -F /dev/null" 2>&1
            $env:GIT_SSH_COMMAND = "ssh -i $([regex]::Escape($ExistingSSHPrivateKeyPath))"

            # Test the connection
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.FileName = $SSHExePath
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = "-o `"StrictHostKeyChecking=no`" -i `"$ExistingSSHPrivateKeyPath`" -T git@github.com"
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            $Process.WaitForExit()
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $AllOutput = $stdout + $stderr

            if ($AllOutput -match $GitHubUserName) {
                Write-Host "GitHub Authentication via SSH for $GitHubUserName using '$ExistingSSHPrivateKeyPath' was successful." -ForegroundColor Green
                $True
            }
            else {
                Write-Warning "GitHub Authentication for $GitHubUserName using SSH was NOT successful. Please check your connection and/or keys."
                $False
            }
        }
    }
    if ($AuthMethod -eq "https") {
        if (!$PersonalAccessToken) {
            $PersonalAccessToken = Read-Host -Prompt "Please enter the GitHub Personal Access Token you would like to use for https authentication." -AsSecureString
        }

        # Convert SecureString to PlainText
        $PersonalAccessTokenPT = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PersonalAccessToken))
        $Headers = @{
            Authorization = "token $PersonalAccessTokenPT"
        }
        $PublicAndPrivateRepos = $(Invoke-RestMethod -Headers $Headers -Uri "https://api.github.com/user/repos").Name
        # Rest API Alternate Method
        <#
        $Token = "$GitHubUserName`:$PersonalAccessTokenPT"
        $Base64Token = [System.Convert]::ToBase64String([char[]]$Token)
        $Headers = @{
            Authorization = "Basic {0}" -f $Base64Token
        }
        $PublicAndPrivateRepos = $(Invoke-RestMethod -Headers $Headers -Uri "https://api.github.com/user/repos?access_token=$PersonalAccessTokenPT").Name
        #>

        if ($PublicAndPrivateRepos -ne $null) {
            Write-Host "GitHub Authentication via https for $GitHubUserName was successful!" -ForegroundColor Green
            $True
        }
        else {
            Write-Warning "GitHub Authentication via https for $GitHubUserName was NOT successful. Please check your Personal Authentication Token."
            $False
        }
    }
}



if ($PSVersionTable.Platform -eq "Win32NT" -and $PSVersionTable.PSEdition -eq "Core") {
    if (![bool]$(Get-Module -ListAvailable WindowsCompatibility)) {
        try {
            Install-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if (![bool]$(Get-Module WindowsCompatibility)) {
        try {
            Import-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error $_
            Write-Warning "The $ThisModule Module was NOT loaded successfully! Please run:`n    Remove-Module $ThisModule"
            $global:FunctionResult = "1"
            return
        }
    }
}

[System.Collections.ArrayList]$script:FunctionsForSBUse = @(
    ${Function:GetElevation}.Ast.Extent.Text
    ${Function:NewUniqueString}.Ast.Extent.Text
    ${Function:Clone-GitRepo}.Ast.Extent.Text
    ${Function:Configure-GitCmdLine}.Ast.Extent.Text
    ${Function:Install-GitCmdLine}.Ast.Extent.Text
    ${Function:Install-GitDesktop}.Ast.Extent.Text
    ${Function:Manage-StoredCredentials}.Ast.Extent.Text
    ${Function:New-GitRepo}.Ast.Extent.Text
    ${Function:Test-GitAuthentication}.Ast.Extent.Text
)

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUbKvPoQ1CWIxfGvXtGmpqbIqn
# P5ugggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFpbL2RPyVpAsAbd
# X6vNTaf7M7bOMA0GCSqGSIb3DQEBAQUABIIBAKutG+pm3DrBGp2GZuoF9bjLLMlM
# Ww7Az8xyG/43qL7U/jMoTUKmXc6eWN+PbYF3fzMwV5I/K+JpD74fWf6eng56fuVX
# G/OMIJDqhKeJrXTwoSwhc7GH57/362rQtQ+HJT6U3v6upNR0UbIXAgGpiCDm+o8N
# HAL0Hk2kv+YluEglQ5QNoxqe7XnwjWFKNEfOLwjAgXpUrDOKCaybw+iltiiWe5Fu
# CEXB5NMbSan3vDMpJn+i+thMxjxUm1SSqxi8irf+UmXGajKSCkEKmBxoRs80/4gx
# W5YuW9BQmAfgttkI0R+aAcVsEhUtGP2cT5/BzXpGikq2adPrEQD+/2qYcf0=
# SIG # End signature block
