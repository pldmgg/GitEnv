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
