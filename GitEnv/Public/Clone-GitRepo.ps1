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

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUIfJnAaLduS8CoVJDNu5fNdz7
# Iiegggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFCwkyOVphatMG3Bm
# nzP15YxrIr/8MA0GCSqGSIb3DQEBAQUABIIBAHO0WG6iGumMXA7kPUD3GPk0yQZO
# zA2e64MzOy5WVw3UHfQiC1YHD5HDg0RxGexVTgr3s1xSRqKNBMGZiUJlfWd/rWH5
# eHL1/xEtfLfyjgI6KmhX9uVVZkin3Tz6B/ltXi9TBPariK0UCwFXtTfrCq9F0yVr
# j/veuQfXfg1TcAC4HwQv4tPYPn+Y5+o76h9zf4HoODh4IuZzn7brTVVxV8Vbj1VO
# sZOfRhKyK84JgG7HNfZRV0wzNN1UVIHOA7dXyjUmu/VtIEwQzfwjSYvbKzY+ib1x
# jfpjdi/oBzuO8sbCnLM1YxVLSGGZ8S9+gFumiLNfe5G62PMBq4Hd94HKPHg=
# SIG # End signature block
