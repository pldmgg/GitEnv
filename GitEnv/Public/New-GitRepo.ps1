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

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUm2coJzRZMCmuCK7Wr/dJR/0F
# CnOgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFA8xJWNYB4PQJVqd
# HXf9Bb6EE2QBMA0GCSqGSIb3DQEBAQUABIIBAHu6uSV60aAC1yIS+HXUELQ4hPN0
# x/1qdnX+uIdGXtrHpQqRlPHr46L8YW1kUzXIY9sNOzbTt8xyQ1SKuB6fewkMkhiP
# 41cXt2JQFT/uy1mM3PVEo6Ofl+9Qn82/9gPJLcyXEw2wIKdGPT0V4whDkchW+LRx
# F6/Cc8TQOGRtiQT6SAnJlaSxl1dOSVKM43Ebnys6zOveu+q+yuytXX0gKFytl0Q+
# 53dKLS7taLwiCj9uJYLfiXg7cPBnei4Bi8aeNbmp5Qo2AuA/pvc1kWI9MXYrlyNw
# HVpvDX8aV1UPS3l25faGxaeIYqlpHK43DuJAFqfgYHTWl+Jp0lDEQc9aNWU=
# SIG # End signature block
