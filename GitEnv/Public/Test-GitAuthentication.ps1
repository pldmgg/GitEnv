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

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU87ebV0jrOuhltkfBhF/5kJWt
# t1ygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFB43Q1L2vYofwMFK
# 8hxVHLhOJYMKMA0GCSqGSIb3DQEBAQUABIIBAIbFZl/LSV7ZRHU7icLQUWm1pyeq
# 7bocrDpokmzfFFMJyigYuttcYjN9CPiKdR7R19QAKO84jf2mQsAEqvnI5fQJT5eL
# bSgSbghM+3//Ie+QBJUahRgQDtVfXMuZbM7GgyPhx2owZuW3K36oS4VYeSMRZU+P
# cYuRTKPSORgaM4Zo4e3XwDQaLOUQFR9c0xHUC43ckB2GIsjD+s6LHQhsjFpnS8yv
# hECsB91Wr7FEBNPfJjDbFgcXGKfDz47WXN8ApIAjTyECyQKC8n1lUxcmetfIJcO2
# ACWPgJEOWr+XFsfREJi4ntXz1UBfHTc0z0KiNQCvFtN3Ai0tBAlqoJ9Noo8=
# SIG # End signature block
