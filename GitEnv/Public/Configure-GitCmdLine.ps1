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
            Comment = "Saved By Manage-StoredCredentials"
        }
        #>
        $ManageStoredCredsParams = @{
            Target  = "git:https://$GitHubUserName@github.com"
            User    = $GitHubUserName
            Pass    = $PersonalAccessTokenPT
            Comment = "Saved By Manage-StoredCredentials"
        }
        $null = Manage-StoredCredentials -AddCred @ManageStoredCredsParams

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

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUUtN8hHVmwW/QYavm1cjTyd87
# 3Wygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFB9nvEl9ARigHr7K
# VNBDftprDjtNMA0GCSqGSIb3DQEBAQUABIIBAK7qO5/TwsPfnj/UahAK6eOs2kgy
# J9z0QQ6DVLvPaYRk8jicg+PJjozLl1/aIrYgNNXmwnuogH4/n4OKaafbScbMMSqM
# zt3PNIOcouYfP5CODD/IGdDvBwqExapeXw9vEoWqfYGkQGYT0JG9s/IgQluNHc2e
# ytET3mqPy0KTwN5JiGYAZzKBUkyd5jW6p0S/MhK9RkBTEtueULU/H2+98TxwTL4/
# o82hqZVzKc353Dw/w286JGsDh2TWh69oCRwCqmmRgR7VH+Aoj0KnY59AOAFyats2
# r4DFwL/XTleIC/NRZjoq8qdrc3JP9feJjIau1UJL/RGcM1GyG47BZHB602M=
# SIG # End signature block
