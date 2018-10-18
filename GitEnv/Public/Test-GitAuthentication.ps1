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
