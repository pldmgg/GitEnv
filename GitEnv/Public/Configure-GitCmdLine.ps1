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
