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
