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
