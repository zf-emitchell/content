. $PSScriptRoot\CommonServerPowerShell.ps1
$global:HOSTNAME = $demisto.Params().hostname
$global:USERNAME = $demisto.Params().credentials.identifier
$global:PASSWORD = $demisto.Params().credentials.password

function CreateSession ()
{
    <#
    .Description
    Creates a session to target machine using hostname, username and password
    #>
    $user = 'winrm\administrator'
    $password=ConvertTo-SecureString 'dD(;RJP?bRDI8qz=9mK2XK)ul;T*AT2Q' –asplaintext –force
    $Creds = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $password
    $Session = New-PSSession -ComputerName 172.31.38.7 -Authentication Negotiate -credential $Creds -ErrorAction Stop
    return $Session
}

function InvokeCommand ($Command)
{
    <#
    .Description
    Runs invoke-command on existing session.
    .Example
    Get-Process powershell
    #>
    $Title = "Result for PowerShell Remote SSH Command: $Command `n"
    $Session = CreateSession
    $Temp = $demisto.UniqueFile()
    $FileName = $demisto.Investigation().id + "_" + $Temp + ".ps1"
    echo $Command | Out-File -FilePath $FileName
    $Result = Invoke-Command $Session -FilePath $FileName
    $EntryContext = [PSCustomObject]@{Command = $Command;Result = $Result}
    $Context = [PSCustomObject]@{
        PowerShellSSH = [PSCustomObject]@{Query=$EntryContext}
    }
    $Contents = $Title + $Result

    $DemistoResult = @{
        Type = 1;
        ContentsFormat = "json";
        Contents = $Contents;
        EntryContext = $Context;
        ReadableContentsFormat = "markdown";
        HumanReadable = $Contents
    }
    return $DemistoResult
}

function DownloadFile ($Command)
{
    $Temp = $demisto.UniqueFile()
    $FileName = $demisto.Investigation().id + "_" + $Temp
    $Session = CreateSession
    Copy-Item -FromSession $Session $Command -Destination $FileName
    $Session | Remove-PSsession
    $DemistoResult = @{
       Type = 3;
       ContentsFormat = "text";
       Contents = "";
       File = $FileName;
       FileID = $Temp
    }
    return $DemistoResult
}

$demisto.Info("Current command is: " + $demisto.GetCommand())

switch -Exact ($demisto.GetCommand())
{
    'test-module' {
        $TestConnection = InvokeCommand('$PSVersionTable')
        $demisto.Results('ok'); Break
    }
    'pwsh-remoting-query' {
        $Command = $demisto.Args().command
        $RunCommand = InvokeCommand($Command)
        $demisto.Results($RunCommand); Break
    }
    'pwsh-download-file' {
        $Path = $demisto.Args().path
        $FileResult = DownloadFile($Path)
        $demisto.Results($FileResult); Break
    }
    Default {
        $demisto.Error('Unsupported command was entered.')
    }
}
