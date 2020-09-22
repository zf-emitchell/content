$global:HOSTNAME = $demisto.Params().hostname
$global:USERNAME = $demisto.Params().credentials.identifier
$global:PASSWORD = $demisto.Params().credentials.password

function CreateSession ($Hostname)
{
    <#
    .Description
    Creates a session to target machine using hostname, username and password
    #>
    $user = 'winrm\administrator'
    $password=ConvertTo-SecureString 'dD(;RJP?bRDI8qz=9mK2XK)ul;T*AT2Q' –asplaintext –force
    # $user = $global:USERNAME
    # $password=ConvertTo-SecureString $global:PASSWORD –asplaintext –force
    $Creds = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $password
    $Session = New-PSSession -ComputerName $Hostname -Authentication Negotiate -credential $Creds -ErrorAction Stop
    return $Session
}

function InvokeCommand ($Command, $Hostname)
{
    <#
    .Description
    Runs invoke-command on existing session.
    .Example
    Get-Process powershell
    #>
    $Title = "Result for PowerShell Remote SSH Command: $Command `n"
    $Session = CreateSession($Hostname)
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

function DownloadFile ($Command, $Hostname)
{
    $Temp = $demisto.UniqueFile()
    $FileName = $demisto.Investigation().id + "_" + $Temp
    $Session = CreateSession($Hostname)
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

function StartETL ($Host, $EtlPath, $EtlFilter, $EtlTimeLim, $EtlMaxSize)
{
    $Command = 'netsh trace start capture=yes traceFile=' + $EtlPath + ' maxsize=' + $EtlMaxSize + ' ' + $EtlFilter
    return InvokeCommand($Command, $Host)
}

function StopETL ($Host, $ZipFile, $CalculateHash)
{
    $Command = 'netsh trace stop'
    return InvokeCommand($Command, $Host)
}

$demisto.Info("Current command is: " + $demisto.GetCommand())

switch -Exact ($demisto.GetCommand())
{
    'test-module' {
        $TestConnection = InvokeCommand('$PSVersionTable', $global:HOSTNAME)
        $demisto.Results('ok'); Break
    }
    'ps-remote-query' {
        $Command = $demisto.Args().command
        $Host = $demisto.Args().host
        $RunCommand = InvokeCommand($Command, $Host)
        $demisto.Results($RunCommand); Break
    }
    'ps-remote-download-file' {
        $Path = $demisto.Args().path
        $Host = $demisto.Args().host
        $FileResult = DownloadFile($Path, $Host)
        $demisto.Results($FileResult); Break
    }
    'ps-remote-etl-create-start' {
        $Host = $demisto.Args().host
        $EtlPath = $demisto.Args().etl_path
        $EtlFilter = $demisto.Args().etl_filter
        $EtlMaxSize = $demisto.Args().etl_max_size
        $EtlTimeLim = $demisto.Args().etl_time_limit
        $EtlStartResult = StartETL($Host, $EtlPath, $EtlFilter, $EtlMaxSize, $EtlTimeLim)
        $demisto.Results($EtlStartResult); Break
    }
    'ps-remote-etl-create-stop' {
        $Host = $demisto.Args().host
        $ZipFile = $demisto.Args().zip_file
        $CalculateHash = $demisto.Args().calculate_hash
        $EtlStopResult = StopETL($Host, $EtlPath, $EtlFilter, $EtlMaxSize, $EtlTimeLim)
        $demisto.Results($EtlStopResult); Break
    }
    Default {
        $demisto.Error('Unsupported command was entered.')
    }
}
