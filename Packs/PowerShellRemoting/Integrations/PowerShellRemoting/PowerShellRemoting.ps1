$global:DOMAIN = If ($demisto.Params().domain) {"." + $demisto.Params().domain} Else {""}
$global:HOSTNAME = $demisto.Params().hostname
$global:USERNAME = $demisto.Params().credentials.identifier
$global:PASSWORD = $demisto.Params().credentials.password
$global:DNS = $demisto.Params().dns

if($global:DNS) {
    "nameserver $global:DNS" | Set-Content -Path \etc\resolv.conf
}

function CreateSession ($Hostname)
{
    <#
    .Description
    Creates a session to target machine using hostname, username and password
    #>
    $user = $global:USERNAME
    $password=ConvertTo-SecureString $global:PASSWORD –asplaintext –force
    $fqdn = $Hostname + $global:DOMAIN
    $Creds = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $password
    $Session = New-PSSession -ComputerName $fqdn -Authentication Negotiate -credential $Creds -ErrorAction Stop
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
    $Session = CreateSession $Hostname
    $Result = InvokeCommandInSession $Command $Session
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

function InvokeCommandInSession ($Command, $Session)
{
    $Temp = $demisto.UniqueFile()
    $FileName = $demisto.Investigation().id + "_" + $Temp + ".ps1"
    echo $Command | Out-File -FilePath $FileName
    return Invoke-Command $Session -FilePath $FileName
}

function DownloadFile ($Path, $Hostname, $ZipFile, $CheckHash)
{
    $Temp = $demisto.UniqueFile()
    $FileName = $demisto.Investigation().id + "_" + $Temp
    $Session = CreateSession $Hostname
    if($ZipFile -eq 'true') {
        $OldPath = $Path
        $Path = $Path + ".zip"
        $command = 'Compress-Archive -Path ' + $OldPath + ' -Update -DestinationPath ' + $Path
        InvokeCommandInSession $command $Session
    }
    if($CheckHash -eq 'true') {
         $command = '(Get-FileHash ' + $Path + ' -Algorithm MD5).Hash'
         $SrcHash = InvokeCommandInSession $command $Session
    }
    Copy-Item -FromSession $Session $Path -Destination $FileName
    if($ZipFile -eq 'true') {
        $command = 'Remove-Item ' + $Path
        InvokeCommandInSession $command $Session
    }
    $Session | Remove-PSsession
    if($CheckHash -eq 'true') {
         $DstHash = (Get-FileHash $FileName).Hash
         if($SrcHash -ne $DstHash) {
            ReturnError 'Failed check_hash: The downloaded file has a different hash than the file in the host. $SrcHash=' + $SrcHash + ' $DstHash=' + $DstHash
            exit(0)
         }
    }
    $DemistoResult = @{
       Type = 3;
       ContentsFormat = "text";
       Contents = "";
       File = $FileName;
       FileID = $Temp
    }
    return $DemistoResult
}

function StartETL ($Hostname, $EtlPath, $EtlFilter, $EtlMaxSize, $EtlTimeLim)
{
    $Command = 'netsh trace start capture=yes traceFile=' + $EtlPath + ' maxsize=' + $EtlMaxSize + ' ' + $EtlFilter
    return InvokeCommand $Command $Hostname
}

function StopETL ($Hostname)
{
    $Command = 'netsh trace stop'
    return InvokeCommand $Command $Hostname
}

function ExportRegistry ($Hostname, $RegKeyHive, $FilePath)
{
    $command = If ($RegKeyHive -eq 'all') {'regedit /e '} Else {'reg export ' + $RegKeyHive + ' '}
    $command = $command + $FilePaths
    return InvokeCommand $command $Hostname
}

$demisto.Info("Current command is: " + $demisto.GetCommand())

switch -Exact ($demisto.GetCommand())
{
    'test-module' {
        $TestConnection = InvokeCommand '$PSVersionTable' $global:HOSTNAME
        $demisto.Results('ok'); Break
    }
    'ps-remote-query' {
        $Command = $demisto.Args().command
        $Hostname = $demisto.Args().host

        $RunCommand = InvokeCommand $Command $Hostname
        $demisto.Results($RunCommand); Break
    }
    'ps-remote-download-file' {
        $Path = $demisto.Args().path
        $Hostname = $demisto.Args().host
        $ZipFile = $demisto.Args().zip_file
        $CheckHash = $demisto.Args().check_hash

        $FileResult = DownloadFile $Path $Hostname $ZipFile $CheckHash
        $demisto.Results($FileResult); Break
    }
    'ps-remote-etl-create-start' {
        $Hostname = $demisto.Args().host
        $EtlPath = $demisto.Args().etl_path
        $EtlFilter = $demisto.Args().etl_filter
        $EtlMaxSize = $demisto.Args().etl_max_size
        $EtlTimeLim = $demisto.Args().etl_time_limit

        $EtlStartResult = StartETL $Hostname $EtlPath $EtlFilter $EtlMaxSize $EtlTimeLim
        $demisto.Results($EtlStartResult); Break
    }
    'ps-remote-etl-create-stop' {
        $Hostname = $demisto.Args().host

        $EtlStopResult = StopETL $Hostname
        $demisto.Results($EtlStopResult); Break
    }
    'ps-remote-export-registry' {
        $Hostname = $demisto.Args().host
        $RegKeyHive = $demisto.Args().reg_key_hive
        $FilePath = $demisto.Args().file_path

        $result = ExportRegistry $Hostname $RegKeyHive $FilePath
        $demisto.Results($result); Break
    }
    Default {
        $demisto.Error('Unsupported command was entered.')
    }
}
