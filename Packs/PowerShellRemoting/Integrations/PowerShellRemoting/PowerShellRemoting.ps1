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
    $fqdn = $Hostname | ForEach-Object -Process {$_ + $global:DOMAIN}
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
    $Session | Remove-PSsession
    $EntryContext = [PSCustomObject]@{Command = $Command;Result = $Result}
    $Context = [PSCustomObject]@{
        PsRemote = [PSCustomObject]@{Query=$EntryContext}
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
    $Command = '[System.IO.File]::Exists("' + $Path + '")'
    $Result = InvokeCommandInSession $Command $Session
    if(-Not $Result) {
        $Session | Remove-PSsession
        ReturnError($Path + " was not found on the remote host.")
        exit(0)
    }

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
         $DstHash = (Get-FileHash $FileName -Algorithm MD5).Hash
         if($SrcHash -ne $DstHash) {
            ReturnError('Failed check_hash: The downloaded file has a different hash than the file in the host. RemoteHostHash=' + $SrcHash + ' DownloadedHash=' + $DstHash)
            exit(0)
         }
    }
    $FileNameLeaf = Split-Path $Path -leaf

    $DemistoResult = @{
       Type = 3;
       ContentsFormat = "text";
       Contents = "";
       File = $FileNameLeaf;
       FileID = $Temp
    }
    $demisto.Results($DemistoResult)

    $FileExtension = [System.IO.Path]::GetExtension($FileNameLeaf)
    $FileExtension = If ($FileExtension) {$FileExtension.SubString(1, $FileExtension.length - 1)} else {""}

    $EntryContext = [PSCustomObject]@{
        PsRemoteDownloadedFile = [PSCustomObject]@{
            FileName = $FileNameLeaf;
            FileSize = Get-Item $FileName | % {[math]::ceiling($_.length / 1kb)};
            FileSHA1 = (Get-FileHash $FileName -Algorithm SHA1).Hash;
            FileSHA256 = (Get-FileHash $FileName -Algorithm SHA256).Hash;
            FileMD5 = (Get-FileHash $FileName -Algorithm MD5).Hash;
            FileExtension = $FileExtension
          }
    }
    return $DemistoResult = @{
       Type = 1;
       ContentsFormat = "text";
       Contents = "";
       EntryContext = $EntryContext;
    }
}

function StartETL ($Hostname, $EtlPath, $EtlFilter, $EtlMaxSize, $EtlTimeLim, $Overwrite)
{
    $Title = "You have executed the start ETL command successfully `n"
    $Command = 'netsh trace start capture=yes traceFile=' + $EtlPath + ' maxsize=' + $EtlMaxSize + ' overwrite=' + $Overwrite + ' ' + $EtlFilter
    $Session = CreateSession $Hostname
    $Contents = InvokeCommandInSession $Command $Session
    $Session | Remove-PSsession
    $EntryContext = [PSCustomObject]@{
        PsRemote = [PSCustomObject]@{CommandResult = $Contents; EtlFilePath = $EtlPath; EtlFileName = Split-Path $EtlPath -leaf}
    }

    $DemistoResult = @{
        Type = 1;
        ContentsFormat = "json";
        Contents = $Contents;
        EntryContext = $EntryContext;
        ReadableContentsFormat = "markdown";
        HumanReadable = $Title + $Contents;
    }

    return $DemistoResult
}

function StopETL ($Hostname)
{
    $Command = 'netsh trace stop'
    $Session = CreateSession $Hostname
    $Contents = InvokeCommandInSession $Command $Session
    $Session | Remove-PSsession
    $EtlPath = echo $Contents | Select-String -Pattern "File location = "
    if($EtlPath) {
        $EtlPath = $EtlPath.ToString()
        $EtlPath = $EtlPath.Substring(16, $EtlPath.Length - 16)
    } else {
        $EtlPath = ""
    }
    if($Contents) {
        $Contents = [string]$Contents
    }
    $EntryContext = [PSCustomObject]@{
        PsRemote = [PSCustomObject]@{CommandResult = $Contents; EtlFilePath = $EtlPath; EtlFileName = If ($EtlPath) {Split-Path $EtlPath -leaf} else {""}}
    }

    $DemistoResult = @{
        Type = 1;
        ContentsFormat = "json";
        Contents = $Contents;
        EntryContext = $EntryContext;
        ReadableContentsFormat = "markdown";
        HumanReadable = $Contents;
    }

    return $DemistoResult
}

function ExportRegistry ($Hostname, $RegKeyHive, $FilePath)
{
    $command = If ($RegKeyHive -eq 'all') {'regedit /e '} Else {'reg export ' + $RegKeyHive + ' '}
    $command = $command + $FilePath
    $Title = "Ran Export Registry. `n"
    $Session = CreateSession $Hostname
    $Contents = InvokeCommandInSession $Command $Session
    $command = 'Get-Item ' + $FilePath + ' | % {[math]::ceiling($_.length / 1kb)}'
    $FileSize = InvokeCommandInSession $command $Session
    $Session | Remove-PSsession
    $EntryContext = [PSCustomObject]@{
        PsRemote = [PSCustomObject]@{CommandResult = $Contents; RegistryFilePath = $FilePath; RegistryFileName = Split-Path $FilePath -leaf}
    }

    $DemistoResult = @{
        Type = 1;
        ContentsFormat = "json";
        Contents = $Contents;
        EntryContext = $EntryContext;
        ReadableContentsFormat = "markdown";
        HumanReadable = $Title + $Contents;
    }

    return $DemistoResult
}

function UploadFile($EntryId, $DstPath, $Hostname, $ZipFile, $CheckHash)
{
    $Session = CreateSession $Hostname
    $SrcPath = $demisto.GetFilePath($EntryId).path
    if($ZipFile -eq 'true') {
        $OldPath = $SrcPath
        $SrcPath = $SrcPath + ".zip"
        Compress-Archive -Path $OldPath -Update -DestinationPath $SrcPath
    }
    if($CheckHash -eq 'true') {
         $SrcHash = (Get-FileHash $SrcPath -Algorithm MD5).Hash
    }
    Copy-Item -ToSession $Session $SrcPath -Destination $DstPath
    if($CheckHash -eq 'true') {
         $command = '(Get-FileHash ' + $DstPath + ' -Algorithm MD5).Hash'
         $DstHash = InvokeCommandInSession $command $Session
         if($SrcHash -ne $DstHash) {
            ReturnError('Failed check_hash: The uploaded file has a different hash than the local file. LocalFileHash=' + $SrcHash + ' UploadedFileHash=' + $DstHash)
            exit(0)
         }
    }
    $Session | Remove-PSsession

    $FileNameLeaf = Split-Path $SrcPath -leaf
    $FileExtension = [System.IO.Path]::GetExtension($FileNameLeaf)
    $FileExtension = If ($FileExtension) {$FileExtension.SubString(1, $FileExtension.length - 1)} else {""}

    $EntryContext = [PSCustomObject]@{
        PsRemoteDownloadedFile = [PSCustomObject]@{
            FileName = $FileNameLeaf;
            FileSize = Get-Item $SrcPath | % {[math]::ceiling($_.length / 1kb)};
            FileSHA1 = (Get-FileHash $SrcPath -Algorithm SHA1).Hash;
            FileSHA256 = (Get-FileHash $SrcPath -Algorithm SHA256).Hash;
            FileMD5 = (Get-FileHash $SrcPath -Algorithm MD5).Hash;
            FileExtension = $FileExtension
          }
    }
    return $DemistoResult = @{
       Type = 1;
       ContentsFormat = "text";
       Contents = "";
       EntryContext = $EntryContext;
       HumanReadable = "File upload command finished execution."
    }
}

$demisto.Info("Current command is: " + $demisto.GetCommand())

switch -Exact ($demisto.GetCommand())
{
    'test-module' {
        $Hostname = ArgToList $global:HOSTNAME
        $TestConnection = InvokeCommand '$PSVersionTable' $Hostname
        $demisto.Results('ok'); Break
    }
    'ps-remote-query' {
        $Command = $demisto.Args().command
        $Hostname = ArgToList $demisto.Args().host

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
        $Hostname = ArgToList $demisto.Args().host
        $EtlPath = $demisto.Args().etl_path
        $EtlFilter = $demisto.Args().etl_filter
        $EtlMaxSize = $demisto.Args().etl_max_size
        $EtlTimeLim = $demisto.Args().etl_time_limit
        $Overwrite = $demisto.Args().overwrite

        $EtlStartResult = StartETL $Hostname $EtlPath $EtlFilter $EtlMaxSize $EtlTimeLim $Overwrite
        $demisto.Results($EtlStartResult); Break
    }
    'ps-remote-etl-create-stop' {
        $Hostname = ArgToList $demisto.Args().host

        $EtlStopResult = StopETL $Hostname
        $demisto.Results($EtlStopResult); Break
    }
    'ps-remote-export-registry' {
        $Hostname = ArgToList $demisto.Args().host
        $RegKeyHive = $demisto.Args().reg_key_hive
        $FilePath = $demisto.Args().file_path

        $result = ExportRegistry $Hostname $RegKeyHive $FilePath
        $demisto.Results($result); Break
    }
    'ps-remote-upload-file' {
        $EntryId = $demisto.Args().entry_id
        $Path = $demisto.Args().path
        $Hostname = $demisto.Args().host
        $ZipFile = $demisto.Args().zip_file
        $CheckHash = $demisto.Args().check_hash

        $Result = UploadFile $EntryId $Path $Hostname $ZipFile $CheckHash
        $demisto.Results($Result); Break
    }
    Default {
        $demisto.Error('Unsupported command was entered.')
    }
}
