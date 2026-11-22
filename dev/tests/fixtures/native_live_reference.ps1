param([switch]$AllowLiveChanges,[switch]$Network,[switch]$ValidateOnly)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$executable=Join-Path $root 'bin/zapret-rust.exe'
$cases=@(
    @{Name='start';Action='start';Running=$true},
    @{Name='stop';Action='stop';Running=$false},
    @{Name='repeat-stop';Action='stop';Running=$false},
    @{Name='start-again';Action='start';Running=$true},
    @{Name='restart';Action='restart';Running=$true;Changed=$true},
    @{Name='bat-menu-stop';Action='menu';Running=$false;Bat=$true;Input="2`n`n0`n"},
    @{Name='bat-menu-start';Action='menu';Running=$true;Bat=$true;Input="1`n`n0`n"},
    @{Name='bat-menu-restart';Action='menu';Running=$true;Changed=$true;Bat=$true;Input="1`n`n0`n"},
    @{Name='settings-apply';Action='settings-current-alt';Running=$true;Changed=$true}
)
if($Network){
    $cases+=@(
        @{Name='connection-check';Action='connection-check --timeout-ms 5000 https://www.youtube.com https://discord.com https://store.steampowered.com';Running=$true},
        @{Name='webcheck';Action='webcheck --timeout-ms 10000 https://www.youtube.com';Running=$true}
    )
}
if($ValidateOnly){
    [pscustomobject]@{Root=$root;Cases=@($cases|ForEach-Object{$_.Name});RestoresInitialState=$true} | ConvertTo-Json
    exit 0
}
if(-not $AllowLiveChanges){throw 'Use -AllowLiveChanges: this test starts and stops the real bypass. It restores its initial running state.'}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'This live test requires administrator rights.'}
if(-not(Test-Path -LiteralPath $executable)){throw 'Native executable missing'}
$output=Join-Path $root ('dist/native/live-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff'))
[void][IO.Directory]::CreateDirectory($output)
$utf8=New-Object Text.UTF8Encoding($false)
$events=New-Object 'Collections.Generic.List[object]'
$initial=$null
$completed=$false
function Invoke-Native([string]$Action,[string]$InputText='',[bool]$Bat=$false){
    $process=New-Object Diagnostics.Process
    if($Bat){
        $process.StartInfo.FileName=Join-Path $env:SystemRoot 'System32/cmd.exe'
        $process.StartInfo.Arguments='/D /S /C ""'+(Join-Path $root 'zapret-rust.bat')+'" '+$Action+'"'
    }else{
        $process.StartInfo.FileName=$executable
        $jsonMode=if($Action -eq 'menu'){''}else{'--json '}
        $process.StartInfo.Arguments='--root "'+$root+'\." '+$jsonMode+$Action
    }
    $process.StartInfo.WorkingDirectory=$root
    $process.StartInfo.UseShellExecute=$false
    $process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.RedirectStandardInput=$true
    $process.StartInfo.RedirectStandardOutput=$true
    $process.StartInfo.RedirectStandardError=$true
    $process.StartInfo.StandardOutputEncoding=$utf8
    $process.StartInfo.StandardErrorEncoding=$utf8
    [void]$process.Start()
    $outTask=$process.StandardOutput.ReadToEndAsync()
    $errTask=$process.StandardError.ReadToEndAsync()
    if($InputText){$process.StandardInput.Write($InputText)}
    $process.StandardInput.Close()
    $clock=[Diagnostics.Stopwatch]::StartNew()
    try{
        if(-not $process.WaitForExit(90000)){$process.Kill();throw ('Native action timed out: '+$Action)}
        $text=$outTask.Result
        $errorText=$errTask.Result
        $exitCode=$process.ExitCode
    }finally{$process.Dispose()}
    $data=$null
    try{if($text.TrimStart().StartsWith('{') -or $text.TrimStart().StartsWith('[')){$data=$text|ConvertFrom-Json}}catch{}
    [pscustomobject]@{Exit=$exitCode;Text=$text;Error=$errorText;Data=$data;Milliseconds=$clock.ElapsedMilliseconds}
}
function Read-State{
    $result=Invoke-Native 'status'
    if($result.Exit -ne 0 -or $result.Data.known -ne $true -or $result.Data.ownership_known -ne $true){throw ('Unknown bypass state: '+$result.Error)}
    $result.Data
}
function Assert-State($State,[bool]$Running){
    if($State.running -ne $Running){throw 'Requested bypass state was not confirmed'}
    $processes=@($State.processes)
    if($Running){
        if($processes.Count -ne 1 -or $processes[0].pid -le 0 -or $processes[0].created_filetime -le 0){throw 'A single live engine was not confirmed'}
        if($State.service.installed -eq $true -and ($State.service.owned -ne $true -or $State.service.state -ne 4 -or $State.service.pid -ne $processes[0].pid)){throw 'Running service identity mismatch'}
    }else{
        if($processes.Count -ne 0){throw 'Engine processes remain after stop'}
        if($State.service.installed -eq $true -and ($State.service.owned -ne $true -or $State.service.state -ne 1 -or $State.service.pid -ne 0)){throw 'Stopped service state mismatch'}
    }
}
function Assert-NoGame{
    $games=Invoke-Native 'system games'
    if($games.Exit -ne 0 -or ($null -ne $games.Data -and @($games.Data).Count -gt 0)){throw 'Game protection: close the game before live testing.'}
}
try{
    Assert-NoGame
    $initial=Read-State
    foreach($case in $cases){
        Assert-NoGame
        $before=Read-State
        $action=$case.Action
        if($action -eq 'settings-current-alt'){
            $settings=Invoke-Native 'settings'
            $alt=[string]$settings.Data.alt
            if($settings.Exit -ne 0 -or $alt -notmatch '^\d+$'){throw 'Current strategy is unavailable'}
            $action='settings alt '+$alt
        }
        $result=Invoke-Native $action ([string]$case.Input) ([bool]$case.Bat)
        [IO.File]::WriteAllText((Join-Path $output ($case.Name+'.out.txt')),$result.Text,$utf8)
        [IO.File]::WriteAllText((Join-Path $output ($case.Name+'.err.txt')),$result.Error,$utf8)
        if($result.Exit -ne 0){throw ($case.Name+': '+$result.Error)}
        $after=Read-State
        Assert-State $after $case.Running
        if($case.Changed -and $before.running -and $before.processes[0].pid -eq $after.processes[0].pid){throw 'Restart did not replace the engine process'}
        $startup=if($case.Name -eq 'settings-apply'){$result.Data.restart}else{$result.Data}
        foreach($field in @('watcher_error','watch_task_error','confirmation_warning')){
            if($startup.$field){throw ($case.Name+': '+$startup.$field)}
        }
        foreach($component in @('gamepins','telegram')){
            $hook=$startup.post_start.$component
            if($hook.enabled -eq $true -and $hook.ok -ne $true){throw ($component+': '+$hook.error)}
        }
        if($case.Name -eq 'connection-check'){
            if(@($result.Data.targets).Count -ne 3 -or @($result.Data.targets|Where-Object{$_.assessment.reachable_http -ne $true}).Count){throw 'HTTPS target verification failed'}
        }
        if($case.Name -eq 'webcheck'){
            $rows=@($result.Data.rows|Where-Object{$_.mode -in @('BrowserAuto','BrowserTcp')})
            if($rows.Count -ne 4 -or @($rows|Where-Object{$_.state -ne 'OK' -or $_.complete -ne $true -or $_.cleanup_complete -ne $true}).Count){throw 'Browser navigation or cleanup failed'}
        }
        $events.Add([pscustomobject]@{case=$case.Name;passed=$true;elapsed_ms=$result.Milliseconds;running=$after.running;processes=$after.processes;service=$after.service})
        Write-Output ($case.Name+': PASS ('+$result.Milliseconds+' ms)')
    }
    $telegram=Invoke-Native 'telegram status'
    if($telegram.Exit -ne 0 -or $telegram.Data.ownership_error){throw 'Telegram ownership check failed'}
    if($telegram.Data.enabled -eq 'on' -and ($telegram.Data.running -ne $true -or $telegram.Data.requires_restart -ne $false)){throw 'Enabled Telegram component is not ready'}
    $completed=$true
}finally{
    if($null -ne $initial){
        $current=Read-State
        if($current.running -ne $initial.running){
            Assert-NoGame
            $restore=Invoke-Native $(if($initial.running){'start'}else{'stop'})
            if($restore.Exit -ne 0){throw ('Initial state restoration failed: '+$restore.Error)}
        }
        $final=Read-State
        Assert-State $final ([bool]$initial.running)
    }
    $report=[ordered]@{schema=1;completed=$completed;binary_sha256=(Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash;events=@($events.ToArray());initial=$initial;final=$final}
    [IO.File]::WriteAllText((Join-Path $output 'result.json'),($report|ConvertTo-Json -Depth 8),$utf8)
    Write-Output ('Report: '+$output)
}
