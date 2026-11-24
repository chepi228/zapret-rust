# Все проверки разработчика по очереди - на копии папки, настоящий runtime не трогается.
# Трафик не перехватывается: winws2 запускается с --dry-run или пустым фильтром --intercept=0 (luatest). liststest и hoststest ходят в интернет
# (GitHub, DNS, TLS к GitHub/Telegram/Discord, мост Telegram); -Offline их пропускает.
param([switch]$Offline,[switch]$RustRing,[switch]$NativeWindows,[string]$NativeRelease)
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$stage = Join-Path $env:TEMP ('nba-tests-' + [guid]::NewGuid().ToString('N'))
$stage = [IO.Path]::GetFullPath($stage)
if ([IO.Path]::GetDirectoryName($stage) -ne [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')) { throw 'Unsafe test directory' }
$pkg = Join-Path $stage 'pkg'
# The legacy tests need the launcher and its current controller for filtertest.
# Old native images, the worker and the recovery copy are not legacy engine inputs.
& robocopy.exe $root $pkg /E /XJ /XD .git dist runtime rust-ring-next /XF .git zapret.exe zapret-worker.exe zapret-recovery.exe zapret-rust-worker.exe zapret-rust-recovery.exe /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -lt 0 -or $LASTEXITCODE -ge 8) { throw ('robocopy: ошибка ' + $LASTEXITCODE) }
if ($NativeRelease) {
    $sourceImage = Join-Path $NativeRelease 'zapret.exe'
    if (-not (Test-Path -LiteralPath $sourceImage -PathType Leaf)) {
        throw ('Missing native release image: ' + $sourceImage)
    }
    # Worker/recovery are exercised by check-package; the legacy snapshot has a 64 MiB input budget.
    Copy-Item -LiteralPath $sourceImage -Destination (Join-Path $pkg 'bin/zapret-rust.exe') -Force
    Write-Host ('Native test image zapret-rust.exe: ' + (Get-FileHash -LiteralPath $sourceImage -Algorithm SHA256).Hash)
}
if($RustRing -or $NativeWindows){
    $candidate=if($NativeWindows){Join-Path $root 'dist/native/native-engine-candidate'}else{Join-Path $root 'dist/native/ring-candidate'}
    $files=@('bin/zapret-ring.dll','bin/winws2.exe','CHECKSUMS.txt','tools/rust-ring.json','tools/upstream.txt')
    $ring=Get-Content -LiteralPath (Join-Path $candidate 'tools/rust-ring.json') -Raw|ConvertFrom-Json
    if($ring.schema -eq 1){
        $files+=@('bin/cygwin1.dll')
    }elseif($ring.schema -in @(2,3,4)){
        $obsolete=Join-Path $pkg 'bin/cygwin1.dll'
        if([IO.File]::Exists($obsolete)){[IO.File]::Delete($obsolete)}
    }else{throw 'Unsupported Rust ring candidate schema'}
    $ringScripts=@('ring-store.lua','autoring.lua','host-cache.lua')
    if($ring.schema -ge 3){
        # Legacy Lua compatibility tests load the sources explicitly from this copy.
        foreach($script in $ringScripts){
            Copy-Item -LiteralPath (Join-Path $root ('native/zapret-ring/lua/'+$script)) -Destination (Join-Path $pkg ('lua/'+$script)) -Force
        }
    }else{
        $files+=@($ringScripts | ForEach-Object {'lua/'+$_})
    }
    foreach($name in $files){if(-not(Test-Path -LiteralPath (Join-Path $candidate $name) -PathType Leaf)){throw ('Missing Rust ring candidate: '+$name)}}
    foreach($name in $files){Copy-Item -LiteralPath (Join-Path $candidate $name) -Destination (Join-Path $pkg $name) -Force}
}
$tests = @('astlint', 'check', 'lintstrat', 'profiletest', 'capturetest', 'drystrat', 'retrytest', 'retrybudgettest', 'primarydecisiontest', 'selectiontest', 'measurementtest', 'curlcontroltest', 'curlresulttest', 'curlfailuretest', 'curldeadlinetest', 'curlenginetest', 'comparisontest', 'comparisonruntest', 'resourcetest', 'resourceprocesstest', 'latencytest', 'latencyprobetest', 'rankcontexttest', 'starttest', 'coordinatortest', 'healthtest', 'historytest', 'proxytest', 'netstatetest', 'contexttest', 'watchtest', 'watchluatest', 'linkguardtest', 'storeluatest', 'finalchecktest', 'guardtest', 'dnstest', 'updatetest', 'recoverytest', 'labtest', 'luatest', 'autotunetest', 'boostertest', 'securitytest', 'smoke')
$tests += @('hostcachetest','watchcodetest','restarttest','filtertest','buildtest','settingstest','migrationtest','convertertest','updatearchivetest','tgproxytest')
$tests += @('recipetest','reciperuntest')
$tests += @('integritytest')
$tests += @('menutest')
$tests += @('launchtest')
$tests += @('tgembedtest')
$tests += @('curlbodytest')
$tests += @('familysearchtest')
$tests += @('webprobetest','webbrowsertest','webchecktest','webpublishtest')
$tests += @('connectiontest','connectioniotest','connectionruntest')
$tests += @('voicetest','voiceiotest','voiceruntest','voiceguardtest')
if (-not $Offline) { $tests += @('liststest', 'hoststest', 'tgtest') }
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$failed = @()
foreach ($t in $tests) {
    Write-Host ('===== ' + $t) -ForegroundColor Cyan
    & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot ($t + '.ps1')) -Pkg $pkg
    if ($LASTEXITCODE -ne 0) { $failed += $t }
}
Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
if ($failed.Count) { Write-Host ('НЕ ПРОШЛИ: ' + ($failed -join ', ')) -ForegroundColor Red; exit 1 }
Write-Host 'Все проверки прошли.' -ForegroundColor Green
