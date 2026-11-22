param(
    [ValidateSet('build','test','check','fmt','package')][string]$Action='build',
    [string]$Package='',
    [switch]$Install,
    [string]$OutDir
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$tools=Join-Path $root 'dist/rust-tools'
$savedPath=$env:PATH
$savedCargo=$env:CARGO_HOME
$savedRustup=$env:RUSTUP_HOME
try {
    if(-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        $localCargo=Join-Path $tools 'cargo/bin/cargo.exe'
        if(-not (Test-Path -LiteralPath $localCargo)){throw 'Install stable Rust using rustup, then rerun this script.'}
        $env:CARGO_HOME=Join-Path $tools 'cargo'
        $env:RUSTUP_HOME=Join-Path $tools 'rustup'
        $env:PATH=(Join-Path $env:CARGO_HOME 'bin')+';'+$env:PATH
        $llvm=@(Get-ChildItem -LiteralPath $tools -Directory -Filter 'llvm-mingw-*-ucrt-x86_64'|Sort-Object Name -Descending|Select-Object -First 1)
        if($llvm.Count){$env:PATH=(Join-Path $llvm[0].FullName 'bin')+';'+$env:PATH}
    }
    $arguments=@($Action.ToLowerInvariant())
    if($Package){$arguments+=@('--package',$Package)}
    if($Install){$arguments+='--install'}
    if($OutDir){$arguments+=@('--output',[IO.Path]::GetFullPath($OutDir))}
    Push-Location -LiteralPath $root
    try {
        & cargo zapret @arguments
        if($LASTEXITCODE -ne 0){throw ('Native '+$Action+' failed with exit '+$LASTEXITCODE)}
    } finally {
        Pop-Location
    }
} finally {
    $env:PATH=$savedPath
    $env:CARGO_HOME=$savedCargo
    $env:RUSTUP_HOME=$savedRustup
}
