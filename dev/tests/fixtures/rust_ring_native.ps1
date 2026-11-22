# Compatibility entry into the native no-driver fixture runner.
function Invoke-RustRingFixture {
    param([Parameter(Mandatory=$true)][string]$Pkg,[string]$Fixture)
    $sourceRoot=Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $runner=Join-Path $sourceRoot 'dist/native/debug/zapret-dev.exe'
    if(-not (Test-Path -LiteralPath $runner -PathType Leaf)){throw 'Build the native developer runner first: cargo zapret check-engine'}
    $report=Join-Path $sourceRoot ('dist/native/legacy-ring-'+[guid]::NewGuid().ToString('N')+'.json')
    $arguments=@('check-engine','--pkg',[IO.Path]::GetFullPath($Pkg),'--output',$report)
    if($Fixture){$arguments+=@('--fixture',$Fixture)}
    & $runner @arguments
    if($LASTEXITCODE -ne 0){throw ('Native Rust ring fixture failed; report: '+$report)}
}
