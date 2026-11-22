# Compatibility entry point for the native release builder.
param(
    [string]$OutDir=(Join-Path (Split-Path -Parent $PSScriptRoot) 'dist'),
    [switch]$SkipCompile
)
$ErrorActionPreference='Stop'
try {
    if($SkipCompile) {
        $root=Split-Path -Parent $PSScriptRoot
        & (Join-Path $root 'bin/zapret-rust.exe') --root $root package --output ([IO.Path]::GetFullPath($OutDir))
        if($LASTEXITCODE -ne 0){throw ('Native packaging failed with exit '+$LASTEXITCODE)}
    } else {
        & (Join-Path $PSScriptRoot 'native-build.ps1') -Action package -OutDir $OutDir
    }
} catch {
    Write-Error ('Build failed: '+$_.Exception.Message)
    exit 1
}
