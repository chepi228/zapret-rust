# Export the actual Rust menu frames. Does not initialize or control the package.
param([string]$OutDir=(Join-Path (Split-Path -Parent $PSScriptRoot) 'dist/ui-preview'),[ValidateRange(24,200)][int]$Width=80)
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'native-run.ps1') -Arguments @('menu-preview','--out-dir',[IO.Path]::GetFullPath($OutDir),'--width',[string]$Width)
