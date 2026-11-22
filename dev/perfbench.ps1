# Pure historical A/B replay is implemented in Rust. No process/network control.
param([Parameter(Mandatory=$true)][string]$PlanFile,[Parameter(Mandatory=$true)][string]$JournalFile,[Parameter(Mandatory=$true)][string]$OutFile)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$arguments=@('--root',$root,'--json','comparison-report','--plan-file',[IO.Path]::GetFullPath($PlanFile),'--journal-file',[IO.Path]::GetFullPath($JournalFile),'--output',[IO.Path]::GetFullPath($OutFile))
$result=& (Join-Path $root 'bin/zapret-rust.exe') @arguments
if($LASTEXITCODE -ne 0){throw ('Native replay failed with exit '+$LASTEXITCODE)}
Write-Output (($result|ConvertFrom-Json).Status)
