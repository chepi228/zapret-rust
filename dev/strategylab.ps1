# Compatibility entry for the native strategy laboratory.
# Live trials need elevation and temporarily stop the owned bypass. --plan-only is read-only.
param(
    [Parameter(Mandatory=$true)][string]$Dir,
    [string]$Pkg='',
    [string]$ExtraBlobs,
    [int]$MaxMinutes=40,
    [int]$IdleMinutes=10,
    [int]$TimeoutSec=5,
    [int]$Parallel=16,
    [switch]$PlanOnly
)
$ErrorActionPreference='Stop'
if(-not $Pkg){$Pkg=Split-Path -Parent $PSScriptRoot}
$Pkg=[IO.Path]::GetFullPath($Pkg)
$arguments=@('--root',$Pkg,'lab','--dir',[IO.Path]::GetFullPath($Dir),'--max-minutes',[string]$MaxMinutes,'--idle-minutes',[string]$IdleMinutes,'--timeout-sec',[string]$TimeoutSec,'--parallel',[string]$Parallel)
if($ExtraBlobs){$arguments+=@('--extra-blobs',[IO.Path]::GetFullPath($ExtraBlobs))}
if($PlanOnly){$arguments+='--plan-only'}
& (Join-Path $Pkg 'bin/zapret-rust.exe') @arguments
if($LASTEXITCODE -ne 0){throw ('Native laboratory failed with exit '+$LASTEXITCODE)}
