# Native service/menu/startup regression. Requires explicit live opt-in.
param([switch]$AllowLiveChanges,[switch]$Network,[switch]$ValidateOnly,[string]$OutFile)
$ErrorActionPreference='Stop'
$arguments=@('check-live')
if($AllowLiveChanges){$arguments+='--allow-live-changes'}
if($Network){$arguments+='--network'}
if($ValidateOnly){$arguments+='--validate-only'}
if($OutFile){$arguments+=@('--output',[IO.Path]::GetFullPath($OutFile))}
& (Join-Path (Split-Path -Parent $PSScriptRoot) 'native-run.ps1') -Arguments $arguments
