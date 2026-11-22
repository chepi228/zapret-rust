# Actual sandboxed engine checks are orchestrated in Rust; no driver/admin needed.
param([string]$Pkg,[string]$Output)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$arguments=@('zapret','check-engine')
if($Pkg){$arguments+=@('--pkg',[IO.Path]::GetFullPath($Pkg))}
if($Output){$arguments+=@('--output',[IO.Path]::GetFullPath($Output))}
Push-Location $root
try{& cargo @arguments;if($LASTEXITCODE -ne 0){throw ('Native engine checks failed with exit '+$LASTEXITCODE)}}finally{Pop-Location}
