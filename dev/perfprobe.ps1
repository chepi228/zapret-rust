# Read-only CPU/RAM sampling is implemented by cargo zapret perf-probe.
param([Parameter(Mandatory=$true)][ValidateRange(1,2147483647)][int]$ProcessId,[ValidateRange(1,30)][int]$DurationSec=10,[ValidateRange(100,5000)][int]$IntervalMs=250,[Parameter(Mandatory=$true)][string]$OutFile)
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'native-run.ps1') -Arguments @('perf-probe','--process-id',[string]$ProcessId,'--duration-sec',[string]$DurationSec,'--interval-ms',[string]$IntervalMs,'--out-file',[IO.Path]::GetFullPath($OutFile))
