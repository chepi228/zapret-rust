param([string]$Pkg=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
if(Test-Path (Join-Path $Pkg '.git')){throw 'Run on a package copy.'}
$ErrorActionPreference='Stop'
. (Join-Path $Pkg 'tools/lib.ps1')
$module=Join-Path $Pkg 'tools/connectionprobe.ps1';$fails=0
function Check($Name,$Ok){if($Ok){Write-Host ('ok '+$Name)}else{$script:fails++;Write-Host ('FAIL '+$Name)}}
Check 'staged connection diagnostic module exists' (Test-Path $module)
if(-not (Test-Path $module)){exit 1}
. $module
$chosen=@(Select-ConnectionAddresses @('::1','127.0.0.1','127.0.0.2','::2','127.0.0.3','::3','bad','127.0.0.1'))
Check 'address selection deduplicates and limits both families' ($chosen.Count -eq 4 -and ($chosen -join ',') -eq '::1,127.0.0.1,::2,127.0.0.2')
Check 'one address family is retained when the other is absent' (@(Select-ConnectionAddresses @('127.0.0.1','127.0.0.2','127.0.0.3')).Count -eq 2)
function Row($Address,$Attempt,$Stage,$State,$Reason,$Status=0){[pscustomobject]@{Address=$Address;Attempt=$Attempt;Stage=$Stage;State=$State;Reason=$Reason;StatusCode=$Status;HeadersComplete=($State -in @('OK','HTTP_ERROR'))}}
$dns=@([pscustomobject]@{State='OK';Reason='Resolved';Addresses=@('127.0.0.1');Error=''})
$rows=@((Row '127.0.0.1' 1 'Complete' 'OK' 'Completed' 200),(Row '127.0.0.1' 2 'Complete' 'OK' 'Completed' 200))
$ok=Get-ConnectionAssessment $dns @('127.0.0.1') $rows
Check 'two complete attempts confirm observed HTTP reachability' ($ok.Consistency -eq 'Repeated' -and $ok.ReachableHttp -and $ok.Stage -eq 'Complete')
$failure=@((Row '127.0.0.1' 1 'Tls' 'FAIL' 'Certificate'),(Row '127.0.0.1' 2 'Tls' 'FAIL' 'Certificate'))
$tls=Get-ConnectionAssessment $dns @('127.0.0.1') $failure
Check 'repeated certificate failure retains the TLS stage' ($tls.Consistency -eq 'Repeated' -and -not $tls.ReachableHttp -and $tls.Stage -eq 'Tls' -and $tls.Reason -eq 'Certificate')
$mixed=Get-ConnectionAssessment $dns @('127.0.0.1') @($rows[0],$failure[1])
Check 'contradictory retry evidence remains mixed' ($mixed.Consistency -eq 'Mixed' -and $mixed.ReachableHttp -and $mixed.Stage -eq 'Unknown')
$missing=Get-ConnectionAssessment $dns @('127.0.0.1') @($rows[0])
Check 'missing attempts prevent repeated confirmation' ($missing.Consistency -eq 'Incomplete')
$duplicate=Get-ConnectionAssessment $dns @('127.0.0.1') @($rows[0],$rows[0])
Check 'duplicate observations cannot replace a missing attempt' ($duplicate.Consistency -eq 'Incomplete')
$cancel=@($rows[0],(Row '127.0.0.1' 2 'Unknown' 'UNKNOWN' 'Cancelled'))
Check 'cancelled attempt remains incomplete' ((Get-ConnectionAssessment $dns @('127.0.0.1') $cancel).Consistency -eq 'Incomplete')
$denied=@((Row '127.0.0.1' 1 'Complete' 'HTTP_ERROR' 'HttpStatus' 403),(Row '127.0.0.1' 2 'Complete' 'HTTP_ERROR' 'HttpStatus' 405))
$http=Get-ConnectionAssessment $dns @('127.0.0.1') $denied
Check 'HTTP application rejection confirms transport without claiming app success' ($http.ReachableHttp -and $http.Stage -eq 'Complete')
$both=@($rows[0],$rows[1],(Row '::1' 1 'Tcp' 'FAIL' 'NetworkUnreachable'),(Row '::1' 2 'Tcp' 'FAIL' 'NetworkUnreachable'))
Check 'different IPv4 and IPv6 outcomes remain mixed' ((Get-ConnectionAssessment $dns @('127.0.0.1','::1') $both).Consistency -eq 'Mixed')
$dnsFailed=@([pscustomobject]@{State='FAIL';Reason='ResolveFailed';Addresses=@();Error='resolver error'},[pscustomobject]@{State='FAIL';Reason='ResolveFailed';Addresses=@();Error='resolver error'})
$unresolved=Get-ConnectionAssessment $dnsFailed @() @()
Check 'DNS failure cannot become a TCP failure' ($unresolved.Stage -eq 'Dns' -and -not $unresolved.ReachableHttp -and $unresolved.Consistency -eq 'Repeated')
$dnsRecovered=@($dnsFailed[0],$dns[0])
Check 'recovered DNS evidence remains visible as mixed' ((Get-ConnectionAssessment $dnsRecovered @('127.0.0.1') $rows).Consistency -eq 'Mixed')
$corrupt=@((Row '127.0.0.1' 1 'Complete' 'OK' 'Completed'),(Row '127.0.0.1' 2 'Complete' 'OK' 'Completed'))
$invalid=Get-ConnectionAssessment $dns @('127.0.0.1') $corrupt
Check 'an OK label without an HTTP response is not reachability evidence' ($invalid.Consistency -eq 'Incomplete' -and -not $invalid.ReachableHttp)
$noHeaders=@((Row '127.0.0.1' 1 'Complete' 'OK' 'Completed' 200),(Row '127.0.0.1' 2 'Complete' 'OK' 'Completed' 200));$noHeaders[0].HeadersComplete=$false
Check 'incomplete header evidence cannot confirm a repeated successful result' ((Get-ConnectionAssessment $dns @('127.0.0.1') $noHeaders).Consistency -eq 'Incomplete')
$encoded=Get-ConnectionDnsCommand 'localhost' "C:\build’; Write-Output proof; #\runtime\out.json"
$command=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded));$errors=$null
$commandAst=[Management.Automation.Language.Parser]::ParseInput($command,[ref]$null,[ref]$errors)
$injected=@($commandAst.FindAll({$args[0] -is [Management.Automation.Language.CommandAst] -and $args[0].GetCommandName() -eq 'Write-Output'},$true))
Check 'DNS worker treats typographic quotes and command syntax in paths as data' ($errors.Count -eq 0 -and $injected.Count -eq 0)
if($fails){exit 1}
Write-Host 'Connection stage evidence passed.'
