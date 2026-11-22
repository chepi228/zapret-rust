# Capture the historical composer using Windows PowerShell 5.1.
param([Parameter(Mandatory=$true)][string]$Source,[Parameter(Mandatory=$true)][string]$Out)
$ErrorActionPreference = 'Stop'
[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('en-US')
$temp = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')
$pkg = [IO.Path]::GetFullPath((Join-Path $temp ('zapret-argv-' + [guid]::NewGuid().ToString('N') + ' with spaces')))
if ([IO.Path]::GetDirectoryName($pkg) -ne $temp) { throw 'Unsafe fixture directory.' }
$utf8 = New-Object Text.UTF8Encoding($false,$true)
$lf = [char]10
$crlf = [Environment]::NewLine

function Set-FixtureFile($Name,$Text) {
    $path = Join-Path $pkg $Name
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
    [IO.File]::WriteAllText($path,$Text,$utf8)
}
function Get-FixtureText($Name) {
    return $utf8.GetString([IO.File]::ReadAllBytes((Join-Path $Source $Name)))
}
function Get-SortedRecord($Map) {
    $record = [ordered]@{}
    foreach ($key in @($Map.Keys | Sort-Object)) { $record[$key] = $Map[$key] }
    return $record
}
function Capture($Name,$Settings,$Overrides,$Files=[ordered]@{}) {
    $options = [ordered]@{alt=$null;no_auto=$false;ipset_mode=$null;dry_run=$false;debug_file=$null;persistence=$true;network_key=$null}
    foreach ($key in $Overrides.Keys) { $options[$key] = $Overrides[$key] }
    $Script:FixtureNetworkKey = $options.network_key
    $Script:RingPersistAllowed = $options.persistence
    $debug = if ($options.debug_file) { Get-PkgPath $options.debug_file } else { $null }
    $args = New-BypassArgList -Settings $Settings -Alt $options.alt -NoAuto:$options.no_auto -IpsetMode $options.ipset_mode -DryRun:$options.dry_run -DebugFile $debug
    $portableArgs = foreach ($arg in $args) {
        if ($arg.Contains($pkg + '\')) {
            $arg.Replace($pkg + '\','{package}/').Replace('\','/')
        } else { $arg }
    }
    $cases.Add([ordered]@{name=$Name;settings=(Get-SortedRecord $Settings);options=$options;files=$Files;args=@($portableArgs)})
}

try {
    $tools = Join-Path $pkg 'tools'
    [void][IO.Directory]::CreateDirectory($tools)
    Get-ChildItem -LiteralPath (Join-Path $Source 'tools') -File |
        Where-Object { $_.Extension -in @('.ps1','.cs') -or $_.Name -eq 'upstream.txt' } |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $tools }
    . (Join-Path $tools 'lib.ps1')
    function Get-NetworkObservation {
        [pscustomobject]@{Known=$true;Key=$Script:FixtureNetworkKey;ObservedUtc=[datetime]::UtcNow}
    }

    # Only strategy and capture-list bytes affect this pure composer. Stable
    # placeholders exercise the actual legacy file hashing and sort order.
    $files = [ordered]@{}
    foreach ($name in [IO.File]::ReadAllLines((Join-Path $Source 'dev/native-package-files.txt'))) {
        if ($name -match '^strategies/alt[0-9]+\.txt$' -or $name -eq 'lists/ipset-taketwo.txt') {
            $files[$name] = Get-FixtureText $name
        } elseif ($name -match '^(lists|lua|fake|windivert)/') {
            $files[$name] = "fixture $name$lf"
        }
    }
    foreach ($name in @('bin/winws2.exe','bin/cygwin1.dll','tools/targets.txt','tools/dpi-suite.json','lists/autohostlist.txt','lists/list-general.txt.bak')) {
        $files[$name] = "fixture $name$lf"
    }
    foreach ($name in $files.Keys) { Set-FixtureFile $name $files[$name] }
    $scoreFiles = @(Get-ScoreInputFiles)
    foreach ($name in $scoreFiles) {
        if (-not $files.Contains($name)) {
            $files[$name] = "fixture $name$lf"
            Set-FixtureFile $name $files[$name]
        }
    }

    $cases = New-Object 'Collections.Generic.List[object]'
    $network = 'A'*64
    $settings = Get-Settings
    foreach ($strategy in @(Get-Strategies)) {
        Capture ('single-'+$strategy.Id) $settings @{alt=$strategy.Id;no_auto=$true;persistence=$false;dry_run=$true}
    }
    Capture 'default-auto' $settings @{network_key=$network}
    $upper = $settings.Clone(); $upper.game = 'TCP'; $upper.ipset = 'ANY'; $upper.autolist = 'OFF'
    Capture 'uppercase-settings' $upper @{no_auto=$true;persistence=$false}
    $custom = $settings.Clone(); $custom['future-option'] = 'x'; $custom['future'] = 'y'
    Capture 'unknown-settings-composition' $custom @{network_key=$network}
    foreach ($game in @('all','tcp','udp','off')) {
        foreach ($mode in @('loaded','any','none')) {
            $s = $settings.Clone()
            $s.game = $game; $s.gametcp = '123,20000-20100'; $s.gameudp = '456,30000-30100'; $s.autolist = 'off'
            Capture ('ports-'+$game+'-'+$mode) $s @{ipset_mode=$mode;no_auto=$true;persistence=$false;debug_file='runtime/a debug.log'}
        }
    }
    $s = $settings.Clone(); $s.alt = '7'
    Capture 'auto-optional-ipset' $s @{persistence=$false;network_key=$network}

    $capture = 'lists/ipset-taketwo.txt'
    $malformed = [ordered]@{$capture = ("203.0.113.0/24$lf" + "203.0.113.1/24$lf")}
    Set-FixtureFile $capture $malformed[$capture]
    Capture 'malformed-capture-list' $settings @{no_auto=$true;persistence=$false} $malformed
    Set-FixtureFile $capture $files[$capture]

    $ipv6 = 'strategies/alt900.txt'
    $text = $files['strategies/alt12.txt']
    $text = $text.Replace('# name: ALT12','# name: fixture ipv6').Replace('[general]',("[general]" + $crlf + '# match-l3: ipv6')).Replace('[google]',("[google]" + $crlf + '# match-l3: ipv6'))
    $ipv6Files = [ordered]@{$ipv6=$text}
    Set-FixtureFile $ipv6 $text
    $s = $settings.Clone(); $s.alt = '900'
    Capture 'ipv6-auto' $s @{network_key=$network} $ipv6Files
    Capture 'ipv6-single' $s @{persistence=$false;no_auto=$true} $ipv6Files

    $Script:FixtureNetworkKey = $network
    $context = Get-TestResultContext $settings
    $context.RunId = '1'*32
    $base = [pscustomobject]@{Ok=1;Total=8;Groups=[ordered]@{DPI=@{Ok=0;Total=4};YouTube=@{Ok=1;Total=2};Discord=@{Ok=0;Total=2}}}
    $alts = @(
        [pscustomobject]@{Id='12';Name='ALT12';Score=5;Ok=5;Total=8;Harm=0;Freeze=0;Groups=[ordered]@{DPI=@{Ok=3;Total=4};YouTube=@{Ok=2;Total=2};Discord=@{Ok=0;Total=2}}},
        [pscustomobject]@{Id='7';Name='ALT7';Score=3;Ok=4;Total=8;Harm=1;Freeze=1;Groups=[ordered]@{DPI=@{Ok=2;Total=4};YouTube=@{Ok=0;Total=2};Discord=@{Ok=2;Total=2}}},
        [pscustomobject]@{Id='900';Name='fixture ipv6';Score=4;Ok=4;Total=8;Harm=0;Freeze=0;Groups=[ordered]@{DPI=@{Ok=3;Total=4};YouTube=@{Ok=1;Total=2};Discord=@{Ok=0;Total=2}}})
    $table = [ordered]@{'0'=@();'12'=@([pscustomobject]@{Group='DPI';Name='a';State='OK'});'7'=@([pscustomobject]@{Group='DPI';Name='b';State='OK'},[pscustomobject]@{Group='Discord';Name='voice';State='OK'});'900'=@([pscustomobject]@{Group='DPI';Name='c';State='OK'})}
    Save-TestRank $base $alts $context
    Save-TestCover $table $context
    $rank = 'runtime/test-rank.txt'
    $cover = 'runtime/test-cover.txt'
    $rankText = [regex]::Replace([IO.File]::ReadAllText((Join-Path $pkg $rank)),'(?m)^# date: [^\r\n]+','# date: 2026-11-14 00:00')
    $coverText = [IO.File]::ReadAllText((Join-Path $pkg $cover))
    Set-FixtureFile $rank $rankText
    $rankFiles = [ordered]@{$ipv6=$text;$rank=$rankText;$cover=$coverText}
    Capture 'scoped-rank' $settings @{network_key=$network} $rankFiles
    Capture 'rank-other-network' $settings @{network_key=('B'*64)} $rankFiles
    $otherCover = $coverText.Replace(('1'*32),('2'*32))
    Set-FixtureFile $cover $otherCover
    Capture 'coverage-other-run' $settings @{network_key=$network} ([ordered]@{$ipv6=$text;$rank=$rankText;$cover=$otherCover})

    $result = [ordered]@{files=(Get-SortedRecord $files);cases=@($cases.ToArray());rank_context=$context;composition_key=(Get-RingCompositionKey $settings);score_files=$scoreFiles}
    [IO.File]::WriteAllText($Out,($result | ConvertTo-Json -Depth 16 -Compress),$utf8)
} finally {
    if (Test-Path -LiteralPath $pkg -PathType Container) { Remove-Item -LiteralPath $pkg -Recurse -Force }
}
