"""Check upstream L3 semantics as data; never execute a batch fixture."""
import importlib.util
from pathlib import Path
import sys
sys.dont_write_bytecode = True

root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('converter', root / 'dev/tests/fixtures/flowseal_reference.py')
converter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(converter)
sections = converter.convert(root / 'dev/fixtures/flowseal-1.10.4/alt5.bat.txt')
for section in ('general', 'google', 'discord_media'):
    assert '# match-l3: ipv4' in sections[section], section
assert not any(line.startswith('# match-l3:') for line in sections['game_tcp'])
for value in ('', 'invalid', 'ipv4,ipv6'):
    try:
        converter.parse_opts([('--filter-l3', value)])
    except ValueError:
        pass
    else:
        raise AssertionError('Unsupported family was silently accepted: ' + value)
assert converter.read_ours(root / 'dev/experimental/alt5.txt')['general'][0] == '# match-l3: ipv4'
print('ok upstream ALT5 L3 conditions preserved; invalid conditions rejected')


def voice_actions(lines):
    assert lines[0] == '--out-range=a'
    actions = {}
    for line in lines[1:]:
        if line.startswith('--payload='):
            payloads = line.removeprefix('--payload=').split(',')
        else:
            assert line.startswith('--lua-desync=')
            for payload in payloads:
                actions.setdefault(payload, []).append(line)
    return actions


for parent_id, ids in [
    (11, [31, 50, 51, 52, 54, 55, 56, 57, 58, 59, 60, 61, 70, 71]),
    (12, [21, 23, 32]),
]:
    original = converter.read_ours(root / f'strategies/alt{parent_id}.txt')['discord_udp']
    for sid in ids:
        compact = converter.read_ours(root / f'strategies/alt{sid}.txt')['discord_udp']
        assert voice_actions(compact) == voice_actions(original), sid
        original_rules = sum(line.startswith('--lua-desync=') for line in original)
        assert sum(line.startswith('--lua-desync=') for line in compact) == original_rules - 1, sid
print('ok Discord discovery and STUN retain the ordered actions of each profile')
