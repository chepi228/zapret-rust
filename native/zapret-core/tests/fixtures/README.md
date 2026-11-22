# PowerShell 5.1 compatibility data

The default Rust tests read these GZIP-compressed JSON files. The generators
invoke the historical PowerShell functions only when explicitly run.

- `legacy-argv.json.gz` contains exact argument vectors for the 41 bundled profiles
  captured on 2026-11-14, the game/IPSet setting matrix, persistence, an optional
  section, IPv6, a malformed capture list, and rank and coverage from matching and
  mismatching contexts. The fixture also captures legacy score inputs and hashes.
  The inputs preserve the snapshot of the strategy and capture-list text. All
  other files, including engine executables and legacy control files, are text
  placeholders for hashing. The generator normalizes only the package path in
  arguments and the rank timestamp, and uses a fixed synthetic network and run ID.
- `legacy-evidence.json.gz` contains 15 finalists-v1/v2 plans, journals and
  assessments, including mixed context, tampered completion, floating-point
  canonicalization and resource counters.

The generators used the historical control functions from commit
`c4a225e0c6cc022e5cfa4ce49b049d9a6c2aa372` and the then-current 41-profile
native release allowlist and profile bytes. The frozen composition inputs
are included in the archive so edits to strategies and local lists do not
invalidate the historical tests. The native release smoke check separately
validates every current profile through the real engine's dry-run.

To regenerate from the checkout with the intended legacy functions and sample
profiles, run these commands from the repository root in Windows PowerShell 5.1.
Python is used only to compress the captured JSON reproducibly.

```powershell
$stage = Join-Path $env:TEMP ('zapret-fixtures-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
.\native\zapret-core\tests\legacy-fixtures.ps1 -Source $PWD.Path -Out (Join-Path $stage 'legacy-argv.json')
.\native\zapret-core\tests\legacy-evidence.ps1 -Root $PWD.Path -Out (Join-Path $stage 'legacy-evidence.json')
@'
import gzip
import sys
from pathlib import Path

source = Path(sys.argv[1])
fixtures = Path("native/zapret-core/tests/fixtures")
for name in ("legacy-argv.json", "legacy-evidence.json"):
    (fixtures / (name + ".gz")).write_bytes(gzip.compress((source / name).read_bytes(), mtime=0))
'@ | python - $stage
```
