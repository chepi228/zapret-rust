# Native zapret-rust control application

Windows x64 application in Rust. `bin/zapret-rust.exe` owns the menu, typed CLI, settings,
composition, strategy tests, diagnostics, Windows control, updates and packaging.
`zapret-rust.bat` starts it directly. The same binary is shipped as
`bin/zapret-rust-recovery.exe` so an interrupted self-update can recover when the main
executable has temporarily been renamed.

`bin/zapret-rust-worker.exe` is a Rust Windows GUI executable that hosts the notification
and Telegram scheduled helpers without `conhost.exe`. It validates its package and
the console controller, creates the controller suspended in an owned job, forwards
its arguments and exit code, and closes that job if the host exits. SYSTEM watch
and autotune tasks invoke the controller directly because they can restore a
detached engine that must outlive the task. Existing native conhost registrations
remain recognizable and use the new host when reconfigured or relocated.

The engine derivative starts from pinned packet-engine, WinDivert and LuaJIT
sources and uses Win32/UCRT without loading Cygwin. Rust owns packet parsing,
checksums, protocol recognition, connection tracking, packet queues, profile
selection, lists, filters and WinDivert resource management. It also parses the
Windows option table and numeric settings, builds and imports profiles, observes
WLAN/NLM filters and implements the numeric Lua packet API. Blob loading obtains
size and contents from one open file and adds a collection entry after the read
has succeeded. Profile transitions stage allocations before changing either
profile list. Lua invocation parsing retains escaped colons and inserts a rule
after every argument has passed validation. NLM diagnostics enumerate networks
once, preserve the connected-first output order and accept longer Unicode names.
Windows adapter-to-Lua projection now uses borrowed Rust views. Rust selects
active interfaces and their fields, retains the existing IPv4/IPv6 masks and
broadcast bytes, and preserves duplicate address writes. C performs the Windows
query into Lua-owned userdata and writes VM fields between Rust steps. Native
enum promotion retains unsigned 32-bit connection/tunnel values, including high
bits. Source-address route lookup owns its UDP socket in Rust, closes it on every
path and publishes the address only after close. Lua allocation/errors occur
after that ownership scope ends.
Lua AES and AES-CTR use the RustCrypto AES implementation for 128-, 192- and
256-bit keys. CTR processes eight blocks at a time, including counter rollover
and the final partial block.
Lua SHA-224, SHA-256 and HKDF use the pinned RustCrypto `sha2` and `hkdf`
libraries. Invalid HKDF output lengths are rejected before allocating Lua
userdata; the existing nil/error results are retained.
Lua AES-GCM uses RustCrypto AES-GCM, counter mode and GHASH. Runtime nonce
lengths, all three AES key sizes and the legacy computed-tag decryption result
are retained. Native builds no longer compile the engine's legacy C crypto
implementations; those files remain independent conformance references.
IP address rendering, host/port extraction and Lua `ntop`/`pton` conversion
also run in Rust, using aligned stack buffers for Winsock and bounded output.
Windows service dispatch, status transitions and stop callbacks run in Rust.
Status publication is serialized, recursive service dispatch is suppressed and
the engine's shutdown/reload flags use C atomics across callback threads.
Console events and CRT signals use a shared Rust dispatcher. Lua shutdown
detaches its VM before cleanup and waits for any interrupt installation to
finish. Stop requests received before publication are applied after the VM is
ready; late requests cannot access a closed VM. SCM stop requests also interrupt
Lua execution through this guard.
Native system identity queries validate UTF-16 names and publish a complete
result. Windows event logging uses Unicode APIs, releases a previous source
when reopened, and holds its handle while a write is pending. Closing the log
waits for that write; debugger output remains available if registration fails.
The engine's fragmented log buffer is also owned by Rust. Accumulation and
writer calls are serialized; a bounded nested path prevents a writer callback
from waiting on its own lock. Hex diagnostics check capacity arithmetic and
allocation before reading payload data.
String, string-pair and Lua-function collections use Rust with the existing
intrusive list ABI and UCRT allocation. Copies stage a complete chain before
publishing it, self-copy reads only the original chain, and string searches skip
nullable placeholders.
Packet-filter collections use the same ownership code, stage copies before
publication and match filters within Rust. Global defaults validate their C
field layout before writing. Capture-filter buffer replacement keeps all prior
buffers on allocation failure. Startup initializes defaults before constructing
the version string, preserving `NFQWS2_VER` in Lua.
CIDR parsing borrows its input, rejects wrapped prefix lengths and publishes
address/prefix together after success. IPv6 masks are aligned immutable data.
Comma-separated configuration lists retain the original argument. Pool
normalization uses a private mutable token; string-list insertion stages the
whole chain before publication. Host/IP include/exclude policy and reload order
run over the Rust collections, including callbacks that replace a pool.
Stream retry loops and binary/text file helpers run in Rust. Native file handles
close on every path, invalid sizes are rejected before truncation, and binary
reads initialize raw C storage directly. Text append retains UCRT CRLF bytes;
EINTR retries and anomalous empty stream results have finite handling.
Native config argument expansion publishes a UCRT-owned argv after a single
expansion. Config reads retain the previous argv on failure and explicitly
reject files above the existing 16,381-byte budget instead of truncating them.
TCP option lookup, SYN classification, endpoint extraction and IP/TCP reversal
run directly in Rust. TCP NOP runs use bounded word reads; wire and sockaddr
updates retain the existing untouched bytes and support unaligned fields.
Final IPv4, TCP, UDP and ICMP checksum field updates also run in Rust, retaining
the existing family selection and byte-level behavior for partial lengths.
Packet diagnostic strings use a shared bounded Rust writer without allocation.
Protocol/ICMP names, flag order, hexadecimal fields and the C print-buffer
truncation limits remain compatible with the pinned engine.
File metadata, modification stamps, access probes, EXEDIR and path resolution
also run in Rust. Access probes reject creation, truncation and delete-on-close
flags. Checksum carry folding uses fixed-width end-around carries; bounded tail
loads avoid CRT memcpy calls for the last zero to seven bytes.
Native token privilege transitions and low integrity setup run in Rust with
bounded, validated token snapshots and owned handles. ANSI and UTF-16 privilege
names are supported; partial adjustment and logical lookup failures cannot be
reported as full success, and cleanup preserves the original error.
Template imports
preserve the previous profile on allocation failure. Windows observations release
COM objects, WLAN buffers and handles when an operation fails. The Windows
LuaJIT bindings use the Win64 unwind ABI during protected VM operations.
Rust also coordinates Lua packet assembly, validates returned header sizes and
copies payloads within the remaining output span. A resource-free state passes
between VM calls. Fragment,
lazy table lookup and checksum behavior remain compatible with the pinned API.
Reconstruction/raw-send options also use Rust field policy. Only requested
output pointers cause lookups; aliased flags retain publication order, negative
repeat counts are published before the C error and fwmark reads the current
default after its VM query. Single/multiple/range marker calls calculate their
complete result in fixed Rust storage before C enters Lua. Required string/type
checks, error precedence, the 128-marker limit, strict missing endpoints and
zero/one-based positions retain the existing API.
The five outer packet Lua APIs now also use Rust stage selection. Argument
validation, raw-string/table routing, reconstruction, parse/purge/feed order,
destination extraction, send results and return counts are selected between C
operations. Disabled conntrack returns two nils before reading packet/options;
active tracking reads the current pool at each actual operation and publishes
the direction observed by feed. All constructors, reference releases and driver
calls execute on the C stack after Rust returns. Rawsend and dissect retain
small stack frames; the large buffer is confined to reconstruction entries.
Eight file/system/time Lua APIs now also use Rust projection and extraction:
stat, uname, both clocks, local/UTC calendar views and inverse conversions.
Borrowed native snapshots retain 64-bit file identities, fractional timestamps,
zero-based months, full calendar years, exact result counts and field order.
Inverse conversion keeps strict number fields, lazy/metamethod lookup order,
native 32-bit narrowing, year adjustment and the CRT's normalization and -1
failure sentinel. Zone lookup and bounded date formatting run at their original
publication points. C retains native observations, errno/strerror and all VM
operations; no Rust frame or owned resource spans a Lua call or error.
Lua file probing and compressed-file preparation now use Rust native owners.
Fallback allocation, optional magic reads, full-name probing, bounded resolved
paths and file-close order retain the pinned behavior. A resource-free loader
policy selects compile, release and execution; C frees decompressed UCRT bytes
after protected compilation and before executing the chunk. Basic VM startup,
JIT-status traversal/log selection, cleanup/shutdown sequencing and periodic GC
also use Rust. GC rereads the interval and previous timestamp after the native
clock query, preserves unsigned wraparound and publishes its captured timestamp
after collection/logging, including nested calls. Actual VM operations stay in C.
Complete AES/block/CTR/GCM entry policy now also runs in Rust. It preserves
argument/error precedence, Lua truthiness, strict keys/IVs versus the CTR payload's
string coercion, nullable associated data, temporary userdata and result counts.
Rust selects the existing crypto backends only after all preceding VM checks
return. Codec option defaults/narrowing and native initialization/close/GC are
also Rust, retaining allocator identity, metatable operations, role checks and
valid/role publication order. Only z_stream is initialized before the native
codec succeeds; closed streams skip role/state reads during GC. All VM calls,
errors and any reentrant Lua calls remain outside Rust frames.
The eight random/hex/binary-buffer entries also use one resource-free Rust
policy. It selects strict string or coercing integer reads, rejects odd hex
before allocation, preserves embedded-NUL hex termination and seeded generator
consumption, checks equal operand lengths and selects publication/removal order.
Entropy failure keeps its fatal Lua error; failed hex decoding pops userdata
before publishing nil. Production dispatch reuses the migrated helpers and
Windows entropy source. C alone owns VM operations and their longjmp boundary.
All ten outer header dissect/reconstruct APIs now also use Rust for arity,
strict inputs, IPv6 option sequencing, native capacities, errors and result
publication. Header-field names and the composite packet table are Rust
projections. Each native source field is read at its original VM boundary;
fragment checks remain deferred and header spans stay captured across key
publication. Native sockaddr projection selects IPv4/IPv6 byte ranges in Rust
while unknown families require only their family bytes. C performs actual VM
calls and the existing field extraction without an active Rust frame.
Packet header/item table metadata and publication order also use Rust. The
31 scalar field names, address/option keys, table capacities, one-based item
indices and optional fields are selected without a live Rust frame during VM
calls. Scalars remain captured before table creation; raw wire bytes stay
borrowed and iterator kind/progress remain live between operations. Position
and range tables also use deferred Rust projections. Blob lookup keeps exact
relative indices, local non-nil precedence (including false), global fallback,
number-to-string conversion, diagnostics and failure cleanup in Rust policy;
C alone performs the corresponding Lua and logging operations.
The 31 scalar/address fields of the five reconstructed headers now use a Rust
schema beside their serializers. Rust selects lookup order, validates required
types and address widths, narrows integers and tracks IPv6 payload-length
presence. C performs each Lua lookup/coercion and any checked error after Rust
returns. Rust also selects array indices and field queries for TCP options and
IPv6 extensions, accounts for capacity, links extensions after a successful
write and finalizes the captured header fields. TCP END/NOP skip their data
lookup; END retains the pinned API's continuing array traversal. C dispatches
the selected Lua operation and unwinds its own stack on failure.
Complete old/new builders are compared in LuaJIT, including nested lookups,
partial writes, guarded spans and protected allocation failures. Fresh LuaJIT
VMs can reach different collection checkpoints at the same allocation budget,
including reference-vs-reference runs before the list policy is reached. The
list checker validates each OOM trace prefix and complete partial-buffer image
against a catalog of C checkpoints; ordinary comparisons remain exact.
Rust decodes TCP, UDP, ICMP and IP fields for Lua using borrowed wire views.
TCP END padding and IPv6 extension/fragment iteration retain the pinned API's
behavior on truncated and malformed inputs. C creates VM tables after each Rust
call returns. Rust also reads gzip/zlib files into UCRT-owned output buffers,
uses geometric growth and rejects inconsistent codec counts or stalled progress.
File loader errors return through Lua's normal status protocol and close the VM.
Rust computes the Lua connection views, including signed counter conversions,
wrapping TCP positions, timestamp arithmetic and direct/reverse direction.
Saved packet positions are kept separate from the live connection protocol;
the Lua tables retain shared direction objects and the original registry state.
The native builder compares both implementations through actual LuaJIT, guarded
input pages and failing VM allocations before replacing the C calculations.
Connection table metadata and publication order now also use resource-free Rust
steps. Counter/TCP fields, optional flow/hostname fields, table capacities,
registry references, timestamps and direction aliases are selected in Rust;
C performs the VM operations. The named track key precedes the native query.
Views are read at their original publication boundaries, hostname bytes remain
borrowed, and direct/reverse reuse the actual client/server table objects.
Complete old/new publishers are compared for exact VM order, mutable native and
view inputs, nested calls, guarded storage and failing VM allocations.
Argument substitution and execution plans also use borrowed Rust metadata;
C performs lazy Lua lookups and creates the VM objects after Rust returns.
Rust also prepares the execution context and rule identity, selects cutoff
directions, applies one-way connection cutoffs and cancels execution plans.
Raw-packet calls return a borrowed Rust span before C enters the VM. Contexts
are active only around the protected Lua callback; errors and allocation failures
return before they are invalidated. Userdata size is checked before reading its
context fields. Instance cutoff tables retain lazy lookups, per-profile scope,
diagnostics and the original nil-context argument order.
Rust prepares the Lua checksum inputs and output workspace, selects the address
family and copies/updates the packet bytes with the shared Rust checksum code.
IP, transport and payload validation retain their original error order. Header
tails and odd-sized transport strings stay intact; payloads above 65,535 bytes
and overflowing workspace lengths are rejected before allocating VM userdata.
The four Lua APIs are compared with the pinned C predicates/checksum code and
actual LuaJIT, including guarded inputs and allocation failure cleanup.
Rust selects Lua startup phases, traverses initialization scripts and profile
functions, bounds debug previews and supplies the sandbox removal paths.
Script/file execution and all VM lookups remain in C after each Rust call.
List links are read after callbacks return, and quit is checked only before an
existing next script. Blob storage is released only after its Lua global is
published; a changed list head is rejected before releasing another blob.
The builder compares startup behavior with the pinned C through actual LuaJIT,
including callback mutations, VM allocation failures and exact cleanup order.
Real no-driver engine fixtures also check binary blobs, Unicode script files,
multi-profile strategy lookup and failure short-circuiting. Sandbox adapters
report a Lua error if a standard library table has an invalid type.
The native Windows registration catalog also lives in Rust: 119 numeric entries,
five Boolean settings, the version string, 101 API names/slots and metatable
fields/order. C callback addresses are bound from the pinned source at build
time; a changed callback count is rejected. Runtime values are captured at their
original group boundaries, preserving publication callbacks, the repeated
`TH_FIN` write and the `bitnot`/`bitnot48` alias. Actual LuaJIT comparisons verify
the C header values, callback identities, partial errors, repeated registration,
existing metatables and VM allocation failure cleanup. The full public catalog
fixture can also run independently with
`cargo zapret check-engine --fixture registrytest.lua`.
Rust also selects the per-packet Lua invocation fields, including profile labels,
interfaces, nested target addresses, replay counters and nullable binary spans.
Unsigned replay addition and signed offset conversion retain the pinned C
behavior. Mutable profile and position fields are read after preceding VM work;
the fallback `DEFAULT_MSS` lookup remains lazy. C creates the tables and publishes
each selected field after Rust returns. The native builder compares both the
exact C block and its replacement input construction through real LuaJIT,
including reentry, GC mutations, protected errors and guarded binary buffers.
Its paired benchmark measures isolated marshalling rather than live traffic.
Per-handler invocation control now also uses a resource-free Rust phase machine.
It preserves voluntary cutoff before range/payload checks, callback lookup and
argument errors, aggregation before cancellation and the original pass-through
fallback on failure. C keeps context activation immediately around `lua_pcall`,
all VM predicates/coercions, error reporting and table cleanup. Rust classifies
the result count/type and accepted verdict bits after the C query returns,
including LuaJIT's existing numeric-string and fractional-number coercions.
The builder compares the complete previous/replacement desync body in LuaJIT,
including callbacks, nested dispatch, protected errors and modified-packet policy.
The Lua TLS entry also uses a Rust workspace plan, preserving pass-through calls
without userdata allocation. Modifying calls validate the existing 260-byte
growth budget before C allocates Lua-owned storage, then copy and transform the
rooted source within Rust. Complete LuaJIT comparisons retain diagnostics, PRNG
state, input bytes and cleanup under VM allocation failure. No socket or other
Rust-owned resource remains live when these adapters publish Lua values.
Main's option-category routing and final startup order now also use Rust. The
existing numeric/startup/list/profile/capture/control adapters remain separate,
with numeric exclusions for the two negative network-filter flags. A return of
two only requests a successful process exit from capture/control adapters; other
categories treat it as an ordinary handled option. Mutable profile/list pointers
are read by the C adapter at each stage. Rust selects final profile completion,
argument release, validation, capture preparation, lifecycle, engine run and
cleanup phases before C performs them. Early exports and dry runs preserve their
exit paths; normal cleanup keeps params, argument mutex and stdio in that order.
The builder compares both original C blocks with mutating/reentrant/failing
adapters, and real no-driver CLI fixtures check mixed-category error ordering and
startup exits on both the previous and new engines.
The remaining C integration includes table/API adapters and protected VM calls. LuaJIT and WinDivert
remain pinned external components. The Cygwin engine remains a separate build path.
Telegram uses a Rust core derived from Flowseal TG WS Proxy
v1.11.4, integrated into `zapret-rust.exe`; it needs no Python or separate tray executable.
Rust manages exact process identities and lifetimes. The native ZIP excludes
PowerShell and C# production code. Legacy `tools/*.ps1` and `tools/*.cs` remain in
the source checkout as compatibility references and for existing developer checks.
The explicit Telegram menu start and human CLI start open the confirmed active
local proxy link with the native Windows shell. Telegram keeps its own connection
confirmation. Background starts and JSON commands remain silent; if no protocol
handler is available, the running bridge and printed manual link remain available.

Network probes, downloads and HTTP/2 share bounded address fallback: IPv4 and IPv6
are interleaved, at most two TCP attempts run at once, and a stalled address lets
the next attempt start after 250 ms. The Telegram transport applies the same
fallback policy with its existing overall connection deadline. Losing attempts
close when the request succeeds or is cancelled. These TCP clients disable Nagle
buffering before the TLS handshake or HTTP exchange.

Owned process completion wakes on the process handle while retaining a 5 ms
pipe and timeout polling bound. Menu cancellation is cleared after an action and
its cleanup have returned. The engine's loop without interception caps sleep
requests at 50 ms to check shutdown and runs timers only when their deadline is reached.
The four Lua timer APIs now use resource-free Rust policies for validation order,
callback resolution, optional values, registry ownership, replacement/deletion,
info fields, enumeration indices, dirty flags and logging. C performs every VM
operation and native query after Rust returns. Info queries preserve the original
pool observation before a coercing name check; enumeration reads its next ID
after the preceding VM write. The Rust scheduler and C callback dispatch bridge
keep their existing behavior. Complete real-LuaJIT comparisons cover nested
calls, mutable query views, pool changes, native failures and VM allocation errors.

All 32 numeric Lua entry policies now also run in Rust. Rust selects arity
diagnostics, public names, operand batches, strict binary inputs, optional offset
defaults, backend calls, errors, binary widths and result publication. C retains
LuaJIT coercion and every VM operation. Numeric batches read all operands before
range validation; binary reads observe the stack count and offset type after
obtaining the strict string, then consume its borrowed bytes. Existing Rust
arithmetic and its upstream-C comparison remain unchanged. A second complete
real-LuaJIT comparison checks the previous entry adapter against the new policy,
including all nine applicable nested VM boundaries, binary writer reentry,
mutable borrowed sources, allocation failures and protected-page boundaries.

The complete `hash`, `hkdf`, `ntop` and `pton` entry policies also run in Rust.
Algorithm names preserve C-string termination; hash data and address inputs
remain strict strings. HKDF retains salt/key/info nil handling and LuaJIT string
coercion before output-length validation. Its input bytes remain borrowed through
the Lua-owned userdata allocation. Rust preserves backend capacities, including
the Windows 65-byte IPv6 text buffer, publication order, nil/error results and
userdata removal. C performs every VM operation between policy steps. Existing
Rust cryptography/address conversion and upstream-C conformance checks remain;
complete-entry comparisons additionally exercise all VM boundaries, nested
allocation failures, mutable inputs and eager-copy negative controls.

The v0 Windows engine runs its startup, capture, Lua entry, list and resource
policies in Rust. The final migration includes 15 scalar/system Lua entries,
shared Lua argument and context rules, timer and connection lifecycles, and
file/environment compatibility. Rust also controls the ring v1 registration,
call policy and pinned DLL loader, the 77-option CLI catalog, and diagnostic
traversal and output selection. Packet, profile, automatic hostlist and capture
diagnostics use Rust for record order, native arguments and deferred field
observations. The original C entries remain developer comparison inputs.

Rust calls the pinned Lua runtime, Win32 and UCRT through the Win64 ABI. In the
standard Luna engine, Rust owns the gzip script buffer through protected errors.
The LuaJIT compatibility engine uses LuaJIT's protected C frame from Rust to
release the buffer and propagate the original error. The historical Cygwin
engine links the same Rust ring registration, loader and TLS readers with
upstream C. Its driver-free startup policy runs in Rust.
The Rust logging and Luna diagnostic entry points use the compiler's C variadic
ABI. The Rust ring loader verifies its pinned DLL with CNG before loading it and
holds its file handle and module until process exit.
Reloads on list changes still use the Rust list registry. The unused Unix
signal paths and legacy KAVL implementation are excluded from the native
Windows build.

The conformance build captures its reference C sources in
`dist/native/native-engine-build/native-c-snapshot` after linking. The snapshot
lists the compiled comparison units and includes their ABI declarations.
The final inputs are listed in `dist/native/native-engine-build/engine-link.map`.
See [the Windows build variants](zapret-ring-ffi/README.md#native-windows-engine).

The Windows integration uses Telegram's `dd` MTProxy link and a loopback listener.
It carries the Flowseal DC routes, WebSocket pool, CF WebSocket/Worker, CF HTTP/2
media multiplexing and TCP fallback. The packaged core uses the bundled CF domain
list or the user domains in `runtime/tgws/TgWsProxy/config.json`. This integration
does not implement the upstream standalone server's FakeTLS (`ee`) or PROXY
protocol listener modes.

## Workspace

| Crate | Responsibility |
| --- | --- |
| `zapret-core` | Legacy INI and strategy formats, all profiles, IPv4/IPv6 composition, scoped rank/coverage, integrity, atomic files and lists |
| `zapret-platform` | Win32 processes/jobs, SCM, Task Scheduler, exact ownership, registry, hosts, notifications, ETW, Wi-Fi events and shared monotonic clocks |
| `zapret-net` | Bounded HTTP/1.1/HTTP/2, native Schannel, DNS, STUN, ICMP/TCP latency, provider and optional owned browser/HTTP/3 diagnostics |
| `zapret` | Russian menu, CLI, frozen strategy tests, retry/family search, shadow ABBA comparison, reports, recovery and native ZIP |
| `zapret-worker` | Native hidden host for interactive-user background tasks, owned process lifetime and bounded diagnostics |
| `telegram-core` | Integrated local Telegram proxy, derived from TG WS Proxy v1.11.4 |
| `zapret-ring` / `zapret-ring-ffi` | Bounded strategy memory, decisions and the versioned engine ABI |
| `zapret-wincompat` | Rust configuration expansion, cryptographic RNG bridge and native engine primitives |

Cargo package names and internal crate directories retain their build identifiers.
Installation maps
the compiled controller and host to `zapret-rust.exe` and `zapret-rust-worker.exe`; CLI help,
the launcher, recovery entry and the `zapret-rust/` ZIP root use the product name.
Existing SCM/task IDs, control mutex, priority-restoration registry value, hosts
markers and ETW ownership prefix remain compatible with previous installations.
Upstream filenames, licenses and repository URLs retain their upstream identities.

## Build and verify

Network-setting observations use the local Windows
[prefix-policy](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/nettcpipprov/msft-netprefixpolicy)
and [TCP-setting](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/nettcpipprov/msft-nettcpsetting)
providers. Reads use a bounded observation thread; at most one can remain pending
per controller. Updates use an owned Rust process. The preceding 10-second
read/TCP deadline and 25-second IPv4 update/query deadline remain bounded even
if WMI stops responding. Updates
revalidate their exact parent, package control lease and game guard, restrict WMI
to the requested properties, and check observed results. Already-enabled TCP
timestamps avoid a write. Providers that cannot expose or update the persistent
store use the explicit netsh compatibility path, with its backend and native
error retained in the result. A missing IPv6 policy stays unknown.
The worker reads the control lease while the parent keeps it open for writing;
the parent's handle continues to block competing writers and deletion.

Use the x86_64-pc-windows-gnu Rust toolchain for the native Windows engine.
Prepare the pinned toolchain and sources described in [the engine build notes](zapret-ring-ffi/README.md). Run these commands from the repository root.
Cargo uses the LLVM linker bundled with Rust on the GNU target. The GNU target
also needs a MinGW C compiler on PATH to build ring. The existing PowerShell
entry points forward to Cargo and can locate the portable toolchain under
`dist/rust-tools`. Builds and tests use the locked dependency graph.

```powershell
cargo zapret test
cargo zapret check
cargo zapret fmt --check
cargo zapret build --install
cargo zapret check-install
cargo zapret build-ring --native-windows
cargo zapret package --skip-compile --candidate dist/native/native-engine-candidate
cargo zapret check-package dist\zapret-rust-native-v1.0.zip --output dist\native\smoke.json
cargo zapret check-menu dist\zapret-rust-native-v1.0.zip --output dist\native\menu.json
cargo zapret check-probe bin\zapret-rust.exe --subcommand probe --output dist\native\probe.json
```

Builds stay in `dist/native`. Install stages and replaces the controller, recovery
entry and background host in `bin`. Images still mapped by a process are retained
in `dist/native/previous-controllers`. Reopen the menu to load the new controller.
Known installer sidecars from older builds are excluded from launch/test inputs;
other invalid paths still fail validation. Developer checks use TEMP packages and
loopback fixtures. The existing
offline compatibility suite is `dev/tests/run-all.ps1 -Offline` under Windows
PowerShell 5.1. Add `-NativeWindows` to overlay the checked native engine candidate
onto its private package copy. Add `-NativeRelease dist/native/release` to test the
fresh controller; the runner records its SHA-256 and copies it only into its TEMP
package. Worker and recovery images are exercised by `check-package`. Privileged service/driver/hosts/ETW actions need separate live
validation and are not performed by the smoke check.

For an explicitly authorized live check, use an administrator console:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File dev/tests/native-live.ps1 -AllowLiveChanges -Network
```

This starts, stops and restarts the real bypass, exercises the actual BAT menu,
reapplies the selected strategy, verifies enabled startup components and restores
the initial running state. It refuses to proceed while a game is detected.
`-Network` additionally checks HTTPS and isolated browser navigation, including
process/profile cleanup; HTTP/3 absence is reported separately. Without
`-AllowLiveChanges` no live check runs. Reports stay under `dist/native/live-*`.

## Entry points and evidence

`bin\zapret-rust.exe --help` lists the typed commands. `--root PATH` selects a package;
`--json` retains structured evidence; ordinary interactive output is Russian.
`test --plan-only` reads the intended workload without running a strategy test.
`test --last` reads the previous selection without starting probes or changing
settings. The menu exposes it as `3` then `5`. Normal selection output shows
progress and a table of named strategies; `--json` retains the measured record.
The main menu keeps Telegram at `4` and manual strategy selection at `5`.
The answer count is separate from the score, which also accounts for retries
and regressions; the saved text report contains the complete table.
Progress restores per-service scores, TCP/TLS milliseconds, retries, freezes,
ordinary-site regressions and elapsed time. A full per-target text/JSON pair is
saved under `runtime/test-native-<run>.txt`/`.json`, with last-result aliases.
Rejected final validation preserves the completed measurements and prior settings.
Final selection checks up to three candidates even when the measured leader is
the current primary. Stable working DPI coverage, user services and ordinary-site
latency remain required; retry-only synthetic DPI responses stay in the report
and score without vetoing the final result. Successful explicit application starts
the accepted configuration even when the bypass was stopped before selection.
Quick tests defer clearly inferior strategies using a local context-scoped cache;
near winners, the primary, unmeasured/changed files and service specialists stay.
Deferred strategies return after five further runs or seven days; a changed
network/input signature resets learning. Full and manual selection retain all
profiles. Report-only tests do not update this learning cache.
`provider-check` performs the full report-only strategy workflow and writes a
provider-named shareable report; `provider-info` only reads ISP/IP information.
`provider-check --args '{"plan_only":true}' inspects the full workflow without
ISP lookups, strategy launches or file publication.
`probe` reads bounded version-1 JSONL jobs through EOF and streams observations.

The native menu preserves the original rounded frames, pink/lilac accents and
numbered sections. The main screen switches to a compact layout in a short console;
long rows wrap to its current width. RGB colors use Windows virtual-terminal mode,
with console palette fallback. Redirected output contains plain framed text.
Back and cancelled input return without a second prompt or starting an action;
completed actions and errors remain visible until Enter. Ordinary results describe
the requested operation in Russian; `--json` and private workers retain structured
output. Saved selection results are labelled as historical observations.
`menu-preview --screen main --width 55 --height 16` renders fixture data only,
without initializing settings, requesting elevation or starting maintenance.

The autostart setting changes the service's future startup mode while preserving
the current engine identity and running state. It does not start or stop the
bypass. Scheduled-task settings verify registration/removal before saving their
preference and restore the prior task if that transaction fails. Unconfirmed
ownership or state prevents the change and is not displayed as disabled.

Service inspection handles legacy strategy commands larger than the 8 KiB SCM
query reply limit. Only buffer/RPC size failures with a confirmed oversized
ImagePath use a read-only registry fallback. The configuration is reread for
consistency; exact process ownership and service-state checks still gate control.
Explicit package roots resolve ordinary Win32 dot components before deriving
engine paths, so the BAT's `--root "%~dp0."` uses the same path as its service.
Driver cleanup accepts an already pending deletion (1072) or an already missing
service (1060), releases its handle, and reports pending deletion separately.
Access/handle failures and foreign-driver ownership checks remain enforced.

Strategy runs hold a pinned TEMP package. They reread settings, targets and
strategies from that snapshot after acquiring control. Worker output must contain
one complete typed result for each requested identity. Cancellation, incomplete
output, changed network/source/native executable and a dead engine reject the
run. Failed or drifting control sites exclude the corresponding strategy from
selection, history, rankings and coverage; other confirmed trials remain usable.
The report retains all observations and explains exclusions. The chosen final
combination must still pass replay, including ordinary sites, before publication.
Accepted ranks and coverage retain the legacy scoped text formats and matching
RunId. All 36 profiles are available in manual selection and the full test;
the quick test retains its smaller candidate pool.

`test --compare-a 12 --compare-b 13` collects endpoint calibration plus balanced
ABBA/BAAB blocks. `finalists-native-v1` uses shared QPC target clocks, per-target
linear drift adjustment, calibration noise and first-attempt quality gates.
The report remains advisory and never updates rankings or settings. Resource
windows measure the exact engine process from warmup end to measured end; CPU
and memory differences are descriptive. Detailed native journals contain URLs
and local metadata and should be reviewed before sharing.

Network reports publish immutable text/JSON pairs and a last-result alias. JSON
references the exact text and SHA256. A failed alias replacement restores the
preceding pair. HTTP/3 uses asynchronous WinHTTP where Windows supports it and
Quinn with rustls otherwise. Both validate certificates through the system and
require an observed h3 response within one deadline. An explicit CA file selects
Quinn and adds trust for that process. Browser results concern the main document;
STUN and ETW metadata do not establish two-way audio or a cause of failure.

The strategy probe interleaves address families and staggers at most two TCP
attempts by 250 ms, following the connection-attempt approach in
[RFC 8305](https://www.rfc-editor.org/rfc/rfc8305.html). Losing attempts are dropped
with their sockets and recorded as cancelled, so an additional unreachable AAAA
record cannot add another one-second delay before IPv4. TLS validation is unchanged.

Updates validate a bounded ZIP, canonical paths, a complete per-file SHA256
catalog, pinned upstream files, the integrated Telegram controller and a native launcher before stopping
anything. Remote installs require the authoritative release asset digest. Local
archives can be previewed with `update --from archive.zip`. Installation uses a
trusted durable journal and verifies every backup before rollback. Private update
storage remains Administrator/SYSTEM-only; published executables allow Users
read/execute. Unknown engine ownership prevents mutation. A completed self-update and an Applying rollback require reopening the menu.
Existing menus also reject control actions when another window replaces their
executable, keeping controller context tied to the program loaded at startup.

`dev/native-package-files.txt` is the release allowlist. Package building embeds
clean user-list defaults and an empty runtime. Run `cargo zapret licenses` with the
`rust-docs` component to regenerate `LICENSE-rust.txt` from the locked release
dependency graph and the Rust standard-library notices. Regenerate this file when
changing release dependencies or the build toolchain.

The developer converter runs as `cargo zapret import-flowseal SOURCE strategies --check --allow-known-differences`.
It validates all 22 supported Flowseal inputs. A catalog with `retired.txt` skips
withdrawn output files during comparison and export. An empty export directory
receives all 18 converter-managed profiles. The Python entry point
forwards to this command. Frozen Python conversion logic is retained in the test
fixtures as a parity reference.


## Native laboratory and developer measurements

`bin/zapret-rust.exe lab --dir PATH --plan-only` validates the `.queue` files and
reads the current DPI/target suite without DNS, process control or runtime writes.
Remove `--plan-only` only for an authorized live experiment in an elevated console.
Trials use a private pinned package, a destination-IP capture filter, Windows Job
ownership and the same bounded native HTTP probes as strategy selection. A game,
changed connection, VPN, Ctrl+C, `stop` file or the overall deadline ends collection.
The original owned bypass is restored unless a newly started game prevents it.

The existing `@ name`, `@sleep N`, allowed payload/range/desync lines, TSV columns,
`.summary`, `.queue.done`, `lab.log` and `finished` files are retained. An invalid
line now rejects the whole queue before a trial instead of silently changing the
variant. Each batch reuses one captured 65536-byte POST payload via `probe --post-file`.
No curl process is launched per target. The legacy `dev/strategylab.ps1` forwards to
the installed controller and also accepts `-PlanOnly`.

```powershell
cargo zapret perf-probe --process-id 1234 --duration-sec 10 --interval-ms 250 --out-file dist/resources.json
cargo zapret memory-bench --baseline PATH --out dist/memory.json --hosts 1000 --rounds 7 --warm 10000
cargo zapret check-probe bin/zapret-rust.exe --subcommand probe --output dist/native/probe.json --compare-legacy
```

`perf-probe` keeps the Schema-1 process-only report, a held process handle and
creation-time identity. Existing output is never overwritten. `memory-bench` runs
the ring-learning Lua workload on a virtual filesystem using Lua 5.4 embedded in
the Rust developer tool. No separate Python/Lupa runtime is needed. CPU accounting
is quantized and remains separate from wall time.

The native package, BAT/menu, mapped-image installation and probe acceptance
harnesses now run through `cargo zapret check-*` and write success or failure
evidence. Probe fixtures include verified local TLS and require no OpenSSL.
`--compare-legacy` explicitly runs the historical PowerShell/curl benchmark arm.
Without that option the report contains native measurements only and claims no
speedup over another implementation. These are loopback measurements, not full
strategy-selection duration or game latency. Python/PowerShell entries remain thin
compatibility launchers. Original fixtures, the historical finalist replay and
privileged engine/Lua checks remain reference checks outside the product ZIP.

## Historical replay, menu PNGs and native ring

- `cargo zapret perf-bench --plan-file PLAN --journal-file JOURNAL --out-file REPORT` replays both historical finalist protocols with the original canonical digest, integer threshold, completion and resource checks.
- `cargo zapret menu-preview --out-dir dist/ui-preview` exports five offscreen PNGs from actual native menu Frame/spans.
- `cargo zapret check-live --validate-only` emits the service/start/restore plan. Mutating execution additionally requires explicit `--allow-live-changes`, ownership, admin and game checks.
- `cargo zapret check-ring` runs the original Lua fixtures through the Rust ABI in embedded Lua 5.4.
- `cargo zapret build-ring` builds the pinned engine bridge/DLL and tests actual LuaJIT, sandbox, timers and file I/O without a driver or network. `--queue` prepares rollback data for activation on the next explicit start/restart.
- `cargo zapret build-ring --native-windows` builds the Win64 engine with built-in Rust rules and Luna for user scripts. It uses LLVM MinGW and extracts the pinned resource and WinDivert import library with Windows `tar.exe`. The candidate is `dist/native/native-engine-candidate`. Add `--conformance` for the C and LuaJIT comparisons. The comparison compiler's worker count is configurable with `ZAPRET_NATIVE_BUILD_JOBS`. Add `--compatibility` to build with LuaJIT and the legacy updater files.
- `cargo zapret package --candidate dist/native/native-engine-candidate` builds the controller and packages the candidate in a temporary copy.
- `cargo zapret check-engine [--pkg DIR] [--fixture NAME]` repeats actual-engine checks in private TEMP jobs.

[Native ring design, source pins and build prerequisites](zapret-ring-ffi/README.md). The native package exports verified queued files without activating them on the developer connection. Build tools, compatibility references and rollback data are excluded.
