# Native ring integration

`zapret-ring` owns strategy hints, TTL/LRU, context/link leases, packet decisions
and the bounded active-host index. `zapret-ring-ffi` publishes a narrow versioned
C ABI. The Rust bridge handles the Lua stack, retains engine objects and
loads only the adjacent `zapret-ring.dll` with its compiled SHA-256 and ABI pin.
The engine disables FFI and removes `package.loadlib`.
The two project-specific functions in `lua/fooling.lua` use the same bridge for
TCP sequence adjustment and split ranges. The adapter calls the engine's
existing Lua helpers for packet objects, replay state and sending. It includes
the legacy implementations for stock engines and older bridges.

The following commands cover the legacy LuaJIT and Cygwin build. See
[Native Windows engine](#native-windows-engine) for the default Windows package.

```text
cargo zapret build-ring
cargo zapret check-ring
cargo zapret check-engine
cargo zapret build-ring --queue
```

The last command prepares a complete before/after transaction under
`tools/rust-ring-next`. It leaves the active engine and its Lua files intact.
The installed controller applies it during the next explicit start/restart,
after the owned process stops, and rolls back the files and restarts the previous
engine on failure. An interrupted write is recovered from the journal. Packaging
exports the verified queued bytes into the private release archive without
activating them on the user's connection. The queue and its rollback data do not
ship in the archive.

`check-engine` runs the selected engine in a private TEMP directory.
The opt-in environment `ZAPRET_RING_SELFTEST=1` together with `--intercept=0`
enters the engine's restricted Lua/timer stack before any WinDivert open. It
cannot enable interception. The suite covers the original store, watchdog,
link guard, host cache and packet fixtures, the Rust-backed `fooling.lua` adapter,
real low-integrity file writes,
timer expiry, restricted Lua APIs and rejection of a modified module. The
developer Lua 5.4 binding uses the same ABI for fast pure-fixture checks.

The runner requires cached, hash-verified sources under
`dist/upstream/rust-ring-build/`:

| File | Pinned source | SHA-256 |
| --- | --- | --- |
| zapret2-221d7dff.tar.gz | [zapret2 commit 221d7dff](https://codeload.github.com/bol-van/zapret2/tar.gz/221d7dff24bfec0cd5ac0a5070b8acef2008af3d) | c9925bb194eea8c19feb05ea6b24a848e8b50af8c64643b9e394ffe653327d87 |
| luajit2-2.1-20250826.tar.gz | [OpenResty LuaJIT v2.1-20250826](https://codeload.github.com/openresty/luajit2/tar.gz/refs/tags/v2.1-20250826) | 5a49743ad6ce4b7f19aac71b55a08052c1feb62750f051982082c12bf62f39c0 |
| luna-core-4.0.2.crate | [Luna Core 4.0.2](https://static.crates.io/crates/luna-core/luna-core-4.0.2.crate) | 0162144beb06b927dce484b6447ca7ec6a62f331bbd257b6c16eab9186497c82 |

Private build tools live under `dist/rust-tools`: the pinned Cargo/Rust toolchain,
GNU linker and Cygwin (`gcc-core`, `make`, `zlib-devel`, `pkg-config`, `binutils`,
plus archive utilities). Cygwin can be installed without administrator rights
using its [official installer](https://cygwin.com/install.html) with
`--no-admin --no-desktop --no-startmenu --no-shortcuts --no-write-registry
--no-replaceonreboot --root <private-root>`.
Compiler downloads are development tools and are excluded from release inputs.

The Cygwin build validates source archives, extracts the base into a fresh
directory and applies anchored engine patches. It builds static LuaJIT with
`LUAJIT_DISABLE_FFI` and links the Rust Lua bridge, startup entries, bounded TLS
readers and pinned DLL loader into the upstream C engine. The C call sites pass
filter allocation, library registration and the driver-free self-test to Rust.
The TLS resize guard checks the caller's buffer and the record length before a
resize. The bridge uses the Windows x64 calling convention and a `no_std` Rust
archive. The final executable uses the Cygwin C runtime.
`dist/native/ring-engine-link.map` records the linked objects. The conformance
suite uses `rust_ring.c` as the C reference. `tools/upstream.txt` records the base
release provenance. `tools/rust-ring.json` records derivative files and hashes.

The previous Lua algorithms are compatibility references in `dev/tests/fixtures`.
The legacy adapters translate engine tables, call detectors and timers, and
perform file I/O. No extra per-packet process or IPC is involved.

## Native Windows engine

```text
cargo zapret build-ring --native-windows
cargo zapret check-engine --pkg dist/native/native-engine-candidate --fixture native-platform.lua
cargo zapret package --candidate dist/native/native-engine-candidate
```

The native Windows engine builder requires Rust 1.99 or later for its C variadic
entry points. The standard engine links the pinned Luna interpreter and
`zapret-wincompat`. The controller
loads the bundled rule implementations through `--builtin-rules`. The standard
ZIP contains no Lua files. Lua source passed explicitly through `--lua-init`
uses the Lua 5.2 dialect with zapret's compatibility functions. The separate
`--compatibility` build retains LuaJIT for LuaJIT-specific scripts and bytecode.

The standard link uses the SHA-256-pinned `winws_res64.o` and
`libwindivert64.a` from the upstream archive. The engine's own tables are
linked from Rust. Run `cargo zapret build-ring --native-windows --conformance`
to compile and compare the pinned C and LuaJIT references.
Rust releases gzip script buffers through Luna's protected errors. The LuaJIT
compatibility build uses the pinned interpreter's protected C frame to release
the buffer before propagating the original error. The C oracle checks the Win64
GC64 frame layout, the inherited error handler and the error status. Both builds
use the external WinDivert driver.
The conformance suite prepares the pinned C and Lua sources and the local
comparison fixtures. The linked objects are listed in
`dist/native/native-engine-build/engine-link.map`.

### Migration checkpoints

The checkpoints below record the migration of each interface. They include the
C and LuaJIT bindings used to verify the corresponding Rust implementation.

Rust provides configuration expansion, Unicode
file operations, daemon re-execution, packet header parsing and serialization,
internet checksums, timer scheduling, host/IP list readers, connection tracking,
TCP reassembly, bounded privilege transitions, integrity labels, balanced
COM initialization for the low-integrity known folder, Job limits and atomic
publication of a completed process-sandbox transition. Writable-directory setup
checks path bounds, directory type, low-integrity labeling and environment
publication before reporting success. Startup PID output reuses the owned Rust
file writer; console icons use best-effort timed messages without destroying
shared or foreign icon handles. Windows entry and cleanup ordering is controlled
by Rust; C callbacks bind existing engine fields, protected Lua initialization
and driver-specific capture storage. Per-rule Lua instance keys use the same
bounded Rust byte writer and decimal conversion as native PID output.
Gzip uses the Cargo-pinned `zlib-rs` through its zlib ABI and `flate2`. Rust owns
Lua streaming-codec output and checked geometric buffer growth. A Lua userdata
finalizer retains that output across VM allocation errors; stream I/O pointers
are cleared before returning. The C boundary supplies remaining engine
startup operations and the existing Lua API adapters. The
engine uses the existing WinDivert API.

The public Lua reconstruction functions decode tables in C and serialize
IPv4, IPv6, TCP, UDP and ICMP fields in Rust. Rust writes options and extension
headers, updates packet lengths and checksums, and checks fragment bounds
before moving bytes. The LuaJIT fixture checks 300 wire outputs against a
digest recorded from the pinned C engine and exercises invalid input through
the same Lua API.

The timer pool owns its names, insertion order, deadlines and fire counters in
Rust. C holds Lua registry references and invokes callbacks between Rust calls.
A generation ID keeps completion of a removed timer from changing a replacement
created inside its callback. `timertest.lua` exercises this through real LuaJIT.

The list readers retain the pinned plain-text chunk sizes, NUL handling,
strict-host marker, lowercase conversion and first-gzip-member behavior.
Corrupt gzip input fails before pool insertion. Rust owns the host hash tables,
strict domain matching and the ordered IPv4/IPv6 prefix sets. Duplicate domains
retain the first entry's flags. Broader prefixes replace contained entries.
Every native build compares these operations to the pinned C implementation
without opening a driver.

Rust owns the registered list files, their modification signatures and the
ordered references in each profile. Profiles share a record for each resolved
filename. Inline lists have separate records, and imports append the template's
references in their existing order. C resolves the filename, reads file metadata
and invokes the existing loader. A failed access check preserves the loaded
entries. If loading fails after that check, the partial contents are removed and
the previous signature allows a later retry.

The list registry comparison covers path aliases, duplicate references,
profile imports, timestamp and size changes, missing files and failed reloads.
The real engine test verifies that shared files load once and that template
imports preserve each profile's ordering.

Rust walks profiles in their configured order and selects the first match.
It checks the address family, protocol and port before running the existing
list callbacks. Profiles without configured lists bypass those callbacks.
Hostlist reload, IP exclusions in both directions, automatic hostlist
precedence and the optional host-check outputs retain their existing order.
The native build compares 65,562 selections with pinned C using the real
list APIs and reports local search timings for three profile sets.

Rust also reselects the profile when a connection reveals its L7 protocol or
hostname. It updates the connection's cached hostlist result, resets Lua
cutoffs on a profile change, and invokes the existing UDP failure callback
before applying a negative hostlist result. C supplies the hostname parser,
allocator, cache/list APIs and diagnostic output. The comparison runs 40,286
discovery calls and 12 boundary checks, including two allocation/cache failures
followed by successful retries. Failed discovery preserves the previous
hostname and keeps discovery pending. A matching cached hostname reuses its
existing allocation.

Packet setup in play_prolog also uses Rust. It validates the IP family,
initializes the play state, constructs source/destination addresses, resolves
direction and server-side ports, and selects the cached or first matching
profile. Conntrack creation and cleanup execute in C between two Rust calls,
keeping Lua allocation and release outside Rust frames. Hostname cache reads,
TTL operations and logging use the existing C entry points. The conformance
check covers 32,775 setups and nine boundary cases. A cached IP hostname retains
its IP flag, and a failed hostname copy leaves profile lookup pending for retry.
Disabled debug logging skips the reporting callbacks.

Rust decides automatic hostlist failures from TCP retransmissions, early RST
and HTTP redirect replies, and UDP packet counts. It retains the wrapping
sequence bounds, stopped-counter sentinel, replay positions and server-mode
rules. Rust also serializes the bounded IPv4/IPv6 reset frames and owns the
failure-count and publication decisions. C provides cache clocks, list checks,
file I/O, logs and the existing raw sender. Failed file appends roll back newly
inserted in-memory hosts. The buffered writer checks fflush and fclose.
Every build compares 20,005 cases, 71 boundary checks and 486 reset frames
against pinned C, including a failed publication followed by a successful retry.

Connection keys, direct/reverse lookup, insertion order, TCP/UDP accounting,
TCP state transitions, expiration decisions and in-order TCP reassembly use
Rust. C retains stable connection records, clocks and Lua references. Rust
allocates and frees the client reassembly buffer. Tuple reuse releases the old
Lua state between Rust calls. TCP sequence arithmetic retains the
upstream wrapping and overlap rules, including its reset-counter semantics.

Every native build compiles the pinned original C connection table before
patching it and compares both APIs in memory. The oracle covers all TCP flags
and window-scale bytes, malformed options, IPv4/IPv6 keys, both directions,
tuple reuse, ordered enumeration, drops, timeout boundaries and buffer
cleanup. It also compares 960,000 reassembly decisions. `conntracktest.lua`
exercises the ordinary `conntrack_feed` API in real LuaJIT on both engine paths.
Rust additionally rejects length requests that overflow the reassembly size.

The Rust client reassembly lifecycle checks the TCP server window, validates
the first fragment, and tracks the TLS or QUIC payload kind until completion
or cancellation. A completed session retains its buffer while the deferred
packets are replayed. Cancellation clears the buffer and drains queued originals
in order, including after a send failure. On queue overflow the TCP handler
falls back to the incoming packet's payload. The native build compares 2400
sessions against the pinned C implementation and checks seven boundary cases.

Rust owns the deferred packet queue and copies each packet's bytes, destination,
interface names, marks and optional connection positions at enqueue time.
The existing packet limit and FIFO order apply. Dequeuing transfers ownership
to the caller until `rawpacket_free`, including when the connection is cleared.
Empty queues retain their container allocation until connection cleanup, so
subsequent deferred bursts reuse its capacity.
The native build compares queue operations against the pinned C implementation.

Rust also replays deferred packets in FIFO order. It computes the TCP sequence
or UDP byte offset, handles the engine verdict, and owns each packet until the
callbacks return. The replay loop drains the queue after a send failure. An
oversized modified length is rejected before sending. When early packets lack a
TCP position snapshot, the first available sequence becomes the anchor at the
accumulated byte offset. The native build compares the Rust and pinned C replay
loops on the same FIFO using in-memory packet and send callbacks.

Rust drives the Windows capture loop, including network reconnection, batch
framing, packet verdict dispatch and timer scheduling. The WinDivert receive
stays pending until completion or cancellation and drain. The C adapters
submit and send through WinDivert and call the existing LuaJIT API.
Each native build compares batch dispatch against the pinned C loop and checks
overlapped receive and cancellation on private Windows pipes.
Receive timers use elapsed monotonic time after each wait, including delayed
wakeups under scheduler load.

Rust also provides the protocol signatures, HTTP header and TLS SNI readers,
partial TLS extension parsing, protocol and payload filters, and marker parsing
and resolution. QUIC version and connection-ID parsing and CRYPTO fragment
assembly use bounded Rust slices. MTProto detection uses the workspace's AES
crate. The native build compares these APIs and their output buffers against
the pinned C source, including every signature's positive cases, truncations,
invalid lengths, fragment overlap and duplicate removal. `protocoltest.lua`
checks marker resolution through the public Lua API.
TLS field lookups also reject extensions past the advertised handshake end,
while accepting partial captures and coalesced handshakes.

ClientHello modifications also execute in Rust: option parsing, SNI replacement
and randomization, random/session-id changes and padding encapsulation. The edit
is validated before any write or random draw, with checked record, handshake and
extension lengths. A fatal error preserves the fake buffer and its size. An
oversized real payload remains a nonfatal padding failure. C supplies only the
existing public entry point and logger. Rust edits the caller's allocation
without allocating another buffer, initializes only newly exposed output bytes,
and snapshots at most 299 payload bytes when a session-id copy needs them.

Every native build compares 24,815 modifier/parser scenarios against pinned C,
including random draw order, buffer alignment, session IDs and padding. It also
checks unchanged buffers after failure and two intentional fixes for wrapped
lengths. `protocoltest.lua` exercises the public `tls_mod` API and the record-size
overflow regression in real LuaJIT. A separate microbenchmark records C/Rust batch
timings in `dist/native/native-engine-build/protocol-check.benchmark.json`; it
measures transformations with a silent logger, not network round-trip time.

QUIC Client Initial decryption also runs in Rust, using the workspace-pinned
`ring` library for HKDF-SHA256, header protection and authenticated AES-128-GCM.
All eight legacy/version salt choices and v1/v2 labels are retained. Only an
authenticated plaintext is copied to the caller: failed parsing, capacity checks
or tag verification leave its buffer and length unchanged. CID lengths, Initial
type and reserved bits are validated. Stack scratch is bounded to 65535 bytes,
the header to 2048 bytes, and no per-packet heap allocation is introduced.

The native build compares encrypted packets against pinned C, including both
RFC client Initial examples, older drafts, variable-width fields, packet-number
boundaries, damaged tags and truncations. Rust unit tests also cover coalesced
datagrams and overlapping input/output buffers. Golden fixtures come from
RFC 9001 and RFC 9369. Complete C/Rust decryption microbenchmarks are
saved in `dist/native/native-engine-build/protocol-check.quic-benchmark.json`.
The native `protocol.c` now contains only the TLS ABI/logger adapter. Existing
Lua cryptographic APIs and their legacy primitives remain separate C adapters.

Rust also owns the auto-hostlist failure records and the IPv4/IPv6 hostname/TTL
caches. Their public C payloads stay at stable addresses and use `UnsafeCell`
for field access between Rust calls. Host-failure names use Rust allocation;
the C caller retains ownership of the IP-cache hostname buffers it replaces.
Keys retain the native 44-byte interface buffer and byte truncation rules.
Failure expiry does not renew on increment, and the IP-cache purge limiter is
shared across cache instances, including calls that disable expiration.

The auxiliary-cache oracle compares the pinned C API with Rust on 61,000
host-failure operations, 84,096 IP-cache operations, 634,000 state snapshots
and 693 diagnostic dumps. It checks duplicate records across hash expansion,
ordered deletion and reinsertion, mutable payloads, timestamp refresh and clock
calls, interface isolation, zero lifetime and backwards clock observations.

The builder checks PE imports and the real-engine tests run in a TEMP package
without `cygwin1.dll`. They also exercise Unicode paths longer than MAX_PATH,
Lua file and module APIs, system time, RNG, interface observations and a denied
write to a prepared medium-integrity sentinel. The native Lua adapter recognizes
Windows drive and UNC paths through the Rust ABI.

The complete engine check exercises generated, explicit and disabled filter
exports with `--dry-run`. It validates their text with the pinned
`WinDivertHelperCompileFilter` API. The native lifecycle checks start in a
private job with absent standard handles and exercise `--daemon` with a relative
working directory.

The build additionally requires these pinned inputs.

| Input | Location | SHA-256 |
| --- | --- | --- |
| LLVM MinGW 20261104 UCRT x64 archive | `dist/rust-tools/llvm-mingw-20261104-ucrt-x86_64.zip` | `552191b5754c49a5a20723276a6fc56541ea1922c4c50b7b669022333fc1b40f` |

The workspace CI downloads the versioned upstream archives and verifies those
digests. The x64 Windows GNU build uses system `tar.exe`, LLVM MinGW and the
pinned BSD declarations in `engine_native/include`. Rust builds the upstream
LuaJIT archive for reference checks and the compatibility engine. The native CI
job builds and packages schema 4 engine manifests without a Cygwin installation.
The runtime uses the Windows UCRT and system DLLs.

For a controller that only reads version 1 engine manifests, build a transition
ZIP from a checkout with the original pinned Cygwin DLL.

```text
cargo zapret build-ring --native-windows --compatibility
cargo zapret package --candidate dist/native/native-engine-compatibility-candidate --compatibility
```

`--queue` also uses the compatibility candidate for the existing nine-file
activation journal. Reopen the menu after installing the transition ZIP to load
the new controller before installing the compact ZIP. The updater backs up and
retires `bin/cygwin1.dll` if the old manifest pins its current bytes, and restores
it during rollback. The Cygwin engine build continues to ship its DLL and license.

Native directory replacement uses FileRenameInfoEx where Windows supports it.
The older API fallback retains file replacement and can reject replacement of
an existing empty directory. Engine state snapshots use file replacement.
