# Engine configuration expansion

`wordexp-cygwin.json` records 86 results from the Cygwin 3.6.12-1 implementation
with Bash 5.2.21-1 and `WRDE_NOCMD`, captured on 2026-11-14. The corpus includes
the exact environment values and filesystem names used by the oracle.
`wordexp-cygwin.c` is the oracle program. It reads the input file as bytes and
prints the return code, word count, and each returned word as hexadecimal.

The engine calls `wordexp` once, with `WRDE_NOCMD`, then reads `we_wordc` and
`we_wordv`. Its cleanup calls `wordfree`. It prefixes the configuration with a
dummy argument and replaces CR, LF and TAB with spaces before expansion.
The Rust tests also exercise the underlying parser directly.

The protected Cygwin implementation preserves command and process substitutions
as literal text. Its newline-delimited protocol also splits expansion-produced
newlines while reading the original number of words. Both behaviors are captured
in the corpus. The Rust parser performs the expansions in-process.

`cargo test --locked --manifest-path native/Cargo.toml -p zapret-wincompat`
replays the frozen corpus and tests the caller-buffer contract, invalid input
and expansion budgets. The production C shim allocates and frees both the
string block and pointer table through the native C CRT. It publishes the
result only after parsing and all allocations finish. The Rust boundary catches
panics and reports required byte/word counts when the caller buffer is short.
Input is bounded to 64 KiB, output to 4 MiB, words to 16,384, and nesting to 32.
The engine's configuration file limit is 16 KiB.

To run the allocation/reuse/free regression, first build the release staticlib,
then compile `wordexp-caller.c` with the production `wordexp.c`, its include
directory, and `libzapret_wincompat.a`. The native LLVM MinGW link uses `-static`
and the Windows libraries `ws2_32`, `userenv`, `bcrypt`, `ntdll`, and `advapi32`.
The same native oracle executable can replay the corpus with the recorded
environment and working-directory fixture.
