/* MIT. Lua and the Rust receive/replay loops share these packet actions. */
_Static_assert(VERDICT_PASS == 0 && VERDICT_MODIFY == 1 && VERDICT_DROP == 2 &&
    VERDICT_MASK == 3 && VERDICT_PRESERVE_NEXT == 4, "Rust packet verdict ABI");
uint8_t zapret_verdict_aggregate(uint8_t, uint8_t);
#define verdict_aggregate zapret_verdict_aggregate
