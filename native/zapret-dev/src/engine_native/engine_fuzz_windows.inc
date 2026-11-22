/* Every RNG, allocation and process/VM observation happens outside Rust. */
typedef struct { uint32_t stage, iteration; size_t length, modified; uint8_t first; } zapret_fuzz;
uint32_t zapret_engine_fuzz_next(zapret_fuzz *, uint32_t, size_t);
const char *zapret_engine_fuzz_name(uint32_t, uint32_t);
const char *zapret_engine_fuzz_message(uint32_t);
_Static_assert(sizeof(zapret_fuzz) == 8 + 3 * sizeof(size_t) &&
    FUZZ_MAX_PACKET_SIZE == 69632, "Rust diagnostic loop ABI");

static void fuzzPacketData(unsigned count)
{
    uint8_t *packet = NULL, modified[FUZZ_MAX_PACKET_SIZE];
    uint32_t mark = 0;
    size_t observation = 0;
    zapret_fuzz state = {0};
    uint32_t step;
    while ((step = zapret_engine_fuzz_next(&state, count, observation))) {
        switch (step) {
        case 1: observation = bQuit; break;
        case 2: DLOG_CONDUP("fuzz ct=%u\n", state.iteration); break;
        case 3: case 7: case 9: observation = random(); break;
        case 4: packet = malloc(state.length); observation = packet != NULL; break;
        case 5: fill_random_bytes(packet, state.length); break;
        case 6: observation = packet[0]; break;
        case 8: packet[0] = state.first; break;
        case 10: {
            size_t length = state.modified;
            // Keep the two native RNG observations in their original argument slots.
            processPacketData(&mark, zapret_engine_fuzz_name(0, random()),
                zapret_engine_fuzz_name(1, random()), packet, state.length, modified, &length);
            break;
        }
        case 11: free(packet); break;
        }
    }
}

static void do_fuzz(void)
{
    const char *format = zapret_engine_fuzz_message(params.fuzz);
    if (format) {
        DLOG_CONDUP(format, params.fuzz);
        fuzzPacketData(params.fuzz);
    }
}
