/* MIT. Policy-only fixture for preflight and per-rule Lua entry decisions. */
#include "lua_rules_abi.h"
#include "packet_range_windows.inc"

static size_t reference_rules(const struct func_list *first, const t_ctrack_position *pos,
    bool incoming, t_l7payload payload, uint32_t voluntary, uint32_t *stage, uint32_t *issued)
{
    bool cutoff = true, unwanted = true;
    uint32_t number = 0;
    size_t count = 0;
    for (const struct func_list *rule = first; rule; rule = LIST_NEXT(rule, next)) {
        const struct packet_range *range = incoming ? &rule->range_in : &rule->range_out;
        ++number;
        if (unwanted)
            unwanted &= !l7_payload_match(payload, rule->payload_type);
        if (cutoff && !(voluntary & (1u << number)) && !check_pos_cutoff(pos, range))
            cutoff = false;
    }
    *stage = cutoff ? 0 : unwanted ? 1 : 2;
    if (*stage != 2) return 0;
    number = 0;
    for (const struct func_list *rule = first; rule; rule = LIST_NEXT(rule, next)) {
        const struct packet_range *range = incoming ? &rule->range_in : &rule->range_out;
        ++number;
        if (!(voluntary & (1u << number)) && check_pos_range(pos, range) &&
            l7_payload_match(payload, rule->payload_type)) issued[count++] = number;
    }
    return count;
}
static size_t rust_rules(struct func_list *first, const zapret_rule_direction *direction,
    bool incoming, t_l7payload payload, uint32_t voluntary, bool skip, uint32_t *stage, uint32_t *issued)
{
    const zapret_rule_cursor setup = {.next = first, .position = direction->current,
        .payload = payload, .incoming = incoming, .all_cutoff = true};
    zapret_rule_cursor cursor = setup;
    zapret_rule_step step;
    while (zapret_lua_scan_next(&cursor, &step))
        zapret_lua_scan_observe(&cursor, &step, !!(voluntary & (1u << step.number)));
    *stage = zapret_lua_scan_result(&cursor, direction);
    if (*stage != 2) return 0;
    cursor = setup;
    size_t count = 0;
    while (zapret_lua_invoke_next(&cursor, &step, skip)) {
        CHECK(step.rule == first + step.number - 1);
        CHECK(step.range == (incoming ? &step.rule->range_in : &step.rule->range_out));
        if (!(voluntary & (1u << step.number)) && step.in_range && step.accepts_payload)
            issued[count++] = step.number;
    }
    return count;
}
static void check_lua_rules(void)
{
    enum { COUNT = 5, SCENARIOS = 32768 };
    uint32_t rng = 0xfa6a91e3u;
    unsigned invocations = 0, cutoffs = 0, refused = 0;
    for (test_flags = 0; test_flags < SCENARIOS; ++test_flags) {
        t_ctrack record = {0};
        const bool has_track = (test_flags & 1) != 0, incoming = (test_flags & 2) != 0;
        const bool server = (test_flags & 4) != 0, supplied = (test_flags & 8) != 0;
        record.pos.client.pcounter = (test_flags >> 4) & 15;
        record.pos.server.pcounter = (test_flags >> 8) & 15;
        t_ctrack_positions replay = record.pos;
        replay.client.pcounter += 5;
        replay.server.pcounter += 7;
        zapret_rule_direction direction;
        CHECK(zapret_lua_rule_direction(has_track ? &record : NULL, supplied ? &replay : NULL,
            incoming, server, &direction));
        const t_ctrack_positions *snapshot = supplied ? &replay : has_track ? &record.pos : NULL;
        const t_ctrack_position *current = snapshot ? incoming ^ server ? &snapshot->server : &snapshot->client : NULL;
        CHECK(direction.positions == snapshot && direction.current == current);
        CHECK(direction.opposite == (snapshot ? incoming ^ server ? &snapshot->client : &snapshot->server : NULL));
        CHECK(direction.cutoff == (has_track ? incoming ? &record.b_lua_in_cutoff : &record.b_lua_out_cutoff : NULL));
        struct func_list list[COUNT] = {0};
        static const char modes[] = {'a', 'x', 'n', 's', 'b', 'p'};
        for (unsigned n = 0; n < COUNT; ++n) {
            rng = rng * 1664525u + 1013904223u;
            list[n].next.le_next = n + 1 < COUNT ? &list[n + 1] : NULL;
            list[n].payload_type = rng & (1u << 16) ? 0 : rng & (1u << 17)
                ? 1ull << L7P_HTTP_REQ : 1ull << L7P_KNOWN;
            list[n].range_in = (struct packet_range){
                {modes[(rng >> 2) % 6], (rng >> 7) & 15}, {modes[(rng >> 12) % 6], (rng >> 16) & 15},
                !!(rng & (1u << 20))};
            list[n].range_out = (struct packet_range){
                {modes[(rng >> 21) % 6], (rng >> 23) & 15}, {modes[(rng >> 27) % 6], (rng >> 25) & 15},
                !!(rng & (1u << 31))};
        }
        t_l7payload payload = test_flags & 16 ? L7P_HTTP_REQ : test_flags & 32 ? L7P_UNKNOWN : L7P_DNS_QUERY;
        uint32_t voluntary = has_track ? test_flags >> 8 : 0;
        uint32_t before[COUNT], after[COUNT], ref_stage, actual_stage;
        size_t a = reference_rules(list, current, incoming, payload, voluntary, &ref_stage, before);
        size_t b = rust_rules(list, &direction, incoming, payload, voluntary, !has_track && (test_flags & 64),
            &actual_stage, after);
        CHECK(ref_stage == actual_stage && a == b && !memcmp(before, after, a * sizeof(*before)));
        CHECK(record.b_lua_in_cutoff == (has_track && incoming && !ref_stage));
        CHECK(record.b_lua_out_cutoff == (has_track && !incoming && !ref_stage));
        if (has_track) {
            CHECK(zapret_lua_rule_direction(&record, NULL, incoming, server, &direction) == !!ref_stage);
            CHECK(zapret_lua_rule_direction(&record, NULL, !incoming, server, &direction));
        }
        invocations += (unsigned)b;
        cutoffs += ref_stage == 0;
        refused += ref_stage == 1;
    }
    for (lua_Integer value = -512; value < 512; ++value)
        CHECK(zapret_lua_verdict(value) == ((value & ~VERDICT_MASK_VALID_LUA) ? -1 : (int32_t)value));
    CHECK(zapret_lua_verdict(INT64_MIN) == -1 && zapret_lua_verdict(INT64_MAX) == -1);
    CHECK(invocations && cutoffs && refused);
    printf("PASS lua_rules cases=%u invocations=%u cutoffs=%u refused=%u verdict_values=1026\n",
        SCENARIOS, invocations, cutoffs, refused);
}
