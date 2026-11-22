/* MIT. The rule iterator yields before any Lua call. */
#pragma once
typedef struct {
    const t_ctrack_positions *positions;
    const t_ctrack_position *current, *opposite;
    bool *cutoff;
} zapret_rule_direction;
typedef struct {
    struct func_list *next;
    const t_ctrack_position *position;
    uint32_t number, payload;
    bool incoming, all_cutoff, wanted;
} zapret_rule_cursor;
typedef struct {
    struct func_list *rule;
    const struct packet_range *range;
    uint32_t number;
    bool accepts_payload, in_range, cutoff;
} zapret_rule_step;

_Static_assert(offsetof(struct func_list, payload_type) == 8 &&
    offsetof(struct func_list, range_in) == 16 && offsetof(struct func_list, range_out) == 36 &&
    offsetof(struct func_list, args) == 56 && offsetof(struct func_list, next.le_next) == 64,
    "Rust Lua rule node ABI");
_Static_assert(offsetof(t_ctrack, pos) == 24 && offsetof(t_ctrack, b_lua_in_cutoff) == 197 &&
    offsetof(t_ctrack, b_lua_out_cutoff) == 198 && sizeof(zapret_rule_direction) == 32 &&
    sizeof(zapret_rule_cursor) == 32 && offsetof(zapret_rule_cursor, incoming) == 24 &&
    sizeof(zapret_rule_step) == 24 && offsetof(zapret_rule_step, accepts_payload) == 20,
    "Rust Lua rule selection ABI");
_Static_assert(VERDICT_MASK_VALID_LUA == 7 && sizeof(lua_Integer) == 8, "Rust Lua verdict ABI");

bool zapret_lua_rule_direction(t_ctrack *, const t_ctrack_positions *, bool, bool, zapret_rule_direction *);
bool zapret_lua_scan_next(zapret_rule_cursor *, zapret_rule_step *);
void zapret_lua_scan_observe(zapret_rule_cursor *, const zapret_rule_step *, bool);
uint32_t zapret_lua_scan_result(const zapret_rule_cursor *, const zapret_rule_direction *);
bool zapret_lua_invoke_next(zapret_rule_cursor *, zapret_rule_step *, bool);
int32_t zapret_lua_verdict(lua_Integer);
