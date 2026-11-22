/* MIT. VM calls around the Rust rule iterator. */
#include "lua_rules_abi.h"
#include "lua_context_windows.h"
#include "runtime_log_windows.h"
void zapret_lua_rule_scan_report(const zapret_rule_cursor *, const zapret_rule_step *,
    const t_lua_desync_context *, const char *, bool, zapret_log_sink);

static zapret_rule_cursor lua_rule_cursor(struct desync_profile *profile,
    const t_ctrack_position *position, bool incoming, t_l7payload payload)
{
    return (zapret_rule_cursor){
        .next = LIST_FIRST(&profile->lua_desync), .position = position,
        .payload = payload, .incoming = incoming, .all_cutoff = true,
    };
}
static void lua_rule_instance(t_lua_desync_context *ctx, const zapret_rule_step *step,
    char *name, size_t capacity)
{
    zapret_lua_context_rule(ctx,step->rule->func,step->number,name,capacity);
}
static uint32_t lua_rules_preflight(t_lua_desync_context *ctx, const zapret_rule_direction *direction,
    t_l7payload payload, bool incoming, char *instance, size_t capacity)
{
    const t_ctrack_position *pos = direction->current;
    zapret_rule_cursor cursor = lua_rule_cursor(ctx->dp, pos, incoming, payload);
    zapret_rule_step step;
    while (zapret_lua_scan_next(&cursor, &step)) {
        if (ctx->ctrack || params.debug) lua_rule_instance(ctx, &step, instance, capacity);
        const bool voluntary = ctx->ctrack && lua_instance_cutoff_check(params.L, ctx, incoming);
        if (params.debug) zapret_lua_rule_scan_report(&cursor, &step, ctx, instance, voluntary, DLOG);
        zapret_lua_scan_observe(&cursor, &step, voluntary);
    }
    return zapret_lua_scan_result(&cursor, direction);
}
