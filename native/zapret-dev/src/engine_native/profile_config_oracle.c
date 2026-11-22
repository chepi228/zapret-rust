/* MIT. Compare real list contents, template flags and ownership cleanup. */
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#undef main
struct params_s params;
static unsigned cases, faults, allocated, freed;
static unsigned errors;
static const char *last_error;
#define CHECK(condition) do { \
    if (!(condition)) { fprintf(stderr, "FAIL profile config case %u line %d: %s\n", cases, __LINE__, #condition); exit(1); } \
} while (0)
int DLOG(const char *format, ...) { (void)format; return 0; }
int DLOG_ERR(const char *format, ...) { ++errors; last_error = format; return 0; }
int DLOG_PERROR(const char *name) { (void)name; return 0; }
struct tm *zapret_localtime_r(const time_t *value, struct tm *output)
{ return localtime_s(output, value) ? NULL : output; }
#define dp_init_dynamic reference_dp_init_dynamic
#define dp_init reference_dp_init
#define dp_clear reference_dp_clear
#define dp_clear_dynamic reference_dp_clear_dynamic
#define dp_entry_destroy reference_dp_entry_destroy
#define dp_list_destroy reference_dp_list_destroy
#define dp_list_add reference_dp_list_add
#define dp_copy reference_dp_copy
#define dp_list_move reference_dp_list_move
#define dp_list_search_name reference_dp_list_search_name
#define dp_list_have_autohostlist reference_dp_list_have_autohostlist
#include "profile_config_reference.inc"
#undef dp_init_dynamic
#undef dp_init
#undef dp_clear
#undef dp_clear_dynamic
#undef dp_entry_destroy
#undef dp_list_destroy
#undef dp_list_add
#undef dp_copy
#undef dp_list_move
#undef dp_list_search_name
#undef dp_list_have_autohostlist
#define filter_defaults reference_filter_defaults
#include "profile_defaults_reference.inc"
#undef filter_defaults
#include "profile_config_windows.inc"
#include "profile_defaults_windows.inc"

static struct zapret_list_files *lists;
static struct zapret_list_file *automatic;

static void populate(struct desync_profile *profile, unsigned value)
{
    profile->n = value;
    profile->name = strdup(value ? "source" : "destination");
    profile->cookie = strdup(value ? "cookie-source" : "cookie-destination");
    CHECK(profile->name && profile->cookie);
    port_filter ports = {(uint16_t)(value ? 443 : 80), 444, false};
    icmp_filter icmp = {FLTMODE_FILTER, (uint8_t)(value ? 8 : 3), 0, true};
    ipp_filter ip = {FLTMODE_FILTER, (uint8_t)(value ? 50 : 47)};
    CHECK(port_filter_add(&profile->pf_tcp, &ports) && port_filter_add(&profile->pf_udp, &ports));
    CHECK(icmp_filter_add(&profile->icf, &icmp) && ipp_filter_add(&profile->ipf, &ip));
    struct func_list *rule = funclist_add_tail(&profile->lua_desync, value ? "source" : "destination");
    CHECK(rule);
    rule->payload_type = value;
    rule->range_in = (struct packet_range){{'n', 3}, {'n', 5}, true};
    CHECK(zapret_list_register(&lists, &profile->hl_collection, value ? "source" : "destination"));
    CHECK(zapret_list_register(&lists, &profile->hl_collection_exclude, value ? "source" : "destination"));
    CHECK(zapret_list_register(&lists, &profile->ips_collection, value ? "source" : "destination"));
    CHECK(zapret_list_register(&lists, &profile->ips_collection_exclude, value ? "source" : "destination"));
}
static void same(const struct desync_profile *left, const struct desync_profile *right)
{
    CHECK(left->n == right->n && !strcmp(left->name, right->name) && !strcmp(left->cookie, right->cookie));
    CHECK(left->filter_ipv4 == right->filter_ipv4 && left->filter_ipv6 == right->filter_ipv6 &&
        left->filter_l7 == right->filter_l7 && left->hostlist_auto == right->hostlist_auto);
    CHECK(left->hostlist_auto_fail_threshold == right->hostlist_auto_fail_threshold &&
        left->hostlist_auto_fail_time == right->hostlist_auto_fail_time &&
        left->hostlist_auto_retrans_threshold == right->hostlist_auto_retrans_threshold &&
        left->hostlist_auto_retrans_maxseq == right->hostlist_auto_retrans_maxseq &&
        left->hostlist_auto_incoming_maxseq == right->hostlist_auto_incoming_maxseq &&
        left->hostlist_auto_retrans_reset == right->hostlist_auto_retrans_reset &&
        left->hostlist_auto_udp_in == right->hostlist_auto_udp_in &&
        left->hostlist_auto_udp_out == right->hostlist_auto_udp_out);
    CHECK(!memcmp(&left->b_hostlist_auto_fail_threshold, &right->b_hostlist_auto_fail_threshold, 10));
    const struct zapret_list_collection *a[] = {left->hl_collection, left->hl_collection_exclude,
        left->ips_collection, left->ips_collection_exclude};
    const struct zapret_list_collection *b[] = {right->hl_collection, right->hl_collection_exclude,
        right->ips_collection, right->ips_collection_exclude};
    for (unsigned c = 0; c < 4; ++c) {
        for (size_t n = 0;; ++n) {
            const struct zapret_list_file *one = zapret_list_collection_at(a[c], n);
            CHECK(one == zapret_list_collection_at(b[c], n));
            if (!one) break;
        }
    }
    const struct port_filter_item *l = LIST_FIRST(&left->pf_tcp), *r = LIST_FIRST(&right->pf_tcp);
    while (l) {
        CHECK(r && l->pf.from == r->pf.from && l->pf.to == r->pf.to && l->pf.neg == r->pf.neg);
        l = LIST_NEXT(l, next);
        r = LIST_NEXT(r, next);
    }
    CHECK(!r);
    const struct func_list *f = LIST_FIRST(&left->lua_desync), *g = LIST_FIRST(&right->lua_desync);
    while (f) {
        CHECK(g && !strcmp(f->func, g->func) && f->payload_type == g->payload_type);
        CHECK(f->range_in.from.mode == g->range_in.from.mode && f->range_in.from.pos == g->range_in.from.pos &&
            f->range_in.to.mode == g->range_in.to.mode && f->range_in.to.pos == g->range_in.to.pos &&
            f->range_in.upper_cutoff == g->range_in.upper_cutoff);
        f = LIST_NEXT(f, next);
        g = LIST_NEXT(g, next);
    }
    CHECK(!g);
}
static unsigned fail_at, copy_calls, errors_before, staged_cleanups, cookie_releases;
static bool failing_copy(uint32_t kind, void *to, const void *from)
{
    if (++copy_calls == fail_at) return false;
    return profile_config_copy(kind, to, from);
}
static char *failing_duplicate(const char *text)
{
    (void)text;
    return NULL;
}
static void checked_destroy(uint32_t kind, void *head)
{
    CHECK(errors == errors_before);
    ++staged_cleanups;
    profile_config_destroy(kind, head);
}
static void checked_release(void *cookie)
{
    CHECK(errors == errors_before);
    ++cookie_releases;
    free(cookie);
}
static void import_failure(void)
{
    for (fail_at = 1; fail_at <= 18; ++fail_at) {
        struct desync_profile source = {0}, target = {0};
        dp_init(&source); dp_init(&target);
        populate(&source, 1); populate(&target, 0);
        struct desync_profile before;
        memcpy(&before, &target, sizeof(before));
        zapret_profile_config_ops ops = profile_config_ops;
        ops.copy = failing_copy;
        ops.destroy = checked_destroy;
        ops.release = checked_release;
        errors_before = errors;
        copy_calls = staged_cleanups = cookie_releases = 0;
        CHECK(!zapret_profile_import(&target, &source, &ops));
        CHECK(copy_calls == fail_at && staged_cleanups == 9 && cookie_releases == 1);
        CHECK(errors == errors_before + 1 && !strcmp(last_error, "dynamic structure copy failed\n"));
        CHECK(!memcmp(&target, &before, sizeof(before)));
        CHECK(dp_copy(&target, &source));
        // Copying and then destroying must remove valid linked-list heads.
        dp_clear(&target); dp_clear(&source);
        ++faults;
    }
    struct desync_profile source = {0}, target = {0};
    dp_init(&source); dp_init(&target);
    populate(&source, 1); populate(&target, 0);
    struct desync_profile before;
    memcpy(&before, &target, sizeof(before));
    zapret_profile_config_ops ops = profile_config_ops;
    ops.duplicate = failing_duplicate;
    errors_before = errors;
    CHECK(!zapret_profile_import(&target, &source, &ops));
    CHECK(errors == errors_before);
    CHECK(!memcmp(&before, &target, sizeof(before)));
    CHECK(dp_copy(&target, &source));
    dp_clear(&source); dp_clear(&target);
    ++faults;
}
static void import_automatic_conflict(void)
{
    struct zapret_list_collection *files = NULL;
    struct zapret_list_file *other = zapret_list_register(&lists, &files, "other-automatic");
    CHECK(other && automatic != other);
    struct desync_profile target = {.hostlist_auto = automatic}, source = {.hostlist_auto = other};
    errors_before = errors;
    CHECK(!reference_dp_copy(&target, &source));
    CHECK(errors == errors_before + 1);
    const char *reference_error = last_error;
    CHECK(!dp_copy(&target, &source));
    CHECK(errors == errors_before + 2 && !strcmp(last_error, reference_error));
    CHECK(target.hostlist_auto == automatic);
    zapret_list_collection_destroy(&files);
}
static void lifecycle(void)
{
    struct desync_profile_list_head first = {0}, second = {0};
    for (unsigned n = 0; n < 16; ++n) {
        struct desync_profile_list *entry = dp_list_add(&first);
        CHECK(entry);
        entry->dp.n = n;
        entry->dp.name = strdup(n & 1 ? "odd" : "even");
        CHECK(entry->dp.name);
    }
    CHECK(dp_list_search_name(&first, "even") == LIST_FIRST(&first));
    CHECK(!dp_list_search_name(&first, NULL) && !dp_list_search_name(&first, "absent"));
    CHECK(!dp_list_have_autohostlist(&first));
    unsigned moved = 0;
    while (!LIST_EMPTY(&first)) {
        struct desync_profile_list *entry = LIST_FIRST(&first);
        dp_list_move(&second, entry);
        ++moved;
    }
    struct desync_profile_list *entry;
    unsigned expected = 0;
    LIST_FOREACH(entry, &second, next) {
        CHECK(entry->dp.n == expected++);
    }
    CHECK(moved == 16 && expected == 16);
    LIST_FIRST(&second)->dp.hostlist_auto = automatic;
    CHECK(dp_list_have_autohostlist(&second));
    dp_list_destroy(&second);
    CHECK(LIST_EMPTY(&second) && LIST_EMPTY(&first));
}
static void *failing_allocate(size_t size) { (void)size; return NULL; }
static void profile_flow(void)
{
    struct desync_profile_list_head profiles = {0}, templates = {0};
    native_profile_flow flow = {.profiles = &profiles, .templates = &templates};
    CHECK(!native_profile_next(&flow, "base"));
    struct desync_profile_list *base = flow.current;
    CHECK(flow.count == 1 && base == LIST_FIRST(&profiles) && base->dp.n == 1);
    CHECK(!native_profile_label(&base->dp, true, "inherited"));
    flow.template = true;
    zapret_profile_config_ops failure = profile_config_ops;
    failure.allocate = failing_allocate;
    CHECK(zapret_profile_next(&flow, "target", &failure) == 1);
    CHECK(flow.current == base && flow.count == 1 && flow.template && !flow.template_count &&
        LIST_EMPTY(&templates) && !LIST_NEXT(base, next) && base->dp.n == 1);
    CHECK(!native_profile_next(&flow, "target"));
    CHECK(flow.count == 1 && flow.template_count == 1 && !flow.template && LIST_FIRST(&templates) == base);
    CHECK(base->next.le_prev == &templates.lh_first && flow.current->next.le_prev == &profiles.lh_first);
    CHECK(native_profile_import(&flow, "absent") == 3);
    CHECK(!native_profile_import(&flow, "base") && !strcmp(flow.current->dp.cookie, "inherited"));
    CHECK(flow.current->dp.n == 1 && !strcmp(flow.current->dp.name, "target"));
    CHECK(!native_profile_next(&flow, "base") && flow.count == 2 && flow.current->dp.n == 2);
    struct desync_profile_list *last = flow.current;
    flow.template = true;
    CHECK(native_profile_next(&flow, "uncommitted") == 2 && native_profile_finish(&flow) == 2);
    CHECK(flow.current == last && flow.template_count == 1 && flow.count == 2);
    flow.skip = true;
    failure = profile_config_ops;
    failure.duplicate = failing_duplicate;
    CHECK(zapret_profile_next(&flow, "fresh", &failure) == 1);
    CHECK(zapret_profile_label(&last->dp, false, "fresh", &failure) == 1);
    CHECK(flow.skip && flow.template && !strcmp(last->dp.name, "base"));
    CHECK(!native_profile_next(&flow, "fresh"));
    CHECK(flow.current == last && !flow.skip && !flow.template && flow.count == 2 && !strcmp(last->dp.name, "fresh"));
    CHECK(!last->dp.cookie && last->dp.n == 2);
    flow.skip = true;
    CHECK(!native_profile_finish(&flow) && !flow.current && flow.count == 1);
    CHECK(!LIST_NEXT(LIST_FIRST(&profiles), next));
    CHECK(!native_profile_next(&flow, "tail"));
    last = flow.current;
    flow.template = true;
    CHECK(!native_profile_finish(&flow) && flow.count == 1 && flow.template_count == 2 && !flow.current);
    CHECK(LIST_NEXT(base, next) == last && last->next.le_prev == &base->next.le_next && last->dp.n == 2);
    dp_list_destroy(&profiles);
    dp_list_destroy(&templates);
    CHECK(LIST_EMPTY(&profiles) && LIST_EMPTY(&templates));
    puts("PASS profile_flow operations=15 allocation_failures=3 duplicate_rejections=2");
}
int main(void)
{
    struct zapret_list_collection *dummy = NULL;
    automatic = zapret_list_register(&lists, &dummy, "automatic");
    CHECK(automatic);
    zapret_list_collection_destroy(&dummy);
    for (unsigned f = 0; f < 4096; ++f) {
        struct desync_profile a = {0}, b = {0}, source = {0};
        reference_dp_init(&a); dp_init(&b); dp_init(&source);
        populate(&a, 0); populate(&b, 0); populate(&source, 1);
        source.hostlist_auto_fail_threshold = 7;
        source.hostlist_auto_fail_time = 25;
        source.hostlist_auto_retrans_threshold = 6;
        source.hostlist_auto_retrans_maxseq = 456;
        source.hostlist_auto_incoming_maxseq = 123;
        source.hostlist_auto_retrans_reset = false;
        source.hostlist_auto_udp_in = 2;
        source.hostlist_auto_udp_out = 8;
        source.filter_ipv4 = true;
        source.filter_l7 = 8;
        bool *flags = &source.b_hostlist_auto_fail_threshold;
        for (unsigned k = 0; k < 10; ++k) flags[k] = !!(f & (1u << k));
        a.b_filter_l3 = b.b_filter_l3 = !!(f & 1024);
        a.filter_ipv6 = b.filter_ipv6 = true;
        if (f & 2048) source.hostlist_auto = automatic;
        CHECK(reference_dp_copy(&a, &source) && dp_copy(&b, &source));
        same(&a, &b);
        CHECK(reference_filter_defaults(&a) == filter_defaults(&b));
        same(&a, &b);
        reference_dp_clear(&a); dp_clear(&b); dp_clear(&source);
        ++cases;
    }
    import_failure();
    import_automatic_conflict();
    lifecycle();
    zapret_list_files_destroy(&lists);
    printf("PASS profile_config cases=%u atomic_failures=%u list_entries=16 ordered_copy_errors=18 automatic_conflicts=1\n", cases, faults);
    profile_flow();
    return 0;
}
