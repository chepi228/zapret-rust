/* MIT. All files and allocator faults belong to this private fixture. */
#include <setjmp.h>
#include <stdarg.h>
#include "params.h"
#include "helpers.h"
#ifdef ZAPRET_BLOB_INPUT_DIRECT
void *__wrap_malloc(size_t size);
void __wrap_free(void *pointer);
#define malloc __wrap_malloc
#define free __wrap_free
#endif
#include "blob_windows.h"
#ifdef ZAPRET_BLOB_INPUT_DIRECT
#undef malloc
#undef free
#endif
#undef main
#undef DLOG
#undef DLOG_ERR
#ifndef ZAPRET_BLOB_INPUT_DIRECT
static int blob_fixture_log(const char *format, ...) { (void)format; return 0; }
#define DLOG blob_fixture_log
#define DLOG_ERR blob_fixture_log
#endif

static unsigned cases, fault_checks, raw_checks, invalid_checks, scenario;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL engine blob case=%u scenario=%u line=%d: %s\n", cases, scenario, __LINE__, #condition); \
    exit(1); } } while (0)
static jmp_buf escape;
#ifdef ZAPRET_BLOB_INPUT_DIRECT
static jmp_buf binding_escape;
static bool observe_exit;
#endif
static void exit_clean(int code)
{
#ifdef ZAPRET_BLOB_INPUT_DIRECT
    if (observe_exit) longjmp(binding_escape, code);
#endif
    longjmp(escape, code);
}
struct tm *zapret_localtime_r(const time_t *value, struct tm *output) { CHECK(false); return NULL; }
#include "blob_reference.inc"
#ifdef ZAPRET_BLOB_INPUT_DIRECT
#define load_file_or_exit prior_load_file_or_exit
#define load_blob_to_collection prior_load_blob_to_collection
#define native_publish_const_blob prior_publish_const_blob
#endif
#include "blob_input_windows.inc"
#ifdef ZAPRET_BLOB_INPUT_DIRECT
#undef load_file_or_exit
#undef load_blob_to_collection
#undef native_publish_const_blob
#include "engine_blob_input_abi.h"

static void load_file_or_exit(const char *argument, void *buffer, size_t *size)
{
    if (!zapret_native_blob_read_fixed(argument, buffer, size)) exit_clean(1);
}

static struct blob_item *load_blob_to_collection(const char *argument,
    struct blob_collection_head *head, size_t maximum, size_t reserve)
{
    struct blob_item *item = zapret_native_blob_read_named(head, argument, maximum, reserve);
    CHECK(item);
    return item;
}
#endif

static unsigned allocations, active, fail_at;
static bool replace_input;
static const char contents[] = "\x00\x80\x0d\x0a\xff\x01\x07\x00";
static void write_fixture(const char *path, const char *data, size_t length)
{
    FILE *file = fopen(path, "wb");
    CHECK(file);
    CHECK(fwrite(data, 1, length, file) == length);
    CHECK(!fclose(file));
}
static void *allocate(size_t size)
{
    if (++allocations == fail_at) return NULL;
    if (replace_input) {
        replace_input = false;
        CHECK(MoveFileExW(L"swap.fixture", L"swapped.fixture", 0));
        write_fixture("swap.fixture", "new", 3);
    }
    void *pointer = malloc(size);
    CHECK(pointer);
    ++active;
    memset(pointer, 0x9a, size);
    return pointer;
}
static void release(void *pointer)
{
    if (pointer) { CHECK(active); --active; }
    free(pointer);
}
static const zapret_blob_allocator allocator = {allocate, release};

static void same_blob(const struct blob_item *expected, const struct blob_item *observed)
{
    CHECK(expected && observed);
    CHECK(expected->size == observed->size && expected->size_buf == observed->size_buf);
    CHECK((!expected->name && !observed->name) || (expected->name && observed->name && !strcmp(expected->name, observed->name)));
    CHECK(!observed->extra);
    if (observed->size) CHECK(!memcmp(expected->data, observed->data, observed->size));
}

static void named_checks(void)
{
    struct blob_collection_head legacy = {0}, rust = {0};
    char text[200];
    for (scenario = 0; scenario < 2048; ++scenario) {
        unsigned digits = 2 * (scenario % 60 + 1);
        size_t name_size = (size_t)snprintf(text, sizeof(text), "test_%u:0x", scenario);
        for (size_t i = 0; i < digits; ++i) text[name_size + i] = "0123456789AbCdEf"[(i * 17 + scenario) % 16];
        text[name_size + digits] = 0;
        size_t max_hex = 1 + scenario % 61, reserve = scenario % 11;
        struct blob_item *c = reference_load_blob_to_collection(text, &legacy, max_hex, reserve);
        struct blob_item *r = load_blob_to_collection(text, &rust, max_hex, reserve);
        same_blob(c, r);
        CHECK(zapret_blob_find(&rust, r->name) == r && *r->next.le_prev == r);
        ++cases;
        if (!(scenario % 16)) { reference_blob_collection_destroy(&legacy); zapret_blob_destroy_list(&rust, &native_blob_allocator); }
    }
    struct blob_item *c = LIST_FIRST(&legacy), *r = LIST_FIRST(&rust);
    struct blob_item **previous = &rust.lh_first;
    for (; c && r; c = LIST_NEXT(c, next), r = LIST_NEXT(r, next)) {
        same_blob(c, r);
        CHECK(r->next.le_prev == previous);
        previous = &r->next.le_next;
    }
    CHECK(!c && !r);
    reference_blob_collection_destroy(&legacy);
    zapret_blob_destroy_list(&rust, &native_blob_allocator);
    CHECK(LIST_EMPTY(&legacy) && LIST_EMPTY(&rust));
}

static void file_checks(void)
{
    write_fixture("данные blob.fixture", contents, sizeof(contents) - 1);
    write_fixture("empty.fixture", "", 0);
    static const char *const names[] = {
        "all:@данные blob.fixture", "part:+3@данные blob.fixture", "same:данные blob.fixture",
        "empty:empty.fixture", "empty_seek:+1@empty.fixture", "hex:0x000D0A800b"
    };
    struct blob_collection_head legacy = {0}, rust = {0};
    for (scenario = 0; scenario < sizeof(names) / sizeof(*names); ++scenario) {
        struct blob_item *c = reference_load_blob_to_collection(names[scenario], &legacy, 32, 21);
        struct blob_item *r = load_blob_to_collection(names[scenario], &rust, 32, 21);
        same_blob(c, r);
        ++cases;
    }
    same_blob(reference_load_const_blob_to_collection("constant", contents, sizeof(contents), &legacy, 16),
        native_publish_const_blob(&rust, "constant", contents, sizeof(contents), 16));
    same_blob(reference_blob_collection_add_blob(&legacy, contents, sizeof(contents), 11),
        zapret_blob_add(&rust, &native_blob_allocator, contents, sizeof(contents), 11));
    cases += 2;
    reference_blob_collection_destroy(&legacy);
    while (!LIST_EMPTY(&rust)) {
        struct blob_item *entry = zapret_blob_pop(&rust);
        CHECK(!entry->next.le_next && !entry->next.le_prev);
        CHECK(LIST_EMPTY(&rust) || LIST_FIRST(&rust)->next.le_prev == &rust.lh_first);
        zapret_blob_destroy(entry, &native_blob_allocator);
    }
    CHECK(!zapret_blob_pop(&rust));

    static const char *const raw[] = {"данные blob.fixture", "@данные blob.fixture", "+2@данные blob.fixture",
        "+18@данные blob.fixture", "empty.fixture", "0x80ff00", "0x12345678"};
    for (scenario = 0; scenario < sizeof(raw) / sizeof(*raw); ++scenario) {
        for (size_t limit = 1; limit <= 25; ++limit) {
            uint8_t c[32], r[32];
            memset(c, 0x6f, sizeof(c));
            memcpy(r, c, sizeof(c));
            size_t c_size = limit, r_size = limit;
            reference_load_file_or_exit(raw[scenario], c, &c_size);
            load_file_or_exit(raw[scenario], r, &r_size);
            CHECK(c_size == r_size && !memcmp(c, r, sizeof(c)));
            ++raw_checks;
        }
    }

    write_fixture("swap.fixture", contents, sizeof(contents) - 1);
    zapret_blob_input input = {0};
    struct blob_item *entry = NULL;
    replace_input = true;
    CHECK(!zapret_blob_load_named(&rust, "swap:+2@swap.fixture", 32, 9, &allocator, &input, &entry));
    CHECK(!replace_input && entry == LIST_FIRST(&rust) && entry->size == sizeof(contents) - 3);
    CHECK(!memcmp(entry->data, contents + 2, entry->size));
    CHECK(entry->size_buf == entry->size + 9 && active == 3);
    zapret_blob_destroy_list(&rust, &allocator);
    CHECK(!active);
}

static void error_checks(void)
{
    struct blob_collection_head head = {0};
    struct blob_item *stable = NULL;
    CHECK(!zapret_blob_load_const(&head, "stable", contents, sizeof(contents), 0, &allocator, &stable));
    CHECK(active == 3);
    struct blob_item snapshot = *stable;
    for (scenario = 1; scenario <= 3; ++scenario) {
        fail_at = allocations + scenario;
        zapret_blob_input input = {0};
        struct blob_item *entry = stable;
        CHECK(zapret_blob_load_named(&head, "failed:0x0012", 16, 2, &allocator, &input, &entry) == BLOB_ALLOCATION);
        CHECK(active == 3 && entry == stable && LIST_FIRST(&head) == stable && !memcmp(stable, &snapshot, sizeof(snapshot)));
        ++fault_checks;
    }
    fail_at = 0;
    static const struct { const char *name; uint32_t status; size_t reserve; } invalid[] = {
        {"9invalid:0x11", BLOB_IDENTIFIER, 0}, {":0x12", BLOB_IDENTIFIER, 0},
        {"valid", BLOB_ACCESS, 0}, {"a:missing.fixture", BLOB_ACCESS, 0}, {"a:.", BLOB_ACCESS, 0},
        {"stable:0x12", BLOB_DUPLICATE, 0}, {"a:+x@empty.fixture", BLOB_OFFSET, 0},
        {"a:+18446744073709551615@empty.fixture", BLOB_OFFSET, 0},
        {"a:+8@данные blob.fixture", BLOB_BEYOND_END, 0}, {"a:0x", BLOB_HEX, 0},
        {"a:0xa", BLOB_HEX, 0}, {"a:0x12@0", BLOB_HEX, 0}, {"a:0x12", BLOB_SIZE, SIZE_MAX},
    };
    for (scenario = 0; scenario < sizeof(invalid) / sizeof(*invalid); ++scenario) {
        zapret_blob_input input = {0};
        struct blob_item *entry = stable;
        CHECK(zapret_blob_load_named(&head, invalid[scenario].name, 32, invalid[scenario].reserve, &allocator, &input, &entry) == invalid[scenario].status);
        CHECK(active == 3 && entry == stable && LIST_FIRST(&head) == stable && !memcmp(stable, &snapshot, sizeof(snapshot)));
        ++invalid_checks;
    }
    struct blob_item *entry = NULL;
    CHECK(zapret_blob_load_const(&head, "stable", contents, 1, 0, &allocator, &entry) == BLOB_DUPLICATE && !entry);
    CHECK(!zapret_blob_add(&head, &allocator, contents, SIZE_MAX, 1));
    zapret_blob_destroy_list(&head, &allocator);
    CHECK(!active && LIST_EMPTY(&head));
}

#ifdef ZAPRET_BLOB_INPUT_DIRECT
struct params_s params;
static unsigned binding_cases, binding_faults;
static struct blob_collection_head prior_blobs;

struct binding_sample {
    char trace[1024], name[80];
    unsigned allocations;
    int error;
    size_t size, capacity;
    unsigned char data[64];
    bool ok;
};

static struct binding_sample *observed;
static unsigned binding_fail_at;
void *__real_malloc(size_t size);
void __real_free(void *pointer);

static void append_trace(const char *format, ...)
{
    if (!observed) return;
    int previous_error = errno;
    size_t length = strlen(observed->trace);
    va_list args;
    va_start(args, format);
    int count = vsnprintf(observed->trace + length, sizeof(observed->trace) - length, format, args);
    va_end(args);
    CHECK(count >= 0 && (size_t)count < sizeof(observed->trace) - length);
    errno = previous_error;
}

void *__wrap_malloc(size_t size)
{
    if (observed) {
        bool fail = ++observed->allocations == binding_fail_at;
        append_trace("malloc:%zu:%u;", size, fail);
        if (fail) { errno = ENOMEM; return NULL; }
    }
    return __real_malloc(size);
}

void __wrap_free(void *pointer)
{
    append_trace("free:%u;", pointer != NULL);
    __real_free(pointer);
}

static int fixture_log(bool error, const char *format, va_list args)
{
    if (!observed) return 0;
    char message[384];
    int previous_error = errno;
    int size = vsnprintf(message, sizeof(message), format, args);
    CHECK(size >= 0 && (size_t)size < sizeof(message));
    append_trace("%s:%s;", error ? "error" : "debug", message);
    errno = previous_error;
    return size;
}

int DLOG(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int count = fixture_log(false, format, args);
    va_end(args);
    return count;
}

int DLOG_ERR(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int count = fixture_log(true, format, args);
    va_end(args);
    return count;
}

static bool prior_named(struct blob_collection_head *head, const char *text, size_t maximum, size_t reserve)
{
    observe_exit = true;
    int code = setjmp(binding_escape);
    if (!code) prior_load_blob_to_collection(text, head, maximum, reserve);
    observe_exit = false;
    CHECK(code == 0 || code == 1);
    return !code;
}

static bool fixed_guard(bool rust, const char *text, unsigned char *data, size_t *size)
{
    observe_exit = true;
    int code = setjmp(binding_escape);
    if (!code) {
        if (rust) load_file_or_exit(text, data, size);
        else prior_load_file_or_exit(text, data, size);
    }
    observe_exit = false;
    CHECK(code == 0 || code == 1);
    return !code;
}

static void begin_binding(struct binding_sample *sample, unsigned failure)
{
    memset(sample, 0, sizeof(*sample));
    observed = sample;
    binding_fail_at = failure;
    errno = 71;
}

static struct binding_sample observe_named(bool rust, const char *text, size_t maximum,
    size_t reserve, unsigned failure, bool constant)
{
    struct blob_collection_head *head = rust ? &params.blobs : &prior_blobs;
    struct blob_item *previous = NULL;
    CHECK(LIST_EMPTY(head));
    CHECK(!zapret_blob_load_const(head, "stable", contents, sizeof(contents), 1,
        &native_blob_allocator, &previous));
    struct blob_item snapshot = *previous;

    struct binding_sample sample;
    begin_binding(&sample, failure);
    if (constant) {
        struct blob_item *entry = rust
            ? native_publish_const_blob(head, text, contents, sizeof(contents), reserve)
            : prior_publish_const_blob(head, text, contents, sizeof(contents), reserve);
        sample.ok = entry != NULL;
    } else if (rust) {
        sample.ok = zapret_native_cli_read_blob(text, maximum, reserve);
    } else {
        sample.ok = prior_named(head, text, maximum, reserve);
    }
    sample.error = errno;
    observed = NULL;
    if (sample.ok) {
        struct blob_item *item = LIST_NEXT(previous, next);
        CHECK(LIST_FIRST(head) == previous && item && !LIST_NEXT(item, next) && !item->extra);
        CHECK(previous->next.le_prev == &head->lh_first && item->next.le_prev == &previous->next.le_next);
        CHECK(item->size <= sizeof(sample.data) && strlen(item->name) < sizeof(sample.name));
        sample.size = item->size;
        sample.capacity = item->size_buf;
        if (item->size) memcpy(sample.data, item->data, item->size);
        strcpy(sample.name, item->name);
    } else {
        CHECK(LIST_FIRST(head) == previous && !memcmp(previous, &snapshot, sizeof(snapshot)));
    }
    zapret_blob_destroy_list(head, &native_blob_allocator);
    CHECK(LIST_EMPTY(head));
    return sample;
}

static struct binding_sample observe_fixed(bool rust, const char *text, size_t limit)
{
    struct binding_sample sample;
    begin_binding(&sample, 0);
    sample.size = limit;
    memset(sample.data, 0xa5, sizeof(sample.data));
    sample.ok = fixed_guard(rust, text, sample.data, &sample.size);
    sample.error = errno;
    observed = NULL;
    return sample;
}

static void binding_checks(void)
{
    const char *named[] = {"new:0x6162", "stable:0x1a", "9bad:0x31", "a:0xa", "a:+x@empty.fixture",
        "a:missing.fixture", "a:+4@данные blob.fixture", "a:+32@данные blob.fixture", "a:empty.fixture"};
    for (size_t i = 0; i < sizeof(named) / sizeof(*named); ++i)
        for (unsigned fault = 0; fault < 4; ++fault) {
            struct binding_sample before = observe_named(false, named[i], 64, 4, fault, false);
            struct binding_sample after = observe_named(true, named[i], 64, 4, fault, false);
            CHECK(!memcmp(&before, &after, sizeof(before)));
            if (fault && after.allocations >= fault) { CHECK(!after.ok); ++binding_faults; }
            ++binding_cases;
        }
    const char *fixed[] = {"+2@данные blob.fixture", "0x616263", "empty.fixture", "@missing.fixture", "0xa"};
    for (size_t i = 0; i < sizeof(fixed) / sizeof(*fixed); ++i)
        for (size_t limit = 1; limit < 6; ++limit) {
            struct binding_sample before = observe_fixed(false, fixed[i], limit);
            struct binding_sample after = observe_fixed(true, fixed[i], limit);
            CHECK(!memcmp(&before, &after, sizeof(before)));
            ++binding_cases;
        }
    const char *names[] = {"constant", "stable"};
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i)
        for (unsigned fault = 0; fault < 4; ++fault) {
            struct binding_sample before = observe_named(false, names[i], 0, 4, fault, true);
            struct binding_sample after = observe_named(true, names[i], 0, 4, fault, true);
            CHECK(!memcmp(&before, &after, sizeof(before)));
            if (fault && after.allocations >= fault) { CHECK(!after.ok); ++binding_faults; }
            ++binding_cases;
        }
    CHECK(binding_faults > 0);
}
#endif

int main(void)
{
    if (setjmp(escape)) { CHECK(false); }
    named_checks();
    file_checks();
    error_checks();
#ifdef ZAPRET_BLOB_INPUT_DIRECT
    binding_checks();
    printf("PASS engine_blobs cases=%u raw_reads=%u invalid_inputs=%u allocation_faults=%u replaced_files=1 "
        "rust_binding=1 binding_cases=%u binding_faults=%u exact_logs=1 nonterminating_cli=1\n",
        cases, raw_checks, invalid_checks, fault_checks, binding_cases, binding_faults);
#else
    printf("PASS engine_blobs cases=%u raw_reads=%u invalid_inputs=%u allocation_faults=%u replaced_files=1\n",
        cases, raw_checks, invalid_checks, fault_checks);
#endif
    return 0;
}
