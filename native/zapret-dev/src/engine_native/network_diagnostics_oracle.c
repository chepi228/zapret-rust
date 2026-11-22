/* MIT. Windows vtables and BSTRs with private network and adapter fixtures. */
#include <netlistmgr.h>
#include <stdarg.h>
#undef main

static unsigned scenario, rows_read, names_read, adapter_reads, releases, resets, apartment;
#ifdef ZAPRET_DIRECT_NETWORK_REPORT
uint32_t w_win32_error;
#else
static uint32_t w_win32_error;
#endif
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL NLM listing scenario=%u line=%d: %s\n", scenario, __LINE__, #condition); exit(1); } \
} while (0)
static const GUID network_id = {0x43211234, 0xABCD, 0x1234, {0xAB,0xCD,7,6,5,4,3,2}};
static const GUID adapter_id = {0xF0012340, 0x1234, 0x4321, {0xAB,0xCD,0xEF,1,2,3,4,5}};
static INetworkListManager manager;
static INetwork networks[3];
static IEnumNetworks enumeration;
static INetworkConnection connections[2];
static IEnumNetworkConnections connection_enum;
static unsigned next_row, next_adapter;
static NLM_ENUM_NETWORK flags;

static HRESULT WINAPI fixture_initialize(LPVOID reserved) { CHECK(!reserved); ++apartment; return S_OK; }
static void WINAPI fixture_uninitialize(void) { CHECK(apartment == 1); --apartment; }
static HRESULT WINAPI fixture_create(REFCLSID clsid, IUnknown *outer, DWORD context, REFIID iid, void **out)
{
    CHECK(clsid && iid && !outer && context == CLSCTX_ALL);
    *out = &manager;
    return S_OK;
}
static ULONG WINAPI release_manager(INetworkListManager *self) { CHECK(self == &manager); return 0; }
static ULONG WINAPI release_enum(IEnumNetworks *self) { CHECK(self == &enumeration); ++releases; return 0; }
static ULONG WINAPI release_network(INetwork *self) { CHECK(self >= networks && self < networks + 3); ++releases; return 0; }
static ULONG WINAPI release_conn_enum(IEnumNetworkConnections *self) { CHECK(self == &connection_enum); ++releases; return 0; }
static ULONG WINAPI release_connection(INetworkConnection *self) { CHECK(self >= connections && self < connections + 2); ++releases; return 0; }
static HRESULT WINAPI get_networks(INetworkListManager *self, NLM_ENUM_NETWORK requested, IEnumNetworks **out)
{
    CHECK(self == &manager && (requested == NLM_ENUM_NETWORK_ALL || requested == NLM_ENUM_NETWORK_CONNECTED));
    next_row = 0;
    flags = requested;
    *out = &enumeration;
    return S_OK;
}
static HRESULT WINAPI next_network(IEnumNetworks *self, ULONG count, INetwork **out, ULONG *fetched)
{
    CHECK(self == &enumeration && count == 1);
    if (flags == NLM_ENUM_NETWORK_CONNECTED && next_row == 0) ++next_row;
    if (next_row >= 3) { if (fetched) *fetched = 0; return S_FALSE; }
    *out = &networks[next_row++];
    if (fetched) *fetched = 1;
    ++rows_read;
    return S_OK;
}
static HRESULT WINAPI reset_networks(IEnumNetworks *self) { CHECK(self == &enumeration); ++resets; next_row = 0; return S_OK; }
static HRESULT WINAPI get_connected(INetwork *self, VARIANT_BOOL *connected)
{ *connected = self == networks ? VARIANT_FALSE : VARIANT_TRUE; return S_OK; }
static HRESULT WINAPI get_internet(INetwork *self, VARIANT_BOOL *internet)
{ *internet = self == &networks[1] ? VARIANT_TRUE : VARIANT_FALSE; return S_OK; }
static HRESULT WINAPI get_id(INetwork *self, GUID *id)
{ *id = network_id; id->Data1 += (DWORD)(self - networks); return S_OK; }
static HRESULT WINAPI get_category(INetwork *self, NLM_NETWORK_CATEGORY *category)
{ *category = (NLM_NETWORK_CATEGORY)(self - networks); return S_OK; }
static HRESULT WINAPI get_name(INetwork *self, BSTR *name)
{
    static const WCHAR *const labels[] = {L"disconnected", L"connected", L"Вторая сеть"};
    ++names_read;
    if (scenario == 2 && self == &networks[1]) return E_ACCESSDENIED;
    if (scenario == 3 && self == &networks[1]) {
        WCHAR long_name[201];
        for (unsigned i = 0; i < 200; ++i) long_name[i] = L'X';
        long_name[200] = 0;
        *name = SysAllocString(long_name);
    } else {
        *name = SysAllocString(labels[self - networks]);
    }
    CHECK(*name);
    return S_OK;
}
static HRESULT WINAPI get_connections(INetwork *self, IEnumNetworkConnections **out)
{
    if (self != &networks[1]) return E_FAIL;
    next_adapter = 0;
    *out = &connection_enum;
    return S_OK;
}
static HRESULT WINAPI next_connection(IEnumNetworkConnections *self, ULONG count, INetworkConnection **out, ULONG *fetched)
{
    CHECK(self == &connection_enum && count == 1);
    if (next_adapter >= 2) { if (fetched) *fetched = 0; return S_FALSE; }
    *out = &connections[next_adapter++];
    if (fetched) *fetched = 1;
    return S_OK;
}
static HRESULT WINAPI get_adapter(INetworkConnection *self, GUID *out)
{
    ++adapter_reads;
    if (scenario == 1 && self == &connections[1]) return E_FAIL;
    *out = adapter_id;
    out->Data1 += (DWORD)(self - connections);
    return S_OK;
}

static INetworkListManagerVtbl manager_table = {.Release = release_manager, .GetNetworks = get_networks};
static IEnumNetworksVtbl enum_table = {.Release = release_enum, .Next = next_network, .Reset = reset_networks};
static INetworkVtbl network_table = {.Release = release_network, .GetName = get_name, .GetNetworkId = get_id,
    .GetNetworkConnections = get_connections, .get_IsConnectedToInternet = get_internet, .get_IsConnected = get_connected,
    .GetCategory = get_category};
static IEnumNetworkConnectionsVtbl conn_enum_table = {.Release = release_conn_enum, .Next = next_connection};
static INetworkConnectionVtbl connection_table = {.Release = release_connection, .GetAdapterId = get_adapter};

struct output { size_t length; bool fail; char bytes[4096]; };
static struct output legacy;
static bool fixture_write(void *context, const uint8_t *bytes, size_t count)
{
    struct output *out = context;
    if (out->fail) return false;
    CHECK(count < sizeof(out->bytes) - out->length);
    memcpy(out->bytes + out->length, bytes, count);
    out->length += count;
    out->bytes[out->length] = 0;
    return true;
}
static size_t lookup_name(void *context, const GUID *id, uint8_t *bytes, size_t length)
{
    (void)context;
    const char name[] = "Адаптер fixture";
    if (memcmp(id, &adapter_id, sizeof(*id)) || length < sizeof(name)) return 0;
    memcpy(bytes, name, sizeof(name));
    return sizeof(name) - 1;
}
static bool AdapterID2Name(const GUID *id, char *name, DWORD length)
{ return lookup_name(NULL, id, (uint8_t *)name, length) != 0; }
static int legacy_printf(const char *format, ...)
{
    char text[512];
    va_list args;
    va_start(args, format);
    int size = vsnprintf(text, sizeof(text), format, args);
    va_end(args);
    CHECK(size >= 0 && (size_t)size < sizeof(text));
    CHECK(fixture_write(&legacy, (const uint8_t *)text, (size_t)size));
    return size;
}
#define printf legacy_printf
#define CoInitialize fixture_initialize
#define CoUninitialize fixture_uninitialize
#define CoCreateInstance fixture_create
#define CLSID_NetworkListManager network_id
#define IID_INetworkListManager network_id
#define nlm_list reference_nlm_list
#include "network_diagnostics_reference.inc"
#undef printf
#undef nlm_list

bool zapret_nlm_test_list(void *, bool, void *, bool (*)(void *, const uint8_t *, size_t),
    size_t (*)(void *, const GUID *, uint8_t *, size_t), uint32_t *);

static void reset(void) { rows_read = names_read = adapter_reads = releases = resets = 0; }

#ifdef ZAPRET_DIRECT_NETWORK_REPORT
static FILE *report_stream;
static bool short_write;
static unsigned list_calls, stream_calls, storage_calls;

static bool report_model(bool all, void *context,
    bool (*write)(void *, const uint8_t *, size_t), uint32_t *error)
{
    CHECK(context == report_stream && error == &w_win32_error);
    ++list_calls;
    return zapret_nlm_test_list(&manager, all, context, write, lookup_name, error);
}

bool __wrap_zapret_network_environment_list(bool all, void *context,
    bool (*write)(void *, const uint8_t *, size_t), uint32_t *error)
{
    return report_model(all, context, write, error);
}

FILE *__real___acrt_iob_func(unsigned);
FILE *__wrap___acrt_iob_func(unsigned descriptor)
{
    if (descriptor != 1 || !report_stream) return __real___acrt_iob_func(descriptor);
    ++stream_calls;
    return report_stream;
}

size_t __real_fwrite(const void *, size_t, size_t, FILE *);
size_t __wrap_fwrite(const void *bytes, size_t size, size_t count, FILE *stream)
{
    if (stream == report_stream && count) {
        CHECK(size == 1);
        ++storage_calls;
        if (short_write) return count - 1;
    }
    return __real_fwrite(bytes, size, count, stream);
}

static FILE *fixture_stdout(void)
{
    return __wrap___acrt_iob_func(1);
}

#undef stdout
#define stdout fixture_stdout()
#define nlm_list c_nlm_list
#define zapret_network_environment_list report_model
#include "network_diagnostics_windows.inc"
#undef zapret_network_environment_list
#undef nlm_list
#undef stdout
#define stdout (__acrt_iob_func(1))

bool nlm_list(bool);
static unsigned compare_stdio(void)
{
    unsigned comparisons = 0;
    for (scenario = 0; scenario < 4; ++scenario)
        for (unsigned all = 0; all < 2; ++all)
            for (unsigned short_output = 0; short_output < 2; ++short_output) {
                char bytes[2][4096];
                size_t lengths[2];
                bool status[2];
                uint32_t errors[2];
                short_write = short_output;
                unsigned previous = list_calls;
                for (unsigned side = 0; side < 2; ++side) {
                    report_stream = tmpfile();
                    CHECK(report_stream);
                    unsigned stream = stream_calls, storage = storage_calls;
                    status[side] = side ? nlm_list(all) : c_nlm_list(all);
                    errors[side] = w_win32_error;
                    CHECK(stream_calls == stream + 1);
                    CHECK((storage_calls > storage) == (scenario != 2));
                    CHECK(!fflush(report_stream) && !fseek(report_stream, 0, SEEK_SET));
                    lengths[side] = fread(bytes[side], 1, sizeof(bytes[side]), report_stream);
                    CHECK(!ferror(report_stream) && !fclose(report_stream));
                    report_stream = NULL;
                }
                CHECK(list_calls == previous + 2 && status[0] == status[1] && errors[0] == errors[1]);
                CHECK(lengths[0] == lengths[1] && !memcmp(bytes[0], bytes[1], lengths[0]));
                if (scenario == 2) {
                    CHECK(!status[1] && !lengths[1] && errors[1] == (uint32_t)E_ACCESSDENIED);
                } else if (short_write) {
                    CHECK(!status[1] && !lengths[1]);
                    CHECK(errors[1] == (uint32_t)HRESULT_FROM_WIN32(ERROR_WRITE_FAULT));
                } else CHECK(lengths[1]);
                ++comparisons;
            }
    return comparisons;
}
#endif

int main(void)
{
    manager.lpVtbl = &manager_table;
    enumeration.lpVtbl = &enum_table;
    connection_enum.lpVtbl = &conn_enum_table;
    for (unsigned i = 0; i < 3; ++i) networks[i].lpVtbl = &network_table;
    for (unsigned i = 0; i < 2; ++i) connections[i].lpVtbl = &connection_table;
    unsigned cases = 0;
    for (scenario = 0; scenario < 3; ++scenario) for (unsigned all = 0; all <= 1; ++all) {
        legacy = (struct output){0};
        struct output rust = {0};
        reset();
        bool expected = reference_nlm_list(all);
        uint32_t expected_error = w_win32_error, error = 0;
        CHECK(!apartment);
        if (scenario != 2) CHECK(rows_read == (all ? 6 : 3) && resets == (all ? 2 : 1));
        reset();
        CHECK(zapret_nlm_test_list(&manager, all, &rust, fixture_write, lookup_name, &error) == expected);
        CHECK(legacy.length == rust.length && !memcmp(legacy.bytes, rust.bytes, legacy.length));
        if (scenario == 2) CHECK(error == expected_error && error == (uint32_t)E_ACCESSDENIED);
        else {
            CHECK(!error && !resets && rows_read == (all ? 3 : 2) && names_read == rows_read && adapter_reads == 2);
            CHECK(releases == rows_read + 4);
        }
        ++cases;
    }
    scenario = 3;
    uint32_t error = 0;
    struct output out = {0};
    CHECK(zapret_nlm_test_list(&manager, false, &out, fixture_write, lookup_name, &error));
    CHECK(out.length > 200 && strstr(out.bytes, " (connected) (inet) (private)"));
    scenario = 4;
    out = (struct output){.fail = true};
    reset();
    CHECK(!zapret_nlm_test_list(&manager, true, &out, fixture_write, lookup_name, &error));
    CHECK(error == (uint32_t)HRESULT_FROM_WIN32(ERROR_WRITE_FAULT) && releases == 3 && !adapter_reads);
    CHECK(!zapret_nlm_test_list(NULL, true, &out, fixture_write, lookup_name, &error) && error == (uint32_t)E_POINTER);
    unsigned direct = 0;
#ifdef ZAPRET_DIRECT_NETWORK_REPORT
    direct = compare_stdio();
#endif
    printf("PASS network_listing cases=%u extended_names=1 write_failures=1 null_manager=1 rust_stdio=%u\n",
        cases, direct);
    return 0;
}
