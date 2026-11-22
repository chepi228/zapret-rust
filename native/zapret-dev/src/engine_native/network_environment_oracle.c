/* MIT. Real Windows layouts with deterministic private COM and WLAN fixtures. */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wlanapi.h>
#include <netlistmgr.h>
#include "params.h"
#undef main
uint32_t w_win32_error;
static unsigned cases, scenario, opens, closes, frees, nexts, releases;
#define CHECK(condition) do { \
    if (!(condition)) { fprintf(stderr, "FAIL network environment case %u scenario %u line %d: %s\n", \
        cases, scenario, __LINE__, #condition); exit(1); } \
} while (0)

static const GUID id = {0x12345678, 0x9abc, 0xdef0, {1, 2, 3, 4, 5, 6, 7, 8}};
static INetworkListManager manager;
static IEnumNetworks enumeration;
static INetwork network;
static INetworkListManager *pNetworkListManager = &manager;
static ULONG STDMETHODCALLTYPE enum_release(IEnumNetworks *self) { CHECK(self == &enumeration); ++releases; return 0; }
static ULONG STDMETHODCALLTYPE network_release(INetwork *self) { CHECK(self == &network); ++releases; return 0; }
static HRESULT STDMETHODCALLTYPE get_networks(INetworkListManager *self, NLM_ENUM_NETWORK flags, IEnumNetworks **out)
{
    CHECK(self == &manager && flags == NLM_ENUM_NETWORK_CONNECTED);
    nexts = 0;
    if (scenario == 1) return E_ACCESSDENIED;
    *out = &enumeration;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE next_network(IEnumNetworks *self, ULONG count, INetwork **out, ULONG *fetched)
{
    CHECK(self == &enumeration && count == 1);
    if (scenario == 2) return E_FAIL;
    if (++nexts > (scenario == 3 ? 0 : 2)) {
        if (fetched) *fetched = 0;
        return S_FALSE;
    }
    *out = &network;
    if (fetched) *fetched = 1;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE get_id(INetwork *self, GUID *out)
{
    CHECK(self == &network);
    if (scenario == 4) return E_FAIL;
    *out = id;
    if (nexts == 1) out->Data1 = 0;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE get_name(INetwork *self, BSTR *out)
{
    CHECK(self == &network);
    if (scenario == 5) return E_FAIL;
    WCHAR name[160] = L"fixture";
    if (nexts == 1) wcscpy(name, L"other");
    if (scenario == 6) {
        for (unsigned i = 0; i < 150; ++i) name[i] = L'x';
        name[150] = 0;
    }
    *out = SysAllocString(name);
    CHECK(*out);
    return S_OK;
}
static INetworkListManagerVtbl manager_table = {.GetNetworks = get_networks};
static IEnumNetworksVtbl enum_table = {.Release = enum_release, .Next = next_network};
static INetworkVtbl network_table = {.Release = network_release, .GetName = get_name, .GetNetworkId = get_id};

static void *wlan_fixture_allocate(size_t bytes)
{
    // Some SDKs declare InterfaceInfo as a flexible array and sizeof(list)
    // covers only the two DWORD fields. Keep explicit space for both entries.
    uint8_t *memory = malloc(bytes + 32);
    CHECK(memory);
    memset(memory, 0x5a, bytes + 32);
    memcpy(memory, &bytes, sizeof(bytes));
    memset(memory + 16, 0, bytes);
    return memory + 16;
}
static void wlan_fixture_free(void *pointer)
{
    uint8_t *memory = (uint8_t *)pointer - 16;
    size_t bytes;
    memcpy(&bytes, memory, sizeof(bytes));
    for (size_t index = sizeof(bytes); index < 16; ++index) CHECK(memory[index] == 0x5a);
    for (size_t index = 0; index < 16; ++index) CHECK(memory[16 + bytes + index] == 0x5a);
    free(memory);
}

static DWORD WINAPI wlan_open(DWORD requested, PVOID reserved, PDWORD negotiated, PHANDLE out)
{
    CHECK(requested == 2 && !reserved);
    ++opens;
    if (scenario == 1) return ERROR_ACCESS_DENIED;
    *negotiated = 2;
    *out = (HANDLE)(uintptr_t)41;
    return 0;
}
static DWORD WINAPI wlan_close(HANDLE handle, PVOID reserved)
{
    CHECK(handle == (HANDLE)(uintptr_t)41 && !reserved);
    ++closes;
    return 0;
}
static DWORD WINAPI wlan_enumerate(HANDLE handle, PVOID reserved, PWLAN_INTERFACE_INFO_LIST *out)
{
    CHECK(handle == (HANDLE)(uintptr_t)41 && !reserved);
    if (scenario == 2) return ERROR_NOT_READY;
    WLAN_INTERFACE_INFO_LIST *list = wlan_fixture_allocate(offsetof(WLAN_INTERFACE_INFO_LIST, InterfaceInfo) +
        2 * sizeof(list->InterfaceInfo[0]));
    CHECK(list);
    list->dwNumberOfItems = 2;
    list->InterfaceInfo[0].isState = wlan_interface_state_connected;
    list->InterfaceInfo[1].isState = wlan_interface_state_connected;
    list->InterfaceInfo[1].InterfaceGuid.Data1 = 1;
    if (scenario == 3) list->InterfaceInfo[1].isState = wlan_interface_state_disconnected;
    *out = list;
    return 0;
}
static DWORD WINAPI wlan_query(HANDLE handle, const GUID *guid, WLAN_INTF_OPCODE opcode, PVOID reserved,
    PDWORD size, PVOID *out, PWLAN_OPCODE_VALUE_TYPE value_type)
{
    CHECK(handle == (HANDLE)(uintptr_t)41 && opcode == wlan_intf_opcode_current_connection && !reserved && !value_type);
    if (scenario == 4) return ERROR_ACCESS_DENIED;
    WLAN_CONNECTION_ATTRIBUTES *connection = wlan_fixture_allocate(sizeof(*connection));
    CHECK(connection);
    const char *ssid = guid->Data1 ? "fixture" : "other";
    if (scenario == 5) ssid = "";
    memcpy(connection->wlanAssociationAttributes.dot11Ssid.ucSSID, ssid, strlen(ssid));
    connection->wlanAssociationAttributes.dot11Ssid.uSSIDLength = (ULONG)strlen(ssid);
    if (scenario == 6) connection->wlanAssociationAttributes.dot11Ssid.uSSIDLength = 33;
    *size = scenario == 7 ? 1 : sizeof(*connection);
    *out = connection;
    return 0;
}
static void WINAPI wlan_free(PVOID pointer) { CHECK(pointer); ++frees; wlan_fixture_free(pointer); }
static const void *reserved_ops = NULL;
#define f_WlanOpenHandle wlan_open
#define f_WlanCloseHandle wlan_close
#define f_WlanEnumInterfaces wlan_enumerate
#define f_WlanQueryInterface wlan_query
#define f_WlanFreeMemory wlan_free
#include "guid_reference.inc"
#include "network_environment_reference.inc"

typedef struct {
    DWORD (WINAPI *open)(DWORD, PVOID, PDWORD, PHANDLE);
    DWORD (WINAPI *close)(HANDLE, PVOID);
    DWORD (WINAPI *enumerate)(HANDLE, PVOID, PWLAN_INTERFACE_INFO_LIST *);
    DWORD (WINAPI *query)(HANDLE, const GUID *, WLAN_INTF_OPCODE, PVOID, PDWORD, PVOID *, PWLAN_OPCODE_VALUE_TYPE);
    void (WINAPI *release)(PVOID);
} fixture_wlan_ops;
bool zapret_wlan_match(const fixture_wlan_ops *, const struct str_list_head *, uint32_t *);
bool zapret_nlm_match(void *, const struct str_list_head *, uint32_t *);
bool zapret_network_environment_init(void **, bool, bool, uint32_t *);
void zapret_network_environment_destroy(void **);
bool zapret_network_environment_wlan(const void *, const struct str_list_head *, uint32_t *);
bool zapret_network_environment_nlm(const void *, const struct str_list_head *, uint32_t *);

struct snapshot {
    unsigned opens, closes, frees, nexts, releases;
    uint32_t error;
    bool match;
};
static void reset(void)
{
    w_win32_error = 73;
    opens = closes = frees = nexts = releases = 0;
}
static struct snapshot capture(bool match)
{
    return (struct snapshot){opens, closes, frees, nexts, releases, w_win32_error, match};
}
int main(void)
{
    manager.lpVtbl = &manager_table;
    enumeration.lpVtbl = &enum_table;
    network.lpVtbl = &network_table;
    fixture_wlan_ops ops = {wlan_open, wlan_close, wlan_enumerate, wlan_query, wlan_free};
    static const char *const patterns[] = {"fixture", "absent", "", "12345678-9ABC-DEF0-0102-030405060708",
        "12345678-9abc-def0-0102-030405060708", "12345678-9abc-def0-0102-03040506070Z"};
    for (unsigned p = 0; p < sizeof(patterns) / sizeof(*patterns); ++p) {
        struct str_list list_entry = {.str = (char *)patterns[p]}, extra = {.str = "other"};
        for (unsigned mode = 0; mode < 4; ++mode) {
            struct str_list_head head = {0};
            if (mode) LIST_INSERT_HEAD(&head, &list_entry, next);
            if (mode == 2) LIST_INSERT_HEAD(&head, &extra, next);
            const struct str_list_head *filter = mode == 3 ? NULL : &head;
            for (scenario = 0; scenario <= 6; ++scenario) {
                reset();
                struct snapshot c = capture(nlm_filter_match(filter));
                reset();
                struct snapshot r = capture(zapret_nlm_match(&manager, filter, &w_win32_error));
                CHECK(c.match == r.match && c.releases == r.releases && c.nexts == r.nexts);
                CHECK(c.error == r.error || (!c.match && c.error == S_FALSE && !r.error));
                ++cases;
            }
            for (scenario = 0; scenario <= 5; ++scenario) {
                reset();
                struct snapshot c = capture(wlan_filter_match(filter));
                reset();
                struct snapshot r = capture(zapret_wlan_match(&ops, filter, &w_win32_error));
                CHECK(c.match == r.match && c.error == r.error && c.opens == r.opens && c.closes == r.closes && c.frees == r.frees);
                ++cases;
            }
        }
    }
    struct str_list entry = {.str = "fixture"};
    struct str_list_head head = {0};
    LIST_INSERT_HEAD(&head, &entry, next);
    for (scenario = 6; scenario <= 7; ++scenario) {
        reset();
        CHECK(!zapret_wlan_match(&ops, &head, &w_win32_error));
        CHECK(w_win32_error == ERROR_INVALID_DATA && closes == 1 && frees == 2);
    }
    void *environment = NULL;
    CHECK(zapret_network_environment_init(&environment, false, false, &w_win32_error) && environment && !w_win32_error);
    CHECK(zapret_network_environment_wlan(environment, NULL, &w_win32_error) && !w_win32_error);
    CHECK(zapret_network_environment_nlm(environment, NULL, &w_win32_error) && !w_win32_error);
    CHECK(!zapret_network_environment_wlan(environment, &head, &w_win32_error) && w_win32_error == (uint32_t)E_POINTER);
    zapret_network_environment_destroy(&environment);
    zapret_network_environment_destroy(&environment);
    CHECK(!environment);
    printf("PASS network_environment cases=%u wlan_boundaries=2 environment_cases=5\n", cases);
    return 0;
}
