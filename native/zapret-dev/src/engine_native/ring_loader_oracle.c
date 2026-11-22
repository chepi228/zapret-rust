/* Compare the complete original C loader with Rust on controlled SDK calls. */
#include <stdbool.h>
#include <stdlib.h>
#include <wchar.h>
#include "ring_loader_types.inc"
static const char real_pin[] = RUST_RING_DLL_SHA256;

enum { FILENAME = 1, OPEN, FILE_SIZE, PROVIDER, HASH, READ, UPDATE, FINISH, LOAD, SYMBOL, GET,
    UNLOAD, DESTROY, CLOSE_PROVIDER, CLOSE_FILE };
static unsigned path_shape, size_shape, pin_shape, api_shape, fault, keep_partial, reads, cases;
static unsigned steps, guard_cases;
static uint64_t trace;
static uint8_t bytes[32];
static const char *selected_pin;
static rr_api mock_api;
static void *guard;
static SYSTEM_INFO system_info;
static const HANDLE file = (HANDLE)(uintptr_t)11;
static const HMODULE module = (HMODULE)(uintptr_t)22;
static const BCRYPT_ALG_HANDLE algorithm = (BCRYPT_ALG_HANDLE)(uintptr_t)33;
static const BCRYPT_HASH_HANDLE hasher = (BCRYPT_HASH_HANDLE)(uintptr_t)44;

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "FAIL ring_loader case=%u path=%u size=%u pin=%u abi=%u fault=%u line=%d: %s\n", \
        cases, path_shape, size_shape, pin_shape, api_shape, fault, __LINE__, #x); exit(1); \
} } while(0)
static void mix(uint64_t value) { trace = (trace ^ value) * UINT64_C(1099511628211); }
static bool observe(unsigned event)
{
    mix(event);
    ++steps;
    SetLastError(30000 + event * 100 + steps);
    return event != fault;
}
static void path_trace(const WCHAR *path)
{
    size_t length = wcslen(path);
    CHECK(length < 32768 && length >= 15 && !wcscmp(path + length - 15, L"zapret-ring.dll"));
    mix(length);
    for (size_t i = 0; i <= length; ++i) mix(path[i]);
}

static DWORD WINAPI fixture_filename(HMODULE current, LPWSTR path, DWORD capacity)
{
    CHECK(!current && capacity == 32768);
    if (!observe(FILENAME) || path_shape == 3) return 0;
    if (path_shape == 4) return capacity;
    if (path_shape >= 5) {
        unsigned directory = capacity - 17 + (path_shape == 6);
        for (unsigned i = 0; i < directory - 1; ++i) path[i] = L'x';
        path[directory - 1] = L'\\';
        path[directory] = L'e';
        path[directory + 1] = 0;
        return directory + 1;
    }
    const WCHAR *names[] = {L"C:\\local\\winws2.exe", L"C:/local/\x044e\x043d\x0438/winws2.exe", L"winws2.exe"};
    wcscpy(path, names[path_shape]);
    return (DWORD)wcslen(path);
}
static HANDLE WINAPI fixture_open(LPCWSTR path, DWORD access, DWORD share,
    const SECURITY_ATTRIBUTES *security, DWORD disposition, DWORD attributes, HANDLE inherited)
{
    CHECK(access == GENERIC_READ && share == FILE_SHARE_READ && !security &&
        disposition == OPEN_EXISTING && attributes == FILE_ATTRIBUTE_NORMAL && !inherited);
    path_trace(path);
    return observe(OPEN) ? file : INVALID_HANDLE_VALUE;
}
static BOOL WINAPI fixture_size(HANDLE pin, LARGE_INTEGER *size)
{
    const int64_t sizes[] = {20, 0, 32 * 1024 * 1024, 32 * 1024 * 1024 + 1, -1};
    CHECK(pin == file);
    size->QuadPart = sizes[size_shape];
    return observe(FILE_SIZE);
}
static NTSTATUS WINAPI fixture_provider(BCRYPT_ALG_HANDLE *handle, LPCWSTR id, LPCWSTR implementation, ULONG flags)
{
    CHECK(!wcscmp(id, BCRYPT_SHA256_ALGORITHM) && !implementation && !flags && !*handle);
    bool success = observe(PROVIDER);
    if (success || keep_partial) *handle = algorithm;
    return success ? 0 : -1;
}
static NTSTATUS WINAPI fixture_hash(BCRYPT_ALG_HANDLE provider, BCRYPT_HASH_HANDLE *handle,
    PUCHAR object, ULONG object_size, const UCHAR *secret, ULONG secret_size, ULONG flags)
{
    CHECK(provider == algorithm && !*handle && !object && !object_size && !secret && !secret_size && !flags);
    bool success = observe(HASH);
    if (success || keep_partial) *handle = hasher;
    return success ? 0 : -1;
}
static BOOL WINAPI fixture_read(HANDLE pin, void *output, DWORD capacity, DWORD *count, OVERLAPPED *overlapped)
{
    CHECK(pin == file && capacity == 16384 && !overlapped);
    if (!observe(READ)) return false;
    const unsigned sizes[] = {7, 13, 0};
    CHECK(reads < sizeof(sizes) / sizeof(*sizes));
    *count = sizes[reads++];
    memset(output, (int)(reads + 0x80), *count);
    return true;
}
static NTSTATUS WINAPI fixture_update(BCRYPT_HASH_HANDLE hash, const UCHAR *input, ULONG length, ULONG flags)
{
    CHECK(hash == hasher && !flags && length == (reads == 1 ? 7 : 13));
    for (unsigned i = 0; i < length; ++i) mix(input[i]);
    return observe(UPDATE) ? 0 : -1;
}
static NTSTATUS WINAPI fixture_finish(BCRYPT_HASH_HANDLE hash, PUCHAR digest, ULONG size, ULONG flags)
{
    CHECK(hash == hasher && size == sizeof(bytes) && !flags && reads == 3);
    memcpy(digest, bytes, sizeof(bytes));
    return observe(FINISH) ? 0 : -1;
}
static HMODULE WINAPI fixture_load(LPCWSTR path, HANDLE reserved, DWORD flags)
{
    CHECK(!reserved && flags == (LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32));
    path_trace(path);
    return observe(LOAD) ? module : NULL;
}
static int invoke_stub(uint32_t operation, void *object, const rr_request *request,
    rr_response *response, unsigned char *output, size_t capacity)
{ (void)operation; (void)object; (void)request; (void)response; (void)output; (void)capacity; return 0; }
static void drop_stub(void *object) { (void)object; }
static const rr_api *fixture_get(void)
{
    observe(GET);
    if (api_shape == 1) return NULL;
    if (api_shape >= 6) return guard;
    return &mock_api;
}
static FARPROC WINAPI fixture_symbol(HMODULE library, LPCSTR name)
{
    CHECK(library == module && !strcmp(name, "zapret_ring_api_v1"));
    return observe(SYMBOL) ? (FARPROC)fixture_get : NULL;
}
static BOOL WINAPI fixture_unload(HMODULE library) { CHECK(library == module); return observe(UNLOAD); }
static NTSTATUS WINAPI fixture_destroy(BCRYPT_HASH_HANDLE hash) { CHECK(hash == hasher); observe(DESTROY); return 0; }
static NTSTATUS WINAPI fixture_close_provider(BCRYPT_ALG_HANDLE provider, ULONG flags)
{ CHECK(provider == algorithm && !flags); observe(CLOSE_PROVIDER); return 0; }
static BOOL WINAPI fixture_close_file(HANDLE pin) { CHECK(pin == file); return observe(CLOSE_FILE); }

typedef struct {
    DWORD (WINAPI *filename)(HMODULE, LPWSTR, DWORD);
    HANDLE (WINAPI *open)(LPCWSTR, DWORD, DWORD, const SECURITY_ATTRIBUTES *, DWORD, DWORD, HANDLE);
    BOOL (WINAPI *size)(HANDLE, LARGE_INTEGER *);
    NTSTATUS (WINAPI *open_provider)(BCRYPT_ALG_HANDLE *, LPCWSTR, LPCWSTR, ULONG);
    NTSTATUS (WINAPI *new_hash)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE *, PUCHAR, ULONG, const UCHAR *, ULONG, ULONG);
    BOOL (WINAPI *read)(HANDLE, void *, DWORD, DWORD *, OVERLAPPED *);
    NTSTATUS (WINAPI *update)(BCRYPT_HASH_HANDLE, const UCHAR *, ULONG, ULONG);
    NTSTATUS (WINAPI *finish)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
    HMODULE (WINAPI *load)(LPCWSTR, HANDLE, DWORD);
    FARPROC (WINAPI *symbol)(HMODULE, LPCSTR);
    BOOL (WINAPI *unload)(HMODULE);
    NTSTATUS (WINAPI *destroy_hash)(BCRYPT_HASH_HANDLE);
    NTSTATUS (WINAPI *close_provider)(BCRYPT_ALG_HANDLE, ULONG);
    BOOL (WINAPI *close_file)(HANDLE);
} fixture_operations;
_Static_assert(sizeof(fixture_operations) == 112, "Rust loader test operations ABI");
static const fixture_operations operations = {
    fixture_filename, fixture_open, fixture_size, fixture_provider, fixture_hash, fixture_read,
    fixture_update, fixture_finish, fixture_load, fixture_symbol, fixture_unload,
    fixture_destroy, fixture_close_provider, fixture_close_file,
};

#define rr_backend old_backend
#define rr_pin old_pin
#define rr_module old_module
#define rr_load old_load
#undef RUST_RING_DLL_SHA256
#define RUST_RING_DLL_SHA256 selected_pin
#define GetModuleFileNameW fixture_filename
#define CreateFileW fixture_open
#define GetFileSizeEx fixture_size
#define BCryptOpenAlgorithmProvider fixture_provider
#define BCryptCreateHash fixture_hash
#define ReadFile fixture_read
#define BCryptHashData fixture_update
#define BCryptFinishHash fixture_finish
#define LoadLibraryExW fixture_load
#define GetProcAddress fixture_symbol
#define FreeLibrary fixture_unload
#define BCryptDestroyHash fixture_destroy
#define BCryptCloseAlgorithmProvider fixture_close_provider
#define CloseHandle fixture_close_file
#include "ring_loader_reference.inc"
#undef rr_backend
#undef rr_pin
#undef rr_module
#undef rr_load
#undef RUST_RING_DLL_SHA256
#undef GetModuleFileNameW
#undef CreateFileW
#undef GetFileSizeEx
#undef BCryptOpenAlgorithmProvider
#undef BCryptCreateHash
#undef ReadFile
#undef BCryptHashData
#undef BCryptFinishHash
#undef LoadLibraryExW
#undef GetProcAddress
#undef FreeLibrary
#undef BCryptDestroyHash
#undef BCryptCloseAlgorithmProvider
#undef CloseHandle
#define RUST_RING_DLL_SHA256 real_pin
#include "ring_loader_windows.inc"
bool zapret_ring_load_fixture(zapret_ring_loader *, const char *, const fixture_operations *);

struct outcome { uint64_t trace; unsigned steps, error, cached_error; bool success, pin, module; };
static struct outcome run(bool rust)
{
    char correct[65], lowercase[65];
    for (size_t i = 0; i < sizeof(bytes); ++i) {
        snprintf(correct + i * 2, 3, "%02X", bytes[i]);
        snprintf(lowercase + i * 2, 3, "%02x", bytes[i]);
    }
    selected_pin = pin_shape == 0 ? correct : pin_shape == 1 ? lowercase : "00";
    mock_api = (rr_api){sizeof(rr_api), 1, invoke_stub, drop_stub};
    if (api_shape == 2) mock_api.version = 2;
    if (api_shape == 3) mock_api.size -= 1;
    if (api_shape == 4) mock_api.invoke = NULL;
    if (api_shape == 5) mock_api.drop_object = NULL;
    old_pin = INVALID_HANDLE_VALUE;
    old_backend = NULL;
    old_module = NULL;
    zapret_ring_loader loader = { .pin = INVALID_HANDLE_VALUE };
    reads = steps = 0;
    trace = UINT64_C(14695981039346656037);
    SetLastError(121);
    bool success = rust ? zapret_ring_load_fixture(&loader, selected_pin, &operations) : old_load();
    unsigned error = GetLastError();
    CHECK((rust ? loader.api : old_backend) == (success ? &mock_api : NULL));
    bool pin = (rust ? loader.pin : old_pin) == file;
    bool loaded = (rust ? loader.module : old_module) == module;
    CHECK(pin == success && loaded == success);
    unsigned cached_error = 0;
    if (success) {
        const unsigned observed = steps;
        selected_pin = NULL;
        SetLastError(777);
        CHECK(rust ? zapret_ring_load_fixture(&loader, NULL, &operations) : old_load());
        cached_error = GetLastError();
        CHECK(steps == observed && cached_error == 777);
    }
    return (struct outcome){trace, steps, error, cached_error, success, pin, loaded};
}
static void compare(void)
{
    struct outcome old = run(false), rust = run(true);
    CHECK(old.trace == rust.trace && old.steps == rust.steps && old.error == rust.error &&
        old.cached_error == rust.cached_error && old.success == rust.success &&
        old.pin == rust.pin && old.module == rust.module);
    ++cases;
}

static void check_guard(void)
{
    GetSystemInfo(&system_info);
    const size_t page = system_info.dwPageSize;
    unsigned char *memory = VirtualAlloc(NULL, page * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(memory);
    DWORD old;
    CHECK(VirtualProtect(memory + page, page, PAGE_NOACCESS, &old));
    for (api_shape = 6; api_shape <= 8; ++api_shape) {
        unsigned char *start = memory + page - (api_shape == 8 ? 24 : 16);
        const size_t length = api_shape == 7 ? 16 : sizeof(rr_api);
        const uint32_t version = api_shape == 6 ? 2 : 1;
        memcpy(start, &length, sizeof(length));
        memcpy(start + 8, &version, sizeof(version));
        if (api_shape == 8) memset(start + 16, 0, 8);
        guard = start;
        compare();
        ++guard_cases;
    }
    CHECK(VirtualFree(memory, 0, MEM_RELEASE));
}

static void check_native(void)
{
    zapret_ring_loader rejected = { .pin = INVALID_HANDLE_VALUE };
    CHECK(!GetModuleHandleW(L"zapret-ring.dll"));
    CHECK(!zapret_ring_load(&rejected, "invalid pin"));
    CHECK(!rejected.api && !GetModuleHandleW(L"zapret-ring.dll"));
    CHECK(rr_load() && rr_backend->version == 1 && rr_loader.pin != INVALID_HANDLE_VALUE);
    HANDLE writable = CreateFileW(L"zapret-ring.dll", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (writable != INVALID_HANDLE_VALUE) { CloseHandle(writable); CHECK(false); }
    CHECK(GetLastError() == ERROR_SHARING_VIOLATION);
    SetLastError(913);
    CHECK(zapret_ring_load(&rr_loader, NULL) && GetLastError() == 913);
}

int main(void)
{
    for (unsigned i = 0; i < sizeof(bytes); ++i) bytes[i] = (uint8_t)(0xab + i);
    for (path_shape = 0; path_shape <= 6; ++path_shape)
        for (size_shape = 0; size_shape < 5; ++size_shape)
            for (pin_shape = 0; pin_shape < 3; ++pin_shape)
                for (api_shape = 0; api_shape < 6; ++api_shape)
                    compare();
    path_shape = size_shape = pin_shape = api_shape = 0;
    for (fault = FILENAME; fault <= SYMBOL; ++fault)
        for (keep_partial = 0; keep_partial < 2; ++keep_partial) compare();
    fault = keep_partial = 0;
    check_guard();
    check_native();
    printf("PASS ring_loader cases=%u guarded=%u win32_flags=1 last_error=1 native_unicode=1 "
        "sha256_before_load=1 write_pin_held=1 cached_load=1\n", cases, guard_cases);
    return 0;
}
