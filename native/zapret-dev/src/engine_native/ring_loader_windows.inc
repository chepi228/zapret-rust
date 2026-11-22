/* The pinned DLL loader is statically linked Rust. Keep the native callback type. */
typedef struct {
    const rr_api *api;
    HANDLE pin;
    HMODULE module;
} zapret_ring_loader;
_Static_assert(sizeof(zapret_ring_loader) == 3 * sizeof(void *) &&
    sizeof(rr_api) == 4 * sizeof(void *) && offsetof(rr_api, version) == sizeof(void *) &&
    offsetof(rr_api, invoke) == 2 * sizeof(void *) &&
    offsetof(rr_api, drop_object) == 3 * sizeof(void *), "Rust ring loader ABI");
bool zapret_ring_load(zapret_ring_loader *, const char *);

static zapret_ring_loader rr_loader = {.pin = INVALID_HANDLE_VALUE};
#define rr_backend (rr_loader.api)
static int rr_load(void) { return zapret_ring_load(&rr_loader, RUST_RING_DLL_SHA256); }
