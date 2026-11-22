/* MIT. Existing Windows engine blob layout and CRT allocation contract. */
#pragma once
typedef struct {
    void *(*allocate)(size_t);
    void (*release)(void *);
} zapret_blob_allocator;
typedef struct {
    const char *source;
    uint64_t offset, file_size;
    size_t name_length;
} zapret_blob_input;
enum zapret_blob_error {
    BLOB_IDENTIFIER = 1,
    BLOB_ALLOCATION,
    BLOB_DUPLICATE,
    BLOB_OFFSET,
    BLOB_ACCESS,
    BLOB_BEYOND_END,
    BLOB_READ,
    BLOB_HEX,
    BLOB_SIZE
};

_Static_assert(sizeof(struct blob_item) == 7 * sizeof(void *) &&
    offsetof(struct blob_item, next.le_prev) == 6 * sizeof(void *) &&
    offsetof(struct blob_item, size_buf) == 2 * sizeof(void *) &&
    offsetof(struct blob_item, name) == 3 * sizeof(void *) &&
    offsetof(struct blob_item, extra) == 4 * sizeof(void *) && sizeof(zapret_blob_input) == 32,
    "Rust blob layout");

struct blob_item *zapret_blob_add(struct blob_collection_head *, const zapret_blob_allocator *, const void *, size_t, size_t);
struct blob_item *zapret_blob_find(struct blob_collection_head *, const char *);
void zapret_blob_destroy(struct blob_item *, const zapret_blob_allocator *);
struct blob_item *zapret_blob_pop(struct blob_collection_head *);
void zapret_blob_destroy_list(struct blob_collection_head *, const zapret_blob_allocator *);
uint32_t zapret_blob_load_argument(const char *, void *, size_t *, zapret_blob_input *);
uint32_t zapret_blob_load_named(struct blob_collection_head *, const char *, size_t, size_t,
    const zapret_blob_allocator *, zapret_blob_input *, struct blob_item **);
uint32_t zapret_blob_load_const(struct blob_collection_head *, const char *, const void *, size_t, size_t,
    const zapret_blob_allocator *, struct blob_item **);

static const zapret_blob_allocator native_blob_allocator = {malloc, free};
