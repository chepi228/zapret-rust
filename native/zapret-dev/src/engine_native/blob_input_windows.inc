/* MIT. The caller owns the terminating process exit. */
#include "blob_windows.h"
#include "runtime_log_windows.h"

typedef struct {
    zapret_log_sink debug, error;
} zapret_blob_logs;
bool zapret_blob_read_fixed(const char *, void *, size_t *, const zapret_blob_logs *);
struct blob_item *zapret_blob_read_named(struct blob_collection_head *, const char *, size_t, size_t,
    const zapret_blob_allocator *, const zapret_blob_logs *);
struct blob_item *zapret_blob_read_const(struct blob_collection_head *, const char *, const void *,
    size_t, size_t, const zapret_blob_allocator *, const zapret_blob_logs *);
static const zapret_blob_logs blob_logs = {DLOG, DLOG_ERR};

static void load_file_or_exit(const char *argument, void *buffer, size_t *size)
{
    if (!zapret_blob_read_fixed(argument, buffer, size, &blob_logs)) exit_clean(1);
}

static struct blob_item *load_blob_to_collection(const char *argument, struct blob_collection_head *head, size_t max_hex, size_t reserve)
{
    struct blob_item *blob = zapret_blob_read_named(head, argument, max_hex, reserve, &native_blob_allocator, &blob_logs);
    if (!blob) exit_clean(1);
    return blob;
}

static struct blob_item *native_publish_const_blob(void *head, const char *name, const void *data,
    size_t size, size_t reserve)
{
    return zapret_blob_read_const(head, name, data, size, reserve, &native_blob_allocator, &blob_logs);
}
