/* MIT. Existing collection entry points delegate to Rust. */
#include "blob_windows.h"

struct blob_item *blob_collection_add(struct blob_collection_head *head)
{
    return zapret_blob_add(head, &native_blob_allocator, NULL, 0, 0);
}
struct blob_item *blob_collection_add_blob(struct blob_collection_head *head, const void *data, size_t size, size_t reserve)
{
    return zapret_blob_add(head, &native_blob_allocator, data, size, reserve);
}
void blob_destroy(struct blob_item *blob)
{
    zapret_blob_destroy(blob, &native_blob_allocator);
}
void blob_collection_destroy(struct blob_collection_head *head)
{
    zapret_blob_destroy_list(head, &native_blob_allocator);
}
bool blob_collection_empty(const struct blob_collection_head *head)
{
    return LIST_EMPTY(head);
}
struct blob_item *blob_collection_search_name(struct blob_collection_head *head, const char *name)
{
    return zapret_blob_find(head, name);
}
