/* MIT. Windows entry points for CLI blob inputs. */
#pragma once
#include <stddef.h>
#include "windows_startup_params_abi.h"

_Static_assert(sizeof(struct blob_collection_head) == sizeof(void *) &&
    offsetof(struct blob_collection_head, lh_first) == 0,
    "Rust CLI blob list storage");

bool zapret_native_blob_read_fixed(const char *argument, void *buffer, size_t *size);
struct blob_item *zapret_native_blob_read_named(struct blob_collection_head *head,
    const char *argument, size_t maximum, size_t reserve);
struct blob_item *native_publish_const_blob(void *head, const char *name, const void *data,
    size_t size, size_t reserve);
bool zapret_native_cli_read_blob(const char *argument, size_t maximum, size_t reserve);
