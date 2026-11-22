/* MIT. Native list registration and modification state are owned by Rust. */
#pragma once
#include <stddef.h>

struct zapret_list_files;
struct zapret_list_collection;

/* C-facing prefix of the stable Rust record. The filename is borrowed. */
struct zapret_list_file {
    const char *filename;
    file_mod_sig mod_sig;
    hostlist_pool *hostlist;
    ipset ipset;
};

_Static_assert(sizeof(file_mod_sig) == 24 &&
    offsetof(file_mod_sig, size) == 16 &&
    sizeof(((struct timespec *)0)->tv_nsec) == 4, "Rust list stamp ABI");
_Static_assert(sizeof(struct zapret_list_file) == (sizeof(void *) == 8 ? 56 : 48) &&
    offsetof(struct zapret_list_file, hostlist) == 32 &&
    offsetof(struct zapret_list_file, ipset) == 32 + sizeof(void *), "Rust list file ABI");

struct zapret_list_file *zapret_list_register(struct zapret_list_files **,
    struct zapret_list_collection **, const char *);
struct zapret_list_file *zapret_list_register_path(struct zapret_list_files **,
    struct zapret_list_collection **, const char *);
struct zapret_list_file *zapret_list_files_at(const struct zapret_list_files *, size_t);
void zapret_list_files_reset(const struct zapret_list_files *);
void zapret_list_files_destroy(struct zapret_list_files **);
struct zapret_list_file *zapret_list_collection_at(const struct zapret_list_collection *, size_t);
bool zapret_list_collection_empty(const struct zapret_list_collection *);
bool zapret_list_collection_copy(struct zapret_list_collection **, const struct zapret_list_collection *);
void zapret_list_collection_destroy(struct zapret_list_collection **);

typedef bool (*zapret_list_stat)(const char *, file_mod_sig *, const char *);
typedef bool (*zapret_list_probe)(const char *, const char *);
typedef bool (*zapret_list_append)(struct zapret_list_file *);
bool zapret_list_reload(struct zapret_list_file *, bool *, const char *,
    zapret_list_stat, zapret_list_probe, zapret_list_append);
bool zapret_list_read_stamp(const char *, file_mod_sig *, const char *);
bool zapret_list_probe_read(const char *, const char *);

#define ZAPRET_FOR_LIST_FILE(file, registry) \
    for (size_t list_index = 0; ((file) = zapret_list_files_at((registry), list_index)); ++list_index)
#define ZAPRET_FOR_LIST_REFERENCE(file, collection) \
    for (size_t list_index = 0; ((file) = zapret_list_collection_at((collection), list_index)); ++list_index)
