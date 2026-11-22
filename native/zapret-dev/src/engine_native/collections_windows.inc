/* MIT. Keep the original public list ABI and the engine's UCRT allocator. */
typedef struct {
    void *(*allocate)(size_t);
    void (*release)(void *);
} zapret_collection_allocator;
void *zapret_collection_add(uint32_t, void *, const char *, bool, const zapret_collection_allocator *);
bool zapret_collection_copy(uint32_t, void *, const void *, const zapret_collection_allocator *);
void zapret_collection_destroy(uint32_t, void *, const zapret_collection_allocator *);
bool zapret_collection_search(const void *, const char *);
static const zapret_collection_allocator native_collection_allocator = {malloc, free};
_Static_assert(sizeof(struct str_list) == 24 && offsetof(struct str_list, next) == 8, "Rust string list ABI");
_Static_assert(sizeof(struct str2_list) == 32 && offsetof(struct str2_list, next) == 16, "Rust string pair ABI");
_Static_assert(sizeof(struct packet_range) == 20 && sizeof(struct func_list) == 80, "Rust function range ABI");
_Static_assert(offsetof(struct func_list, args) == 56 && offsetof(struct func_list, next) == 64, "Rust function links ABI");
bool strlist_add(struct str_list_head *head, const char *str)
{ return zapret_collection_add(0, head, str, false, &native_collection_allocator) != NULL; }
bool strlist_add_tail(struct str_list_head *head, const char *str)
{ return zapret_collection_add(0, head, str, true, &native_collection_allocator) != NULL; }
bool strlist_copy(struct str_list_head *to, const struct str_list_head *from)
{ return zapret_collection_copy(0, to, from, &native_collection_allocator); }
void strlist_destroy(struct str_list_head *head)
{ zapret_collection_destroy(0, head, &native_collection_allocator); }
bool strlist_search(const struct str_list_head *head, const char *str)
{ return zapret_collection_search(head, str); }
struct str2_list *str2list_add(struct str2_list_head *head)
{ return zapret_collection_add(1, head, NULL, false, &native_collection_allocator); }
bool str2list_copy(struct str2_list_head *to, const struct str2_list_head *from)
{ return zapret_collection_copy(1, to, from, &native_collection_allocator); }
void str2list_destroy(struct str2_list_head *head)
{ zapret_collection_destroy(1, head, &native_collection_allocator); }
struct func_list *funclist_add_tail(struct func_list_head *head, const char *func)
{ return zapret_collection_add(2, head, func, true, &native_collection_allocator); }
bool funclist_copy(struct func_list_head *to, const struct func_list_head *from)
{ return zapret_collection_copy(2, to, from, &native_collection_allocator); }
void funclist_destroy(struct func_list_head *head)
{ zapret_collection_destroy(2, head, &native_collection_allocator); }
