/* MIT. Token ownership remains in Rust; the adapters keep pool-specific calls. */
bool zapret_config_list(const char *, void *, bool (*)(void *, char *));
typedef struct { void *(*allocate)(size_t); void (*release)(void *); } zapret_config_list_allocator;
bool zapret_collection_parse_strings(void *, const char *, const zapret_config_list_allocator *);
static const zapret_config_list_allocator native_config_list_allocator = {malloc, free};
static bool native_add_domain(void *target, char *text)
{ return AppendHostlistItem(target, text); }
static bool native_add_ip(void *target, char *text)
{ return AppendIpsetItem(target, text); }
static bool parse_domain_list(char *text, hostlist_pool **head)
{ return zapret_config_list(text, head, native_add_domain); }
static bool parse_ip_list(char *text, ipset *head)
{ return zapret_config_list(text, head, native_add_ip); }
static bool parse_strlist(char *text, struct str_list_head *head)
{ return zapret_collection_parse_strings(head, text, &native_config_list_allocator); }
