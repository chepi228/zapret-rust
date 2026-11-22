/* MIT. Bind native allocators and list entry publication to the Rust parser. */
typedef struct {
    void *(*allocate)(size_t);
    void (*release)(void *);
    void *(*start)(void *, const char *);
    bool (*add)(void *, char *, char *);
} native_lua_arguments_ops;
typedef struct {const char *format;int32_t length;} native_lua_arguments_error;
bool zapret_lua_add_argument(const char *, void *, const native_lua_arguments_ops *);
struct func_list *zapret_lua_parse_arguments(const char *, void *, void *,
    const native_lua_arguments_ops *, native_lua_arguments_error *);

static bool native_lua_add_argument_impl(void *args, char *name, char *text)
{
    struct str2_list *entry = str2list_add(args);
    if (!entry) return false;
    entry->str1 = name;
    entry->str2 = text;
    return true;
}

static void *native_lua_start_call(void *staged, const char *name)
{
    struct func_list *entry = funclist_add_tail(staged, name);
    return entry ? &entry->args : NULL;
}

static const native_lua_arguments_ops native_lua_arguments={malloc,free,native_lua_start_call,native_lua_add_argument_impl};

bool lua_call_param_add(char *opt, struct str2_list_head *args)
{
    return zapret_lua_add_argument(opt, args, &native_lua_arguments);
}

struct func_list *parse_lua_call(char *opt, struct func_list_head *head)
{
    struct func_list_head staged = {0};
    native_lua_arguments_error error={0};
    struct func_list *entry=zapret_lua_parse_arguments(opt,&staged,head,&native_lua_arguments,&error);
    if (!entry) {
        if (error.format) DLOG_ERR(error.format,error.length,opt);
        funclist_destroy(&staged);
    }
    return entry;
}
