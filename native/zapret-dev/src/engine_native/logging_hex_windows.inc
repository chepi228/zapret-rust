/* MIT. The writer only calls the engine's ordinary variadic logger. */
bool zapret_log_hex(const uint8_t *, size_t, size_t, void (*)(const char *));
static void native_hex_dlog(const char *text)
{
    DLOG("%s", text);
}
void hexdump_limited_dlog(const uint8_t *data, size_t size, size_t limit)
{
    zapret_log_hex(data, size, limit, native_hex_dlog);
}
