/* MIT. Keep the engine's console buffer and Windows line handling. */
typedef bool (*zapret_network_write)(void *, const uint8_t *, size_t);
bool zapret_network_environment_list(bool, void *, zapret_network_write, uint32_t *);

static bool native_network_list_write(void *file, const uint8_t *bytes, size_t length)
{
    return fwrite(bytes, 1, length, file) == length;
}

bool nlm_list(bool all)
{
    return zapret_network_environment_list(all, stdout, native_network_list_write, &w_win32_error);
}
