/* MIT. Report a native error through the engine's existing errno adapter. */
uint32_t zapret_engine_load_file(const char *, int64_t, void *, size_t *);
uint32_t zapret_engine_save_file(const char *, const uint8_t *, size_t);
uint32_t zapret_engine_append_line(const char *, const char *);
_Static_assert(sizeof(off_t) == 8, "Rust binary input offset ABI");
bool load_file(const char *filename, off_t offset, void *output, size_t *size)
{
    uint32_t error = zapret_engine_load_file(filename, offset, output, size);
    if (error) { wf_error(error); return false; }
    return true;
}
bool save_file(const char *filename, const void *data, size_t size)
{
    uint32_t error = zapret_engine_save_file(filename, data, size);
    if (error) { wf_error(error); return false; }
    return true;
}
bool append_to_list_file(const char *filename, const char *text)
{
    uint32_t error = zapret_engine_append_line(filename, text);
    if (error) { wf_error(error); return false; }
    return true;
}
