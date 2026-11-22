/* MIT. Publish WRITABLE only after Rust verifies the directory and label. */
uint32_t zapret_writable_prepare(const char *,const void *);
bool make_writable_dir(void)
{
    DWORD error=zapret_writable_prepare(params.writable_dir,NULL);
    w_win32_error=error;SetLastError(error);
    if(error)wf_error(error);
    return !error;
}
