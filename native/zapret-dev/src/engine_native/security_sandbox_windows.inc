/* MIT. Process transition and Job ownership are implemented by Rust. */
uint32_t zapret_security_job(const void *);
uint32_t zapret_security_sandbox(bool (*)(void),uint32_t *,const void *);
BOOL JobSandbox(void)
{DWORD error=zapret_security_job(NULL);w_win32_error=error;SetLastError(error);return !error;}
bool win_sandbox(void)
{DWORD error=zapret_security_sandbox(logical_net_filter_present,NULL,NULL);w_win32_error=error;SetLastError(error);return !error;}
