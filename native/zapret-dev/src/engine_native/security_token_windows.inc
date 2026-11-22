/* MIT. Token policy returns an exact error before C publishes last-error state. */
uint32_t zapret_security_adjust(HANDLE,const char *const *,bool,const void *);
uint32_t zapret_security_adjust_current(const char *const *,bool,const void *);
uint32_t zapret_security_adjust_w(HANDLE,const WCHAR *const *,bool,const void *);
uint32_t zapret_security_adjust_current_w(const WCHAR *const *,bool,const void *);
uint32_t zapret_security_remove(const void *);
uint32_t zapret_security_low(const void *);
_Static_assert(sizeof(LUID)==8 && sizeof(LUID_AND_ATTRIBUTES)==12 &&
    offsetof(TOKEN_PRIVILEGES,Privileges)==4 && sizeof(TOKEN_MANDATORY_LABEL)==16 && sizeof(SID)==12,
    "Rust token and SID ABI");
_Static_assert(SE_GROUP_INTEGRITY==0x20 && SECURITY_MANDATORY_LOW_RID==4096 && SID_REVISION==1,
    "Rust low integrity SID values");
static BOOL native_token_result(uint32_t error)
{w_win32_error=error;SetLastError(error);return error==ERROR_SUCCESS;}
BOOL AdjustPrivileges(HANDLE token,const LPCTSTR *names,BOOL enable)
{
#ifdef UNICODE
return native_token_result(zapret_security_adjust_w(token,names,enable!=FALSE,NULL));
#else
return native_token_result(zapret_security_adjust(token,names,enable!=FALSE,NULL));
#endif
}
BOOL AdjustPrivilegesForCurrentProcess(const LPCTSTR *names,BOOL enable)
{
#ifdef UNICODE
return native_token_result(zapret_security_adjust_current_w(names,enable!=FALSE,NULL));
#else
return native_token_result(zapret_security_adjust_current(names,enable!=FALSE,NULL));
#endif
}
static BOOL RemoveTokenPrivs(void) {return native_token_result(zapret_security_remove(NULL));}
BOOL LowMandatoryLevel(void) {return native_token_result(zapret_security_low(NULL));}
