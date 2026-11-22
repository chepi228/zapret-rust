/* MIT. The native error is captured before freeing path or COM resources. */
uint32_t zapret_security_label_w(const WCHAR *,uint32_t,uint32_t,const void *);
uint32_t zapret_security_label_file(const char *,uint32_t,uint32_t,const void *);
uint32_t zapret_security_label_object(HANDLE,int,uint32_t,uint32_t,uint32_t,const void *);
uint32_t zapret_security_ensure(const char *,bool,const void *);
uint32_t zapret_security_appdata(const void *);
_Static_assert(sizeof(ACL)==8 && SYSTEM_MANDATORY_LABEL_NO_WRITE_UP==1 &&
    OBJECT_INHERIT_ACE==1 && CONTAINER_INHERIT_ACE==2 && sizeof(SID)==12,
    "Rust integrity label layout and flags");
static BOOL native_label_result(uint32_t error)
{w_win32_error=error;SetLastError(error);return error==ERROR_SUCCESS;}
BOOL SetMandatoryLabelFileW(LPCWSTR path,DWORD rid,DWORD flags){return native_label_result(zapret_security_label_w(path,rid,flags,NULL));}
BOOL SetMandatoryLabelFile(LPCSTR path,DWORD rid,DWORD flags){return native_label_result(zapret_security_label_file(path,rid,flags,NULL));}
BOOL SetMandatoryLabelObject(HANDLE handle,SE_OBJECT_TYPE kind,DWORD rid,DWORD revision,DWORD flags){return native_label_result(zapret_security_label_object(handle,kind,rid,revision,flags,NULL));}
bool ensure_file_access(const char *path){return native_label_result(zapret_security_ensure(path,false,NULL));}
bool ensure_dir_access(const char *path){return native_label_result(zapret_security_ensure(path,true,NULL));}
bool prepare_low_appdata(void){return native_label_result(zapret_security_appdata(NULL));}
