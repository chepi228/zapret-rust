/* MIT. Previous C identity query, compiled only by the comparison fixture. */
int uname(struct utsname *value)
{
    if(!value){errno=EINVAL;return -1;}
    memset(value,0,sizeof(*value));
    strcpy(value->sysname,"Windows_NT");
    OSVERSIONINFOW version={.dwOSVersionInfoSize=sizeof(version)};
    typedef LONG (WINAPI *version_query)(OSVERSIONINFOW *);
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    version_query query=ntdll?(version_query)GetProcAddress(ntdll,"RtlGetVersion"):NULL;
    if(!query||query(&version)<0){errno=EIO;return -1;}
    snprintf(value->release,sizeof(value->release),"%lu.%lu",(unsigned long)version.dwMajorVersion,(unsigned long)version.dwMinorVersion);
    snprintf(value->version,sizeof(value->version),"build %lu",(unsigned long)version.dwBuildNumber);
    WCHAR name[256];DWORD length=256;
    if(!GetComputerNameW(name,&length)||!WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,name,-1,value->nodename,sizeof(value->nodename),NULL,NULL)){
        errno=EIO;return -1;
    }
    SYSTEM_INFO system;
    GetNativeSystemInfo(&system);
    const char *architecture=system.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64?"x86_64":
        system.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_ARM64?"aarch64":"x86";
    strcpy(value->machine,architecture);
    return 0;
}
