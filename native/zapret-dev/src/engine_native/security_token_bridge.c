/* Exercise the actual C TCHAR adapter with only an owned duplicated token. */
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#undef main
uint32_t w_win32_error;
#include "security_token_windows.inc"
#define CHECK(condition) do {if(!(condition)){fprintf(stderr,"FAIL token bridge line=%d error=%lu: %s\n",__LINE__,(unsigned long)GetLastError(),#condition);exit(1);}}while(0)
static int check_bridge(void)
{
    HANDLE primary,duplicate;CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE,&primary));
    CHECK(DuplicateTokenEx(primary,TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,NULL,SecurityImpersonation,TokenImpersonation,&duplicate));
    const LPCTSTR names[]={SE_CHANGE_NOTIFY_NAME,NULL};CHECK(AdjustPrivileges(duplicate,names,FALSE) && !w_win32_error);CHECK(AdjustPrivileges(duplicate,names,TRUE) && !w_win32_error);
    const LPCTSTR missing[]={TEXT("ZapretFixtureAbsentPrivilege"),NULL};CHECK(!AdjustPrivileges(duplicate,missing,TRUE) && w_win32_error==ERROR_NO_SUCH_PRIVILEGE && GetLastError()==ERROR_NO_SUCH_PRIVILEGE);
    CHECK(CloseHandle(duplicate) && CloseHandle(primary));
    printf("PASS security_token_bridge unicode=%u duplicate_transitions=2 rejected_lookup=1\n",sizeof(TCHAR)==2);return 0;
}
#ifdef UNICODE
int wmain(void){return check_bridge();}
#else
int main(void){return check_bridge();}
#endif
