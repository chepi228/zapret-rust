/* MIT. The Rust engine publishes the native Windows status and parameters. */
#pragma once
#include <windows.h>
#include <aclapi.h>
#include "windows_startup_params_abi.h"

_Static_assert(sizeof(BOOL) == 4 && sizeof(DWORD) == 4 && sizeof(TCHAR) == 1,
    "Rust Windows engine entries");
_Static_assert(sizeof(ACL) == 8 && SYSTEM_MANDATORY_LABEL_NO_WRITE_UP == 1 &&
    OBJECT_INHERIT_ACE == 1 && CONTAINER_INHERIT_ACE == 2 && sizeof(SID) == 12,
    "Rust integrity label layout and flags");
_Static_assert(sizeof(LUID) == 8 && sizeof(LUID_AND_ATTRIBUTES) == 12 &&
    offsetof(TOKEN_PRIVILEGES, Privileges) == 4 && sizeof(TOKEN_MANDATORY_LABEL) == 2 * sizeof(void *),
    "Rust token and SID ABI");
_Static_assert(SE_GROUP_INTEGRITY == 0x20 && SECURITY_MANDATORY_LOW_RID == 4096 &&
    SID_REVISION == 1, "Rust low integrity SID values");

BOOL SetMandatoryLabelFileW(LPCWSTR, DWORD, DWORD);
BOOL SetMandatoryLabelFile(LPCSTR, DWORD, DWORD);
BOOL SetMandatoryLabelObject(HANDLE, SE_OBJECT_TYPE, DWORD, DWORD, DWORD);
BOOL JobSandbox(void);
BOOL AdjustPrivileges(HANDLE, const LPCTSTR *, BOOL);
BOOL AdjustPrivilegesForCurrentProcess(const LPCTSTR *, BOOL);
BOOL LowMandatoryLevel(void);
