//! Anchored filesystem and sandbox changes for the pinned native Windows engine.
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

pub fn apply(nfq: &Path) -> Result<()> {
    replace(
        nfq,
        "helpers.c",
        r###"#ifdef ZAPRET_WINDOWS
#include <sys/cygwin.h>
#endif"###,
        r###"#ifdef ZAPRET_NATIVE_WINDOWS
#include "win_files.h"
#elif defined(ZAPRET_WINDOWS)
#include <sys/cygwin.h>
#endif"###,
    )?;
    replace(
        nfq,
        "helpers.c",
        r###"bool file_size(const char *filename, off_t *size)
{
	struct stat st;
	if (stat(filename, &st) == -1) return false;
	if (size) *size = st.st_size;
	return true;
}
"###,
        r###"bool file_size(const char *filename, off_t *size)
{
#ifdef ZAPRET_NATIVE_WINDOWS

	wf_file_info info;
	if (wf_file_stat(filename, &info)) return false;
	if (size) *size = info.st_size;
	return true;
#else
	struct stat st;
	if (stat(filename, &st) == -1) return false;
	if (size) *size = st.st_size;
	return true;
#endif
}
"###,
    )?;
    replace(
        nfq,
        "helpers.c",
        r###"bool file_mod_signature(const char *filename, file_mod_sig *ms)
{
	struct stat st;
	if (stat(filename, &st) == -1)
	{
		FILE_MOD_RESET(ms);
		return false;
	}
	ms->mod_time = st.st_mtim;
	ms->size = st.st_size;
	return true;
}

"###,
        r###"bool file_mod_signature(const char *filename, file_mod_sig *ms)
{
#ifdef ZAPRET_NATIVE_WINDOWS

	wf_file_info info;
	if (wf_file_stat(filename, &info))
	{
		FILE_MOD_RESET(ms);
		return false;
	}
	ms->mod_time = info.modified;
	ms->size = info.st_size;
	return true;
#else
	struct stat st;
	if (stat(filename, &st) == -1)
	{
		FILE_MOD_RESET(ms);
		return false;
	}
	ms->mod_time = st.st_mtim;
	ms->size = st.st_size;
	return true;
#endif
}

"###,
    )?;
    replace(
        nfq,
        "helpers.c",
        r###"bool set_env_exedir(const char *argv0)
{
	char *s, *d;
	bool bOK = false;
	if ((s = strdup(argv0)))
	{
		if ((d = dirname(s)))
		{
			char d_abs[PATH_MAX];
			if (realpath(d, d_abs))
				d=d_abs;
			bOK = !setenv("EXEDIR", d, 1);
		}
		free(s);
	}
	return bOK;
}

"###,
        r###"bool set_env_exedir(const char *argv0)
{
#ifdef ZAPRET_NATIVE_WINDOWS

	(void)argv0;
	return wf_set_exedir();
#else
	char *s, *d;
	bool bOK = false;
	if ((s = strdup(argv0)))
	{
		if ((d = dirname(s)))
		{
			char d_abs[PATH_MAX];
			if (realpath(d, d_abs))
				d=d_abs;
			bOK = !setenv("EXEDIR", d, 1);
		}
		free(s);
	}
	return bOK;
#endif
}

"###,
    )?;
    replace(
        nfq,
        "helpers.c",
        r###"bool realpath_any(const char *file, char *pabs)
{
	bool b = true;
	char *s1=NULL, *s2=NULL;
	int res;
	size_t l;

#ifdef ZAPRET_WINDOWS
	l = cygwin_conv_path(CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE, file, NULL, 0);
	char *rp_file = (char*)malloc(l);
	if (cygwin_conv_path(CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE, file, rp_file, l))
		goto err;
#else
#define rp_file file
#endif

	if (!realpath(rp_file,pabs))
	{
		char pa[PATH_MAX], *dir, *base;
		if (!(s1 = strdup(rp_file))) goto err;
		dir = dirname(s1);
		if (!realpath(dir,pa))
			goto err;
		if (!(s2 = strdup(rp_file))) goto err;
		base = basename(s2);
		l = strlen(pa);
		if (l && pa[l-1]=='/')
			res=snprintf(pabs,PATH_MAX,"%s%s",pa, base);
		else
			res=snprintf(pabs,PATH_MAX,"%s/%s",pa,base);
		b = res>0 && res<PATH_MAX;
	}
ex:
#ifdef ZAPRET_WINDOWS
	free(rp_file);
#else
#undef rp_file
#endif
	free(s1);
	free(s2);
	return b;
err:
	b = false;
	goto ex;
}

"###,
        r###"bool realpath_any(const char *file, char *pabs)
{
#ifdef ZAPRET_NATIVE_WINDOWS

	return wf_realpath_any(file, pabs);
#else
	bool b = true;
	char *s1=NULL, *s2=NULL;
	int res;
	size_t l;

#ifdef ZAPRET_WINDOWS
	l = cygwin_conv_path(CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE, file, NULL, 0);
	char *rp_file = (char*)malloc(l);
	if (cygwin_conv_path(CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE, file, rp_file, l))
		goto err;
#else
#define rp_file file
#endif

	if (!realpath(rp_file,pabs))
	{
		char pa[PATH_MAX], *dir, *base;
		if (!(s1 = strdup(rp_file))) goto err;
		dir = dirname(s1);
		if (!realpath(dir,pa))
			goto err;
		if (!(s2 = strdup(rp_file))) goto err;
		base = basename(s2);
		l = strlen(pa);
		if (l && pa[l-1]=='/')
			res=snprintf(pabs,PATH_MAX,"%s%s",pa, base);
		else
			res=snprintf(pabs,PATH_MAX,"%s/%s",pa,base);
		b = res>0 && res<PATH_MAX;
	}
ex:
#ifdef ZAPRET_WINDOWS
	free(rp_file);
#else
#undef rp_file
#endif
	free(s1);
	free(s2);
	return b;
err:
	b = false;
	goto ex;
#endif
}

"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"#include <sys/cygwin.h>"###,
        r###"#ifndef ZAPRET_NATIVE_WINDOWS
#include <sys/cygwin.h>
#endif"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"BOOL SetMandatoryLabelFile(LPCSTR lpFileName, DWORD dwMandatoryLabelRID, DWORD dwAceFlags)
{
	BOOL bRes=FALSE;
	DWORD dwErr, dwFileAttributes;
	char buf_label[16], buf_pacl[32];
	PSID label = (PSID)buf_label;
	PACL pacl = (PACL)buf_pacl;
	LPWSTR lpFileNameW = NULL;
	size_t szFileName;

	szFileName = strlen(lpFileName);
	if (!(lpFileNameW = (LPWSTR)LocalAlloc(LMEM_FIXED,(szFileName+1)*sizeof(WCHAR))))
		goto err;

	if (!MultiByteToWideChar(CP_UTF8, 0, lpFileName, -1, lpFileNameW, szFileName+1))
		goto err;

	if (!strncmp(lpFileName,"\\\\.\\",4))
		dwFileAttributes = 0;
	else
	{
		dwFileAttributes = GetFileAttributesW(lpFileNameW);
		if (dwFileAttributes == INVALID_FILE_ATTRIBUTES) goto err;
	}
	InitializeSid(label, &label_authority, 1);
	*GetSidSubAuthority(label, 0) = dwMandatoryLabelRID;
	if (InitializeAcl(pacl, sizeof(buf_pacl), ACL_REVISION) && AddMandatoryAce(pacl, (dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? ACL_REVISION_DS : ACL_REVISION, dwAceFlags, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, label))
	{
		dwErr = SetNamedSecurityInfoW(lpFileNameW, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, pacl);
		SetLastError(dwErr);
		bRes = dwErr==ERROR_SUCCESS;
	}
err:
	if (!bRes) w_win32_error = GetLastError();
	LocalFree(lpFileNameW);
	return bRes;
}

"###,
        r###"BOOL SetMandatoryLabelFile(LPCSTR lpFileName, DWORD dwMandatoryLabelRID, DWORD dwAceFlags)
{
#ifdef ZAPRET_NATIVE_WINDOWS

	wchar_t *wide = wf_path_utf16(lpFileName);
	if (!wide)
	{
		w_win32_error = GetLastError();
		return FALSE;
	}
	BOOL result = SetMandatoryLabelFileW(wide, dwMandatoryLabelRID, dwAceFlags);
	free(wide);
	return result;
#else
	BOOL bRes=FALSE;
	DWORD dwErr, dwFileAttributes;
	char buf_label[16], buf_pacl[32];
	PSID label = (PSID)buf_label;
	PACL pacl = (PACL)buf_pacl;
	LPWSTR lpFileNameW = NULL;
	size_t szFileName;

	szFileName = strlen(lpFileName);
	if (!(lpFileNameW = (LPWSTR)LocalAlloc(LMEM_FIXED,(szFileName+1)*sizeof(WCHAR))))
		goto err;

	if (!MultiByteToWideChar(CP_UTF8, 0, lpFileName, -1, lpFileNameW, szFileName+1))
		goto err;

	if (!strncmp(lpFileName,"\\\\.\\",4))
		dwFileAttributes = 0;
	else
	{
		dwFileAttributes = GetFileAttributesW(lpFileNameW);
		if (dwFileAttributes == INVALID_FILE_ATTRIBUTES) goto err;
	}
	InitializeSid(label, &label_authority, 1);
	*GetSidSubAuthority(label, 0) = dwMandatoryLabelRID;
	if (InitializeAcl(pacl, sizeof(buf_pacl), ACL_REVISION) && AddMandatoryAce(pacl, (dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? ACL_REVISION_DS : ACL_REVISION, dwAceFlags, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, label))
	{
		dwErr = SetNamedSecurityInfoW(lpFileNameW, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, pacl);
		SetLastError(dwErr);
		bRes = dwErr==ERROR_SUCCESS;
	}
err:
	if (!bRes) w_win32_error = GetLastError();
	LocalFree(lpFileNameW);
	return bRes;
#endif
}

"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"BOOL SetMandatoryLabelFile(LPCSTR"###,
        r###"BOOL SetMandatoryLabelFileW(LPCWSTR, DWORD, DWORD);
BOOL SetMandatoryLabelFile(LPCSTR"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"bool ensure_file_access(const char *filename)
{
	bool b=false;
	size_t l = cygwin_conv_path(CCP_POSIX_TO_WIN_W | CCP_ABSOLUTE, filename, NULL, 0);
	WCHAR *wfilename = (WCHAR*)malloc(l);
	if (wfilename)
	{
		if (!cygwin_conv_path(CCP_POSIX_TO_WIN_W | CCP_ABSOLUTE, filename, wfilename, l))
			b = SetMandatoryLabelFileW(wfilename, SECURITY_MANDATORY_LOW_RID, 0);
		free(wfilename);
	}
	return b;
}
"###,
        r###"bool ensure_file_access(const char *filename)
{
#ifdef ZAPRET_NATIVE_WINDOWS

	return SetMandatoryLabelFile(filename, SECURITY_MANDATORY_LOW_RID, 0);
#else
	bool b=false;
	size_t l = cygwin_conv_path(CCP_POSIX_TO_WIN_W | CCP_ABSOLUTE, filename, NULL, 0);
	WCHAR *wfilename = (WCHAR*)malloc(l);
	if (wfilename)
	{
		if (!cygwin_conv_path(CCP_POSIX_TO_WIN_W | CCP_ABSOLUTE, filename, wfilename, l))
			b = SetMandatoryLabelFileW(wfilename, SECURITY_MANDATORY_LOW_RID, 0);
		free(wfilename);
	}
	return b;
#endif
}
"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"bool ensure_dir_access(const char *dir)
{
	bool b=false;
	size_t l = cygwin_conv_path(CCP_POSIX_TO_WIN_W | CCP_ABSOLUTE, dir, NULL, 0);
	WCHAR *wdir = (WCHAR*)malloc(l);
	if (wdir)
	{
		if (!cygwin_conv_path(CCP_POSIX_TO_WIN_W | CCP_ABSOLUTE, dir, wdir, l))
			b=SetMandatoryLabelFileW(wdir, SECURITY_MANDATORY_LOW_RID, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
		free(wdir);
	}
	return b;
}

"###,
        r###"bool ensure_dir_access(const char *dir)
{
#ifdef ZAPRET_NATIVE_WINDOWS

	return SetMandatoryLabelFile(dir, SECURITY_MANDATORY_LOW_RID, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
#else
	bool b=false;
	size_t l = cygwin_conv_path(CCP_POSIX_TO_WIN_W | CCP_ABSOLUTE, dir, NULL, 0);
	WCHAR *wdir = (WCHAR*)malloc(l);
	if (wdir)
	{
		if (!cygwin_conv_path(CCP_POSIX_TO_WIN_W | CCP_ABSOLUTE, dir, wdir, l))
			b=SetMandatoryLabelFileW(wdir, SECURITY_MANDATORY_LOW_RID, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
		free(wdir);
	}
	return b;
#endif
}

"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"		size_t l = cygwin_conv_path(CCP_WIN_W_TO_POSIX | CCP_ABSOLUTE, pszPath, NULL, 0);"###,
        r###"#ifdef ZAPRET_NATIVE_WINDOWS
		char *utf8 = wf_wide_to_utf8(pszPath);
		if (utf8)
		{
			b = wf_setenv("APPDATALOW", utf8, 1) == 0;
			free(utf8);
		}
#else
		size_t l = cygwin_conv_path(CCP_WIN_W_TO_POSIX | CCP_ABSOLUTE, pszPath, NULL, 0);"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"		CoTaskMemFree(pszPath);"###,
        r###"#endif
		CoTaskMemFree(pszPath);"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"// cygwin uses nt directory to store it's state. low mandatory breaks write access there and cause some functions to fail
// it's not possible to reproduce exact directory names, have to iterate and set low integrity to all
BOOL RelaxCygwinNTDir()
{
	NTSTATUS status;
	PROCESS_SESSION_INFORMATION psi;
	WCHAR bno_name[32], cyg_name[256];
	CHAR scyg_name[256];
	UNICODE_STRING bno_us, cyg_us;
	OBJECT_ATTRIBUTES attr;
	HANDLE hDir, hDirCyg;
	BYTE buf[4096];
	ULONG context, rsize;
	BOOL b,ball,restart;
	POBJECT_DIRECTORY_INFORMATION pdir;

	LPCTSTR Privs[] = { SE_TAKE_OWNERSHIP_NAME , NULL };

	if (!AdjustPrivilegesForCurrentProcess(Privs, TRUE))
		return FALSE;

	status = NtQueryInformationProcess(GetCurrentProcess(),	ProcessSessionInformation, &psi, sizeof psi, NULL);
	if (NT_SUCCESS(status))
		swprintf(bno_name, sizeof(bno_name)/sizeof(*bno_name), L"\\Sessions\\BNOLINKS\\%u", psi.SessionId);
	else
		swprintf(bno_name, sizeof(bno_name)/sizeof(*bno_name), L"\\BaseNamedObjects");

	RtlInitUnicodeString(&bno_us, bno_name);
	InitializeObjectAttributes(&attr, &bno_us, 0, NULL, NULL);

	ball = TRUE;
	w_win32_error = 0;
	status = NtOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &attr);
	if (NT_SUCCESS(status))
	{
		context = 0;
		restart = TRUE;
		while (NT_SUCCESS(status = NtQueryDirectoryObject(hDir, buf, sizeof(buf), restart, FALSE, &context, &rsize)))
		{

			for (pdir = (POBJECT_DIRECTORY_INFORMATION)buf; pdir->Name.Length; pdir++)
				if (pdir->TypeName.Length == 18 && !memcmp(pdir->TypeName.Buffer, L"Directory", 18) &&
					pdir->Name.Length >= 14 && !memcmp(pdir->Name.Buffer, L"cygwin1", 14))
				{
					swprintf(cyg_name, sizeof(cyg_name)/sizeof(*cyg_name), L"%ls\\%ls", bno_name, pdir->Name.Buffer);
					if (!WideCharToMultiByte(CP_ACP, 0, cyg_name, -1, scyg_name, sizeof(scyg_name), NULL, NULL))
						*scyg_name=0;
					RtlInitUnicodeString(&cyg_us, cyg_name);
					InitializeObjectAttributes(&attr, &cyg_us, 0, NULL, NULL);
					status = NtOpenDirectoryObject(&hDirCyg, WRITE_OWNER, &attr);
					if (NT_SUCCESS(status))
					{
						b = SetMandatoryLabelObject(hDirCyg, SE_KERNEL_OBJECT, SECURITY_MANDATORY_LOW_RID, ACL_REVISION_DS, 0);
						if (!b)
						{
							w_win32_error = GetLastError();
							DLOG_ERR("could not set integrity label on '%s' . error %u\n", scyg_name, w_win32_error);
						}
						else
							DLOG("set low integrity label on '%s'\n", scyg_name);
						ball = ball && b;
						NtClose(hDirCyg);
					}
				}
			restart = FALSE;
		}
		NtClose(hDir);
	}
	else
	{
		w_win32_error = RtlNtStatusToDosError(status);
		return FALSE;
	}

	return ball;
}



"###,
        r###"#ifndef ZAPRET_NATIVE_WINDOWS
// cygwin uses nt directory to store it's state. low mandatory breaks write access there and cause some functions to fail
// it's not possible to reproduce exact directory names, have to iterate and set low integrity to all
BOOL RelaxCygwinNTDir()
{
	NTSTATUS status;
	PROCESS_SESSION_INFORMATION psi;
	WCHAR bno_name[32], cyg_name[256];
	CHAR scyg_name[256];
	UNICODE_STRING bno_us, cyg_us;
	OBJECT_ATTRIBUTES attr;
	HANDLE hDir, hDirCyg;
	BYTE buf[4096];
	ULONG context, rsize;
	BOOL b,ball,restart;
	POBJECT_DIRECTORY_INFORMATION pdir;

	LPCTSTR Privs[] = { SE_TAKE_OWNERSHIP_NAME , NULL };

	if (!AdjustPrivilegesForCurrentProcess(Privs, TRUE))
		return FALSE;

	status = NtQueryInformationProcess(GetCurrentProcess(),	ProcessSessionInformation, &psi, sizeof psi, NULL);
	if (NT_SUCCESS(status))
		swprintf(bno_name, sizeof(bno_name)/sizeof(*bno_name), L"\\Sessions\\BNOLINKS\\%u", psi.SessionId);
	else
		swprintf(bno_name, sizeof(bno_name)/sizeof(*bno_name), L"\\BaseNamedObjects");

	RtlInitUnicodeString(&bno_us, bno_name);
	InitializeObjectAttributes(&attr, &bno_us, 0, NULL, NULL);

	ball = TRUE;
	w_win32_error = 0;
	status = NtOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &attr);
	if (NT_SUCCESS(status))
	{
		context = 0;
		restart = TRUE;
		while (NT_SUCCESS(status = NtQueryDirectoryObject(hDir, buf, sizeof(buf), restart, FALSE, &context, &rsize)))
		{

			for (pdir = (POBJECT_DIRECTORY_INFORMATION)buf; pdir->Name.Length; pdir++)
				if (pdir->TypeName.Length == 18 && !memcmp(pdir->TypeName.Buffer, L"Directory", 18) &&
					pdir->Name.Length >= 14 && !memcmp(pdir->Name.Buffer, L"cygwin1", 14))
				{
					swprintf(cyg_name, sizeof(cyg_name)/sizeof(*cyg_name), L"%ls\\%ls", bno_name, pdir->Name.Buffer);
					if (!WideCharToMultiByte(CP_ACP, 0, cyg_name, -1, scyg_name, sizeof(scyg_name), NULL, NULL))
						*scyg_name=0;
					RtlInitUnicodeString(&cyg_us, cyg_name);
					InitializeObjectAttributes(&attr, &cyg_us, 0, NULL, NULL);
					status = NtOpenDirectoryObject(&hDirCyg, WRITE_OWNER, &attr);
					if (NT_SUCCESS(status))
					{
						b = SetMandatoryLabelObject(hDirCyg, SE_KERNEL_OBJECT, SECURITY_MANDATORY_LOW_RID, ACL_REVISION_DS, 0);
						if (!b)
						{
							w_win32_error = GetLastError();
							DLOG_ERR("could not set integrity label on '%s' . error %u\n", scyg_name, w_win32_error);
						}
						else
							DLOG("set low integrity label on '%s'\n", scyg_name);
						ball = ball && b;
						NtClose(hDirCyg);
					}
				}
			restart = FALSE;
		}
		NtClose(hDir);
	}
	else
	{
		w_win32_error = RtlNtStatusToDosError(status);
		return FALSE;
	}

	return ball;
}
#endif

"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"	JOBOBJECT_BASIC_LIMIT_INFORMATION basic_limit;"###,
        r###"	JOBOBJECT_BASIC_LIMIT_INFORMATION basic_limit = {0};"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"	JOBOBJECT_BASIC_UI_RESTRICTIONS basic_ui;"###,
        r###"	JOBOBJECT_BASIC_UI_RESTRICTIONS basic_ui = {0};"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"		if (!RelaxCygwinNTDir())
			DLOG_ERR("could not set low mandatory label on cygwin NT directory. some functions may not work. error %u\n", w_win32_error);"###,
        r###"#ifndef ZAPRET_NATIVE_WINDOWS
		if (!RelaxCygwinNTDir())
			DLOG_ERR("could not set low mandatory label on cygwin NT directory. some functions may not work. error %u\n", w_win32_error);
#endif"###,
    )?;
    replace(
        nfq,
        "lua.c",
        r###"#include <sys/ioctl.h>"###,
        r###"#ifndef ZAPRET_NATIVE_WINDOWS
#include <sys/ioctl.h>
#endif"###,
    )?;
    replace(
        nfq,
        "lua.c",
        r###"#else
#include <ifaddrs.h>
#endif"###,
        r###"#elif !defined(ZAPRET_NATIVE_WINDOWS)
#include <ifaddrs.h>
#endif"###,
    )?;
    replace(
        nfq,
        "lua.c",
        r###"// header hell conflicts between unix and win32
typedef struct in6_addr IN6_ADDR, *PIN6_ADDR, *LPIN6_ADDR;
typedef struct sockaddr	*LPSOCKADDR;
typedef struct _SOCKET_ADDRESS {
  LPSOCKADDR lpSockaddr;
  int iSockaddrLength;
} SOCKET_ADDRESS,*PSOCKET_ADDRESS,*LPSOCKET_ADDRESS;
#define _WINSOCK2API_
#define _NETIOAPI_H_
"###,
        r###"#ifndef ZAPRET_NATIVE_WINDOWS
// header hell conflicts between unix and win32
typedef struct in6_addr IN6_ADDR, *PIN6_ADDR, *LPIN6_ADDR;
typedef struct sockaddr	*LPSOCKADDR;
typedef struct _SOCKET_ADDRESS {
  LPSOCKADDR lpSockaddr;
  int iSockaddrLength;
} SOCKET_ADDRESS,*PSOCKET_ADDRESS,*LPSOCKET_ADDRESS;
#define _WINSOCK2API_
#define _NETIOAPI_H_
#endif
"###,
    )?;
    replace(
        nfq,
        "lua.c",
        r###"	struct stat st;
	if (stat(luaL_checkstring(L,1), &st))"###,
        r###"#ifdef ZAPRET_NATIVE_WINDOWS
	wf_file_info st;
	if (wf_file_stat(luaL_checkstring(L,1), &st))
#else
	struct stat st;
	if (stat(luaL_checkstring(L,1), &st))
#endif"###,
    )?;
    replace(
        nfq,
        "lua.c",
        r###"		lua_pushf_number(L,"mtime", st.st_mtim.tv_sec + st.st_mtim.tv_nsec/1000000000.);"###,
        r###"#ifdef ZAPRET_NATIVE_WINDOWS
		lua_pushf_number(L,"mtime", st.modified.tv_sec + st.modified.tv_nsec/1000000000.);
#else
		lua_pushf_number(L,"mtime", st.st_mtim.tv_sec + st.st_mtim.tv_nsec/1000000000.);
#endif"###,
    )?;
    replace(
        nfq,
        "lua.c",
        r###"		const char *ftype;
		switch(st.st_mode & S_IFMT)"###,
        r###"#ifdef ZAPRET_NATIVE_WINDOWS
		const char *ftype = (st.st_mode & _S_IFMT) == _S_IFDIR ? "dir" : "file";
#else
		const char *ftype;
		switch(st.st_mode & S_IFMT)"###,
    )?;
    replace(
        nfq,
        "lua.c",
        r###"		lua_pushf_str(L, "type", ftype);"###,
        r###"#endif
		lua_pushf_str(L, "type", ftype);"###,
    )?;
    replace(
        nfq,
        "lua.c",
        r###"		lua_pushf_str(L,"zone", t.tm_zone);"###,
        r###"#ifdef ZAPRET_NATIVE_WINDOWS
		char zone[128];
		if (timefunc == gmtime_r) strcpy(zone,"UTC");
		else if (!strftime(zone,sizeof(zone),"%Z",&t)) zone[0]=0;
		lua_pushf_str(L,"zone", zone);
#else
		lua_pushf_str(L,"zone", t.tm_zone);
#endif"###,
    )?;
    replace(
        nfq,
        "helpers.c",
        r###"bool fill_crypto_random_bytes(uint8_t *p, size_t sz)
{
	ssize_t rd;
	int fd;

#if defined(__linux__) || defined(ZAPRET_WINDOWS)
	for (; sz && (rd = getrandom(p, sz, GRND_NONBLOCK)) > 0; p += rd, sz -= rd);
	if (sz)
#elif defined(BSD)
	while (sz)
	{
		rd = sz < 256 ? sz : 256; // BSD limitation
		if (getentropy(p, rd)) break;
		p += rd; sz -= rd;
	}
	if (sz)
#endif
	{
		if ((fd = open("/dev/random", O_NONBLOCK)) >= 0)
		{
			do
			{
				if ((rd = read_intr(fd, p, sz)) > 0)
				{
					p += rd; sz -= rd;
				}
			} while (sz && rd > 0);
			close(fd);
		}
		if (sz && (fd = open("/dev/urandom", 0)) >= 0)
		{
			do
			{
				if ((rd = read_intr(fd, p, sz)) > 0)
				{
					p += rd; sz -= rd;
				}
			} while (sz && rd > 0);
			close(fd);
		}
	}
	return !sz;
}

"###,
        r###"bool fill_crypto_random_bytes(uint8_t *p, size_t sz)
{
#ifdef ZAPRET_NATIVE_WINDOWS
	while (sz)
	{
		size_t chunk = sz > UINT32_MAX ? UINT32_MAX : sz;
		ssize_t count = getrandom(p, chunk, GRND_NONBLOCK);
		if (count <= 0) return false;
		p += count;
		sz -= count;
	}
	return true;
#else
	ssize_t rd;
	int fd;

#if defined(__linux__) || defined(ZAPRET_WINDOWS)
	for (; sz && (rd = getrandom(p, sz, GRND_NONBLOCK)) > 0; p += rd, sz -= rd);
	if (sz)
#elif defined(BSD)
	while (sz)
	{
		rd = sz < 256 ? sz : 256; // BSD limitation
		if (getentropy(p, rd)) break;
		p += rd; sz -= rd;
	}
	if (sz)
#endif
	{
		if ((fd = open("/dev/random", O_NONBLOCK)) >= 0)
		{
			do
			{
				if ((rd = read_intr(fd, p, sz)) > 0)
				{
					p += rd; sz -= rd;
				}
			} while (sz && rd > 0);
			close(fd);
		}
		if (sz && (fd = open("/dev/urandom", 0)) >= 0)
		{
			do
			{
				if ((rd = read_intr(fd, p, sz)) > 0)
				{
					p += rd; sz -= rd;
				}
			} while (sz && rd > 0);
			close(fd);
		}
	}
	return !sz;
#endif
}

"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"	sigset_t pending;"###,
        r###"#ifndef ZAPRET_NATIVE_WINDOWS
	sigset_t pending;
#endif"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"void dbgprint_socket_buffers(int fd)"###,
        r###"#ifdef ZAPRET_NATIVE_WINDOWS
void dbgprint_socket_buffers(SOCKET fd)
#else
void dbgprint_socket_buffers(int fd)
#endif"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"bool set_socket_buffers(int fd, int rcvbuf, int sndbuf)"###,
        r###"#ifdef ZAPRET_NATIVE_WINDOWS
bool set_socket_buffers(SOCKET fd, int rcvbuf, int sndbuf)
#else
bool set_socket_buffers(int fd, int rcvbuf, int sndbuf)
#endif"###,
    )?;
    replace(
        nfq,
        "darkmagic.h",
        r###"void dbgprint_socket_buffers(int fd);"###,
        r###"#ifdef ZAPRET_NATIVE_WINDOWS
void dbgprint_socket_buffers(SOCKET fd);
#else
void dbgprint_socket_buffers(int fd);
#endif"###,
    )?;
    replace(
        nfq,
        "darkmagic.h",
        r###"bool set_socket_buffers(int fd, int rcvbuf, int sndbuf);"###,
        r###"#ifdef ZAPRET_NATIVE_WINDOWS
bool set_socket_buffers(SOCKET fd, int rcvbuf, int sndbuf);
#else
bool set_socket_buffers(int fd, int rcvbuf, int sndbuf);
#endif"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, &sz)"###,
        r###"getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&v, &sz)"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, &sz)"###,
        r###"getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&v, &sz)"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(int))"###,
        r###"setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvbuf, sizeof(int))"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(int))"###,
        r###"setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char*)&sndbuf, sizeof(int))"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"DLOG("fd=%d SO_RCVBUF=%d\n", fd, v);"###,
        r###"DLOG("fd=%llu SO_RCVBUF=%d\n", (unsigned long long)fd, v);"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"DLOG("fd=%d SO_SNDBUF=%d\n", fd, v);"###,
        r###"DLOG("fd=%llu SO_SNDBUF=%d\n", (unsigned long long)fd, v);"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"DLOG("set_socket_buffers fd=%d rcvbuf=%d sndbuf=%d\n", fd, rcvbuf, sndbuf);"###,
        r###"DLOG("set_socket_buffers fd=%llu rcvbuf=%d sndbuf=%d\n", (unsigned long long)fd, rcvbuf, sndbuf);"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"bool get_source_ip4(const struct in_addr *target, struct in_addr *source)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) return false;

	struct sockaddr_in serv,name;
	socklen_t namelen;

	memset(&serv,0,sizeof(serv)); // or valgrind complains about uninitialized
	serv.sin_family = AF_INET;
	serv.sin_addr = *target;
	serv.sin_port = 0xFFFF;

	// Connect triggers the kernel's route lookup
	if (!connect(sock, (const struct sockaddr*)&serv, sizeof(serv)))
	{
		namelen = sizeof(name);
		if (!getsockname(sock, (struct sockaddr*)&name, &namelen))
		{
			close(sock);
			*source = name.sin_addr;
			return true;
		}
	}
	close(sock);
	return false;
}
"###,
        r###"#ifdef ZAPRET_NATIVE_WINDOWS
bool get_source_ip4(const struct in_addr *target, struct in_addr *source)
{
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET) return false;

	struct sockaddr_in serv,name;
	socklen_t namelen;

	memset(&serv,0,sizeof(serv)); // or valgrind complains about uninitialized
	serv.sin_family = AF_INET;
	serv.sin_addr = *target;
	serv.sin_port = 0xFFFF;

	// Connect triggers the kernel's route lookup
	if (!connect(sock, (const struct sockaddr*)&serv, sizeof(serv)))
	{
		namelen = sizeof(name);
		if (!getsockname(sock, (struct sockaddr*)&name, &namelen))
		{
			closesocket(sock);
			*source = name.sin_addr;
			return true;
		}
	}
	closesocket(sock);
	return false;
}
#else
bool get_source_ip4(const struct in_addr *target, struct in_addr *source)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) return false;

	struct sockaddr_in serv,name;
	socklen_t namelen;

	memset(&serv,0,sizeof(serv)); // or valgrind complains about uninitialized
	serv.sin_family = AF_INET;
	serv.sin_addr = *target;
	serv.sin_port = 0xFFFF;

	// Connect triggers the kernel's route lookup
	if (!connect(sock, (const struct sockaddr*)&serv, sizeof(serv)))
	{
		namelen = sizeof(name);
		if (!getsockname(sock, (struct sockaddr*)&name, &namelen))
		{
			close(sock);
			*source = name.sin_addr;
			return true;
		}
	}
	close(sock);
	return false;
}
#endif

"###,
    )?;
    replace(
        nfq,
        "darkmagic.c",
        r###"bool get_source_ip6(const struct in6_addr *target, struct in6_addr *source)
{
	int sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0) return false;

	struct sockaddr_in6 serv,name;
	socklen_t namelen;

	memset(&serv,0,sizeof(serv)); // or valgrind complains about uninitialized
	serv.sin6_family = AF_INET6;
	serv.sin6_addr = *target;
	serv.sin6_port = 0xFFFF;

	// Connect triggers the kernel's route lookup
	if (!connect(sock, (const struct sockaddr*)&serv, sizeof(serv)))
	{
		namelen = sizeof(name);
		if (!getsockname(sock, (struct sockaddr*)&name, &namelen))
		{
			close(sock);
			*source = name.sin6_addr;
			return true;
		}
	}

	close(sock);
	return false;
}


"###,
        r###"#ifdef ZAPRET_NATIVE_WINDOWS
bool get_source_ip6(const struct in6_addr *target, struct in6_addr *source)
{
	SOCKET sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET) return false;

	struct sockaddr_in6 serv,name;
	socklen_t namelen;

	memset(&serv,0,sizeof(serv)); // or valgrind complains about uninitialized
	serv.sin6_family = AF_INET6;
	serv.sin6_addr = *target;
	serv.sin6_port = 0xFFFF;

	// Connect triggers the kernel's route lookup
	if (!connect(sock, (const struct sockaddr*)&serv, sizeof(serv)))
	{
		namelen = sizeof(name);
		if (!getsockname(sock, (struct sockaddr*)&name, &namelen))
		{
			closesocket(sock);
			*source = name.sin6_addr;
			return true;
		}
	}

	closesocket(sock);
	return false;
}
#else
bool get_source_ip6(const struct in6_addr *target, struct in6_addr *source)
{
	int sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0) return false;

	struct sockaddr_in6 serv,name;
	socklen_t namelen;

	memset(&serv,0,sizeof(serv)); // or valgrind complains about uninitialized
	serv.sin6_family = AF_INET6;
	serv.sin6_addr = *target;
	serv.sin6_port = 0xFFFF;

	// Connect triggers the kernel's route lookup
	if (!connect(sock, (const struct sockaddr*)&serv, sizeof(serv)))
	{
		namelen = sizeof(name);
		if (!getsockname(sock, (struct sockaddr*)&name, &namelen))
		{
			close(sock);
			*source = name.sin6_addr;
			return true;
		}
	}

	close(sock);
	return false;
}
#endif

"###,
    )?;
    Ok(())
}

fn replace(root: &Path, name: &str, old: &str, new: &str) -> Result<()> {
    let path = root.join(name);
    let text = fs::read_to_string(&path).with_context(|| path.display().to_string())?;
    ensure!(
        text.matches(old).count() == 1,
        "Pinned native file patch changed: {name}"
    );
    fs::write(&path, text.replacen(old, new, 1))?;
    Ok(())
}
