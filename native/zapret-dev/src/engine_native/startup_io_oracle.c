/* MIT. Reference stdio/UI are mocked; real tests own their file and window. */
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include "win_files.h"
#undef main
static unsigned pid_cases,io_repairs,unsigned_repairs,icon_cases,shared_repairs,timeout_cases,boundaries;
#define CHECK(value) do {if(!(value)){fprintf(stderr,"FAIL startup IO pid=%u icon=%u boundary=%u line=%d error=%lu: %s\n",pid_cases,icon_cases,boundaries,__LINE__,(unsigned long)GetLastError(),#value);exit(1);}}while(0)
typedef struct {DWORD (WINAPI *process)(void);uint32_t (*save)(const char *,const BYTE *,size_t);} pid_ops;
typedef struct {HWND (WINAPI *window)(void);HMODULE (WINAPI *module)(const WCHAR *);HANDLE (WINAPI *load)(HINSTANCE,const WCHAR *,UINT,int,int,UINT);LRESULT (WINAPI *send)(HWND,UINT,WPARAM,LPARAM,UINT,UINT,PDWORD_PTR);} icon_ops;
_Static_assert(sizeof(pid_ops)==16 && sizeof(icon_ops)==32,"Rust startup IO callback ABI");
uint32_t zapret_startup_pid(const char *,const void *);
bool zapret_startup_write_pid(const char *,void (*)(DWORD));
uint32_t zapret_startup_icon(const void *);
struct pid_state {DWORD pid;unsigned failure,process_calls,save_calls;char bytes[32];};
static struct pid_state *active_pid;
static DWORD WINAPI mock_pid(void){++active_pid->process_calls;return active_pid->pid;}
static int reference_pid(void){return (int)mock_pid();}
static uint32_t mock_save(const char *filename,const BYTE *bytes,size_t size){CHECK(!strcmp(filename,"fixture.pid") && bytes && size && size<sizeof(active_pid->bytes));++active_pid->save_calls;memcpy(active_pid->bytes,bytes,size);active_pid->bytes[size]=0;const DWORD errors[]={0,ERROR_ACCESS_DENIED,ERROR_DISK_FULL,ERROR_WRITE_FAULT};return errors[active_pid->failure];}
static FILE *mock_open(const char *filename,const char *mode){CHECK(!strcmp(filename,"fixture.pid") && !strcmp(mode,"w"));return active_pid->failure==1?NULL:(FILE *)(uintptr_t)0x1111;}
static int mock_fprintf(FILE *file,const char *format,...){CHECK(file==(FILE *)(uintptr_t)0x1111 && !strcmp(format,"%d"));va_list arguments;va_start(arguments,format);int pid=va_arg(arguments,int);va_end(arguments);if(active_pid->failure==2)return -1;return snprintf(active_pid->bytes,sizeof(active_pid->bytes),"%d",pid);}
static int mock_fclose(FILE *file){CHECK(file==(FILE *)(uintptr_t)0x1111);return active_pid->failure==3?EOF:0;}
#undef fopen
#define fopen mock_open
#define fprintf mock_fprintf
#define fclose mock_fclose
#define getpid reference_pid
#define writepid reference_writepid
#include "startup_pid_reference.inc"
#undef fopen
#undef fprintf
#undef fclose
#undef getpid
#undef writepid
static const pid_ops pids={mock_pid,mock_save};
static void compare_pid(DWORD pid,unsigned failure)
{
    struct pid_state left={0},right={0};left.pid=pid;left.failure=failure;right=left;active_pid=&left;BOOL expected=reference_writepid("fixture.pid");active_pid=&right;DWORD result=zapret_startup_pid("fixture.pid",&pids);char unsigned_pid[32];snprintf(unsigned_pid,sizeof(unsigned_pid),"%lu",(unsigned long)pid);CHECK(!strcmp(right.bytes,unsigned_pid) && right.process_calls==1 && right.save_calls==1);
    if(failure==2 || failure==3){CHECK(expected && result!=0);++io_repairs;}else CHECK(!!expected==!result);
    if(!failure){if(pid<=INT32_MAX)CHECK(!strcmp(left.bytes,right.bytes));else {CHECK(left.bytes[0]=='-' && right.bytes[0]!='-');++unsigned_repairs;}}
    ++pid_cases;
}
struct icon_state {unsigned absent,missing_module,load_fail,send_fail,old_icon,loads,sends,destroys,module_calls;UINT widths[2];WPARAM kinds[2];};
static struct icon_state *active_icon;
static HWND WINAPI mock_window(void){return active_icon->absent?NULL:(HWND)(uintptr_t)0x1000;}
static HMODULE WINAPI mock_module(const WCHAR *name){CHECK(!name);++active_icon->module_calls;return active_icon->missing_module?NULL:(HMODULE)(uintptr_t)0x2000;}
static HANDLE WINAPI mock_load(HINSTANCE module,const WCHAR *name,UINT type,int width,int height,UINT flags)
{CHECK((!module || module==(HINSTANCE)(uintptr_t)0x2000) && (uintptr_t)name==1 && type==IMAGE_ICON && width==height && flags==(LR_DEFAULTCOLOR|LR_SHARED) && active_icon->loads<2);unsigned index=active_icon->loads++;active_icon->widths[index]=width;return active_icon->load_fail&(1u<<index)?NULL:(HANDLE)(uintptr_t)(0x3000+index);}
static HANDLE WINAPI reference_load(HINSTANCE module,const void *ordinal,UINT type,int width,int height,UINT flags)
{CHECK((uintptr_t)ordinal==1);return mock_load(module,MAKEINTRESOURCEW(1),type,width,height,flags);}
static LRESULT WINAPI mock_message(HWND window,UINT message,WPARAM kind,LPARAM icon)
{CHECK(window==(HWND)(uintptr_t)0x1000 && message==WM_SETICON && kind<2 && icon==(LPARAM)(0x3000+kind) && active_icon->sends<2);active_icon->kinds[active_icon->sends++]=kind;return active_icon->old_icon?(LRESULT)0x4000:0;}
static LRESULT WINAPI mock_timeout(HWND window,UINT message,WPARAM kind,LPARAM icon,UINT flags,UINT timeout,PDWORD_PTR result)
{CHECK(flags==(SMTO_ABORTIFHUNG|SMTO_BLOCK|SMTO_ERRORONEXIT) && timeout==200 && result);*result=mock_message(window,message,kind,icon);return active_icon->send_fail&(1u<<kind)?0:1;}
static BOOL WINAPI mock_destroy(HICON icon){CHECK(icon==(HICON)(uintptr_t)0x4000);++active_icon->destroys;return TRUE;}
#undef GetModuleHandle
#undef LoadImage
#undef SendMessage
#define GetConsoleWindow mock_window
#define GetModuleHandle mock_module
#define LoadImage reference_load
#define SendMessage mock_message
#define DestroyIcon mock_destroy
#define TITLE_ICON MAKEINTRESOURCE(1)
#define WinSetIcon reference_WinSetIcon
#include "startup_icon_reference.inc"
#undef GetConsoleWindow
#undef GetModuleHandle
#undef LoadImage
#undef SendMessage
#undef DestroyIcon
#undef TITLE_ICON
#undef WinSetIcon
static const icon_ops icons={mock_window,mock_module,mock_load,mock_timeout};
static void compare_icon(unsigned absent,unsigned missing,unsigned load,unsigned send,unsigned old)
{
    struct icon_state left={0},right={0};left.absent=absent;left.missing_module=missing;left.load_fail=load;left.send_fail=send;left.old_icon=old;right=left;active_icon=&left;reference_WinSetIcon();active_icon=&right;DWORD installed=zapret_startup_icon(&icons);CHECK(!right.destroys && right.module_calls==(absent?0:1));
    if(absent || missing)CHECK(!installed && !right.loads && !right.sends);
    else {CHECK(right.loads<=left.loads && right.sends<=left.sends);for(unsigned i=0;i<right.loads;++i)CHECK(left.widths[i]==right.widths[i]);for(unsigned i=0;i<right.sends;++i)CHECK(left.kinds[i]==right.kinds[i]);unsigned success=0;for(unsigned i=0;i<right.sends;++i)success+=!(send&(1u<<right.kinds[i]));CHECK(installed==success);if(!send)CHECK(right.loads==left.loads && right.sends==left.sends);else if(right.sends && send&(1u<<right.kinds[right.sends-1]))++timeout_cases;}
    if(left.destroys)++shared_repairs;++icon_cases;
}
bool writepid(const char *);
#include "startup_icon_windows.inc"
static unsigned published_pid_errors;
static void pid_publish_error(DWORD error)
{
    CHECK(GetLastError() == error && error == ERROR_PATH_NOT_FOUND);
    ++published_pid_errors;
}
static HWND private_window;static HANDLE window_ready,message_entered,message_release;static LONG block_message,real_loads;
static LRESULT CALLBACK window_proc(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{if(message==WM_SETICON && InterlockedCompareExchange(&block_message,0,0)){CHECK(SetEvent(message_entered) && WaitForSingleObject(message_release,5000)==WAIT_OBJECT_0);return 0;}if(message==WM_CLOSE){DestroyWindow(window);return 0;}if(message==WM_DESTROY){PostQuitMessage(0);return 0;}return DefWindowProcW(window,message,wparam,lparam);}
static DWORD WINAPI window_thread(void *unused)
{(void)unused;WNDCLASSW type={0};type.lpfnWndProc=window_proc;type.hInstance=GetModuleHandleW(NULL);type.lpszClassName=L"zapret-private-startup-icon";CHECK(RegisterClassW(&type));private_window=CreateWindowExW(0,type.lpszClassName,L"",0,0,0,0,0,HWND_MESSAGE,NULL,type.hInstance,NULL);CHECK(private_window && SetEvent(window_ready));MSG message;while(GetMessageW(&message,NULL,0,0)>0){TranslateMessage(&message);DispatchMessageW(&message);}CHECK(UnregisterClassW(type.lpszClassName,type.hInstance));return 0;}
static HWND WINAPI owned_window(void){return private_window;}
static HANDLE WINAPI shared_icon(HINSTANCE module,const WCHAR *name,UINT kind,int width,int height,UINT flags){CHECK(module==GetModuleHandleW(NULL) && (uintptr_t)name==1 && kind==IMAGE_ICON && width==height && flags==(LR_DEFAULTCOLOR|LR_SHARED));InterlockedIncrement(&real_loads);return LoadIconW(NULL,MAKEINTRESOURCEW(32512));}
static void real_icon(void)
{
    window_ready=CreateEventW(NULL,TRUE,FALSE,NULL);message_entered=CreateEventW(NULL,TRUE,FALSE,NULL);message_release=CreateEventW(NULL,TRUE,FALSE,NULL);CHECK(window_ready && message_entered && message_release);HANDLE thread=CreateThread(NULL,0,window_thread,NULL,0,NULL);CHECK(thread && WaitForSingleObject(window_ready,5000)==WAIT_OBJECT_0);
    icon_ops actual={owned_window,GetModuleHandleW,shared_icon,SendMessageTimeoutW};CHECK(zapret_startup_icon(&actual)==2 && real_loads==2);
    InterlockedExchange(&block_message,1);LARGE_INTEGER start,end,frequency;CHECK(QueryPerformanceFrequency(&frequency) && QueryPerformanceCounter(&start));DWORD installed=zapret_startup_icon(&actual);CHECK(QueryPerformanceCounter(&end));double elapsed=(end.QuadPart-start.QuadPart)*1000.0/frequency.QuadPart;
    CHECK(!installed && real_loads==3 && WaitForSingleObject(message_entered,0)==WAIT_OBJECT_0 && elapsed<2000.0);CHECK(SetEvent(message_release) && PostMessageW(private_window,WM_CLOSE,0,0) && WaitForSingleObject(thread,5000)==WAIT_OBJECT_0 && CloseHandle(thread));CHECK(CloseHandle(window_ready) && CloseHandle(message_entered) && CloseHandle(message_release));
    printf("PASS startup_icon_real private_window=1 responsive_updates=2 blocked_attempts=1 timeout_ms=200 elapsed_ms=%.2f\n",elapsed);
}
static void real_pid(void)
{
    WCHAR original[32768],directory[32768];DWORD length=GetTempPathW(32768,directory);CHECK(length && length<32640 && GetCurrentDirectoryW(32768,original));swprintf(directory+length,32768-length,L"zapret-private-pid-%lu-%llu",(unsigned long)GetCurrentProcessId(),(unsigned long long)GetTickCount64());CHECK(CreateDirectoryW(directory,NULL) && SetCurrentDirectoryW(directory));
    DWORD before=0,after=0;CHECK(GetProcessHandleCount(GetCurrentProcess(),&before));for(unsigned i=0;i<512;++i)CHECK(writepid("данные-é-中.pid"));CHECK(GetProcessHandleCount(GetCurrentProcess(),&after) && before==after);
    char expected[16],bytes[16]={0};snprintf(expected,sizeof(expected),"%lu",(unsigned long)GetCurrentProcessId());HANDLE file=CreateFileW(L"данные-é-中.pid",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);CHECK(file!=INVALID_HANDLE_VALUE);CHECK(!writepid("данные-é-中.pid") && GetLastError()==ERROR_SHARING_VIOLATION);DWORD read=0;CHECK(ReadFile(file,bytes,sizeof(bytes)-1,&read,NULL) && read==strlen(expected) && !strcmp(bytes,expected) && CloseHandle(file));CHECK(!writepid(".") && GetLastError()==ERROR_ACCESS_DENIED);
    CHECK(DeleteFileW(L"данные-é-中.pid") && SetCurrentDirectoryW(original) && RemoveDirectoryW(directory));printf("PASS startup_pid_real private_files=1 handle_cycles=512 unicode_paths=1 locked_file_preserved=1 directory_rejected=1\n");
}
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--real-pid")){real_pid();return 0;}if(argc==2 && !strcmp(argv[1],"--real-icon")){real_icon();return 0;}CHECK(argc==1);
    const DWORD values[]={0,1,9,10,99,100,123456789,INT32_MAX,0x80000000u,UINT32_MAX};
    for(unsigned repeat=0;repeat<128;++repeat)for(unsigned pid=0;pid<10;++pid)for(unsigned failure=0;failure<4;++failure)compare_pid(values[pid],failure);
    for(unsigned repeat=0;repeat<16;++repeat)for(unsigned absent=0;absent<2;++absent)for(unsigned missing=0;missing<2;++missing)for(unsigned load=0;load<4;++load)for(unsigned send=0;send<4;++send)for(unsigned old=0;old<2;++old)compare_icon(absent,missing,load,send,old);
    struct pid_state value={0};active_pid=&value;CHECK(zapret_startup_pid(NULL,&pids)==ERROR_INVALID_PARAMETER && !value.save_calls && !value.process_calls);++boundaries;CHECK(zapret_startup_pid("",&pids)==ERROR_PATH_NOT_FOUND && !value.save_calls && !value.process_calls);++boundaries;
    SetLastError(ERROR_SUCCESS);CHECK(!zapret_startup_write_pid("",pid_publish_error) && published_pid_errors==1 && GetLastError()==ERROR_PATH_NOT_FOUND);++boundaries;
    printf("PASS startup_io functions=2 pid_cases=%u io_error_repairs=%u unsigned_pid_repairs=%u icon_cases=%u foreign_icon_repairs=%u timeout_cases=%u boundaries=%u\n",pid_cases,io_repairs,unsigned_repairs,icon_cases,shared_repairs,timeout_cases,boundaries);return 0;
}
