/* MIT. Scripted interruption/error states and genuine shared UCRT stream ABI. */
#include "helpers.h"
#include "random.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <io.h>
#include <fcntl.h>
#undef main
static unsigned scripted, real_reads, real_lines, real_pipes, boundaries;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL engine stdio scripted=%u reads=%u lines=%u pipes=%u line=%d: %s\n", scripted, real_reads, real_lines, real_pipes, __LINE__, #condition); exit(1); } \
} while (0)
struct step { size_t count; int error, failed, ended; };
struct script { struct step steps[8]; unsigned index, cleared, offset; int error, failed, ended; };
static struct script *active;
static struct step advance(void)
{
    unsigned index = active->index++;
    struct step step = active->steps[index < 8 ? index : 7];
    active->error = step.error; active->failed = step.failed; active->ended = step.ended;
    return step;
}
static void fill(void *output, size_t length)
{
    for (size_t index = 0; index < length; ++index) ((uint8_t *)output)[index] = (uint8_t)(active->offset++ * 131);
}
static int script_read(int fd, void *output, unsigned count)
{
    CHECK(fd == 41);
    struct step step = advance();
    if (step.error) return -1;
    size_t length = step.count < count ? step.count : count;
    fill(output, length); return (int)length;
}
static size_t script_fread(void *output, size_t size, size_t count, FILE *stream)
{
    CHECK(stream == (FILE *)active);
    struct step step = advance();
    size_t length = step.count < count ? step.count : count;
    fill(output, length * size); return length;
}
static char *script_fgets(char *output, int capacity, FILE *stream)
{
    CHECK(stream == (FILE *)active);
    struct step step = advance();
    if (step.error || step.ended) return NULL;
    size_t length = step.count < (size_t)(capacity - 1) ? step.count : (size_t)(capacity - 1);
    for (size_t index = 0; index < length; ++index) output[index] = 'a' + (active->offset++ % 26);
    output[length] = 0; return output;
}
static int script_error(FILE *stream) { CHECK(stream == (FILE *)active); return active->failed; }
static int script_end(FILE *stream) { CHECK(stream == (FILE *)active); return active->ended; }
static void script_clear(FILE *stream) { CHECK(stream == (FILE *)active); ++active->cleared; active->failed = active->ended = 0; }
static int *script_errno(void) { return &active->error; }
typedef struct {
    int (*read_fd)(int, void *, unsigned);
    size_t (*read_file)(void *, size_t, size_t, FILE *);
    char *(*read_line)(char *, int, FILE *);
    int (*failed)(FILE *);
    int (*ended)(FILE *);
    void (*clear)(FILE *);
    int *(*error)(void);
} stream_ops;
static const stream_ops ops = {script_read, script_fread, script_fgets, script_error, script_end, script_clear, script_errno};
ssize_t zapret_engine_read(int, void *, size_t, const stream_ops *);
bool zapret_engine_fread(void *, size_t, size_t, FILE *, size_t *, const stream_ops *);
char *zapret_engine_fgets(char *, int, FILE *, const stream_ops *);
bool zapret_engine_crypto_random(uint8_t *, size_t);

#undef errno
#define errno (active->error)
#define read script_read
#define fread script_fread
#define fgets script_fgets
#define ferror script_error
#define feof script_end
#define clearerr script_clear
#define read_intr reference_read_intr
#define fread_safe reference_fread_safe
#define fgets_safe reference_fgets_safe
#define fill_crypto_random_bytes reference_crypto_random
#include "stdio_reference.inc"
#undef read
#undef fread
#undef fgets
#undef ferror
#undef feof
#undef clearerr
#undef read_intr
#undef fread_safe
#undef fgets_safe
#undef fill_crypto_random_bytes
#undef errno
#define errno (*_errno())
#define read_intr native_reference_read_intr
#define fread_safe native_reference_fread_safe
#define fgets_safe native_reference_fgets_safe
#define fill_crypto_random_bytes native_reference_crypto_random
#include "stdio_reference.inc"
#undef read_intr
#undef fread_safe
#undef fgets_safe
#undef fill_crypto_random_bytes

static struct script script(unsigned scenario)
{
    struct script state = {0};
    for (unsigned index = 0; index < 8; ++index) state.steps[index].count = SIZE_MAX;
    if (scenario == 1) state.steps[0] = (struct step){3,0,0,0};
    if (scenario == 2) state.steps[0] = (struct step){0,EINTR,1,0};
    if (scenario == 3) { state.steps[0] = state.steps[1] = (struct step){0,EINTR,1,0}; state.steps[2] = (struct step){2,EINTR,1,0}; }
    if (scenario == 4) state.steps[0] = (struct step){3,EACCES,1,0};
    if (scenario == 5) state.steps[0] = (struct step){0,0,0,1};
    if (scenario == 6) state.steps[0] = (struct step){3,0,0,1};
    if (scenario == 7) { state.steps[0] = (struct step){0,EINTR,1,0}; state.steps[1] = (struct step){0,EACCES,1,0}; }
    return state;
}
static bool same_state(const struct script *left, const struct script *right)
{
    return left->index == right->index && left->cleared == right->cleared && left->offset == right->offset &&
        left->error == right->error && left->failed == right->failed && left->ended == right->ended;
}
static char *no_line_flags(char *output, int capacity, FILE *stream)
{ (void)output; (void)capacity; CHECK(stream == (FILE *)active); ++active->index; return NULL; }
static size_t invalid_read_count(void *output, size_t size, size_t count, FILE *stream)
{ (void)output; (void)size; CHECK(stream == (FILE *)active); ++active->index; return count + 1; }
static void compare_script(unsigned scenario, size_t size)
{
    struct script left = script(scenario), right = left;
    uint8_t a[256], b[256]; memset(a, 0x69, sizeof(a)); memcpy(b, a, sizeof(a));
    size_t read_a = 99, read_b = 99;
    active = &left; bool expected = reference_fread_safe(a + 8, size, 20, (FILE *)&left, &read_a);
    active = &right; bool actual = zapret_engine_fread(b + 8, size, 20, (FILE *)&right, &read_b, &ops);
    CHECK(expected == actual && read_a == read_b && !memcmp(a,b,sizeof(a)) && same_state(&left,&right)); ++scripted;
    left = script(scenario); right = left; memset(a,0x69,sizeof(a)); memcpy(b,a,sizeof(a));
    active = &left; ssize_t expected_read = reference_read_intr(41, a + 8, 37);
    active = &right; ssize_t actual_read = zapret_engine_read(41, b + 8, 37, &ops);
    CHECK(expected_read == actual_read && !memcmp(a,b,sizeof(a)) && same_state(&left,&right)); ++scripted;
    left = script(scenario); right = left; memset(a,0x69,sizeof(a)); memcpy(b,a,sizeof(a));
    active = &left; char *expected_line = reference_fgets_safe((char *)a + 8, 37, (FILE *)&left);
    active = &right; char *actual_line = zapret_engine_fgets((char *)b + 8, 37, (FILE *)&right, &ops);
    CHECK(!!expected_line == !!actual_line && !memcmp(a,b,sizeof(a)) && same_state(&left,&right)); ++scripted;
}
static FILE *temporary(void)
{
    WCHAR directory[MAX_PATH], path[MAX_PATH];
    CHECK(GetTempPathW(MAX_PATH, directory) && GetTempFileNameW(directory, L"zrs", 0, path));
    HANDLE handle = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    CHECK(handle != INVALID_HANDLE_VALUE);
    int descriptor = _open_osfhandle((intptr_t)handle, _O_RDWR | _O_BINARY); CHECK(descriptor >= 0);
    FILE *stream = _fdopen(descriptor, "w+b"); CHECK(stream); return stream;
}
int main(void)
{
    for (unsigned scenario = 0; scenario < 8; ++scenario) for (size_t size = 1; size <= 9; ++size) compare_script(scenario,size);
    FILE *left = temporary(), *right = temporary();
    uint8_t data[1024];
    for (unsigned index = 0; index < sizeof(data); ++index) data[index] = (uint8_t)(index * 131);
    CHECK(fwrite(data,1,sizeof(data),left) == sizeof(data) && fwrite(data,1,sizeof(data),right) == sizeof(data));
    for (size_t size = 0; size < 9; ++size) for (size_t count = 0; count < 257; count += 16) {
        rewind(left); rewind(right);
        uint8_t a[4096], b[4096]; memset(a,0x69,sizeof(a)); memcpy(b,a,sizeof(a)); size_t read_a=99, read_b=99;
        errno=77; bool expected=native_reference_fread_safe(a+8,size,count,left,&read_a); int error=errno;
        errno=77; bool actual=zapret_engine_fread(b+8,size,count,right,&read_b,NULL);
        CHECK(expected == actual && read_a == read_b && error == errno && !memcmp(a,b,sizeof(a)));
        CHECK(ferror(left) == ferror(right) && feof(left) == feof(right)); ++real_reads;
    }
    for (int capacity=1; capacity<=40; ++capacity) {
        rewind(left); rewind(right);
        for (unsigned index=0; index<16; ++index) {
            char a[64],b[64]; memset(a,0x69,sizeof(a)); memcpy(b,a,sizeof(a));
            errno=77; char *expected=native_reference_fgets_safe(a+8,capacity,left); int error=errno;
            errno=77; char *actual=zapret_engine_fgets(b+8,capacity,right,NULL);
            CHECK(!!expected == !!actual && error == errno && !memcmp(a,b,sizeof(a))); ++real_lines;
        }
    }
    CHECK(!fclose(left) && !fclose(right));
    for (unsigned count=0; count<=96; count+=3) {
        int a[2],b[2]; CHECK(!_pipe(a,256,_O_BINARY) && !_pipe(b,256,_O_BINARY));
        CHECK(_write(a[1],data,64)==64 && _write(b[1],data,64)==64); CHECK(!_close(a[1]) && !_close(b[1]));
        uint8_t x[128],y[128]; memset(x,0x69,sizeof(x)); memcpy(y,x,sizeof(x));
        errno=77; ssize_t expected=native_reference_read_intr(a[0],x+8,count); int error=errno;
        errno=77; ssize_t actual=zapret_engine_read(b[0],y+8,count,NULL);
        CHECK(expected == actual && error == errno && !memcmp(x,y,sizeof(x))); CHECK(!_close(a[0]) && !_close(b[0])); ++real_pipes;
    }
    struct script state=script(0); active=&state; uint8_t output[64]; size_t read=99;
    CHECK(!zapret_engine_fread(output,SIZE_MAX,2,(FILE *)&state,&read,&ops) && !read && state.error==EINVAL && !state.index); ++boundaries;
    CHECK(!zapret_engine_fread(NULL,1,2,(FILE *)&state,&read,&ops) && !state.index); ++boundaries;
    CHECK(!zapret_engine_fgets((char *)output,0,(FILE *)&state,&ops) && !state.index); ++boundaries;
    CHECK(zapret_engine_read(41,output,SIZE_MAX,&ops)==-1 && !state.index); ++boundaries;
    state=script(0); for(unsigned index=0;index<8;++index) state.steps[index]=(struct step){0,EINTR,1,0};
    CHECK(zapret_engine_read(41,output,32,&ops)==-1 && state.index==1024 && state.error==EINTR); ++boundaries;
    state=script(0); for(unsigned index=0;index<8;++index) state.steps[index]=(struct step){0,EINTR,1,0};
    CHECK(!zapret_engine_fgets((char *)output,32,(FILE *)&state,&ops) && state.index==1024); ++boundaries;
    state=script(0); for(unsigned index=0;index<8;++index) state.steps[index]=(struct step){0,EINTR,1,0};
    CHECK(!zapret_engine_fread(output,1,32,(FILE *)&state,&read,&ops) && !read && state.index==1025); ++boundaries;
    state=script(0); stream_ops malformed=ops; malformed.read_line=no_line_flags;
    CHECK(!zapret_engine_fgets((char *)output,32,(FILE *)&state,&malformed) && state.index==1 && state.error==EIO); ++boundaries;
    state=script(0); malformed=ops; malformed.read_file=invalid_read_count;
    CHECK(!zapret_engine_fread(output,1,32,(FILE *)&state,&read,&malformed) && !read && state.index==1 && state.error==EIO); ++boundaries;
    for(unsigned count=0;count<=40;++count) {
        memset(output,0x69,sizeof(output)); CHECK(zapret_engine_crypto_random(output+8,count));
        for(unsigned index=0;index<sizeof(output);++index) if(index<8 || index>=8+count) CHECK(output[index]==0x69);
    }
    CHECK(zapret_engine_crypto_random(NULL,0) && !zapret_engine_crypto_random(NULL,1));
    CHECK(!zapret_engine_crypto_random(output,SIZE_MAX));
    printf("PASS engine_stdio functions=4 scripted_cases=%u real_reads=%u real_lines=%u real_pipes=%u boundaries=%u rng_boundaries=44\n",scripted,real_reads,real_lines,real_pipes,boundaries);
    return 0;
}
