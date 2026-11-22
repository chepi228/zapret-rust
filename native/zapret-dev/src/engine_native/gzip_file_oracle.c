/* MIT. File inflater parity, real UCRT streams and injected codec/allocator errors. */
#include "gzip.h"
#include "helpers.h"
#include <io.h>
#include <fcntl.h>
#undef main
static unsigned cases,probes,boundaries,faults,repairs,ends,reads,resizes,live,cleared,native_cases;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL gzip file cases=%u bounds=%u line=%d: %s\n",cases,boundaries,__LINE__,#v);exit(1);}}while(0)
static int fail_after=-1,read_error_after=-1,codec_mode;
static unsigned read_calls,resize_calls,init_calls,end_calls;
static bool rust_side,scripted;
static const uint8_t *script_input;
static size_t script_length,script_offset,read_limit=16384,last_allocation;
static int seek_failure,seek_calls;
bool zapret_engine_fread(void *,size_t,size_t,FILE *,size_t *,const void *);
int zapret_engine_gzip_read(FILE *,char **,size_t *,size_t,const void *);
bool zapret_engine_is_gzip(FILE *,const void *);
static bool fixture_read(FILE *file,uint8_t *data,size_t capacity,size_t *count)
{
    ++reads;unsigned index=read_calls++;*count=0;
    if(read_error_after>=0 && index>=(unsigned)read_error_after)return false;
    if(scripted){
        if(codec_mode==6){*count=capacity+1;return true;}
        size_t length=script_length-script_offset;if(length>capacity)length=capacity;if(length>read_limit)length=read_limit;
        if(length)memcpy(data,script_input+script_offset,length);script_offset+=length;*count=length;return true;
    }
    return zapret_engine_fread(data,1,capacity,file,count,NULL);
}
bool fread_safe(void *data,size_t width,size_t count,FILE *file,size_t *read)
{CHECK(width==1);return fixture_read(file,data,count,read);}
static size_t fixture_raw_read(void *data,size_t width,size_t count,FILE *file)
{
    if(scripted){CHECK(width==1);size_t length=script_length-script_offset;if(length>count)length=count;if(length)memcpy(data,script_input+script_offset,length);script_offset+=length;return length;}
    return fread(data,width,count,file);
}
static int fixture_seek(FILE *file,long offset,int origin)
{
    CHECK(offset==0 && origin==SEEK_SET);++seek_calls;
    if(seek_failure && seek_calls==seek_failure)return -1;
    if(scripted){script_offset=0;return 0;}return fseek(file,offset,origin);
}
static void *managed_resize(void *pointer,size_t size)
{
    CHECK(size && size<=PTRDIFF_MAX);++resizes;
    unsigned index=resize_calls++;if(fail_after>=0 && index>=(unsigned)fail_after)return NULL;
    bool fresh=!pointer;void *result=realloc(pointer,size);if(result){if(fresh)++live;last_allocation=size;}return result;
}
static void *managed_malloc(size_t size){return managed_resize(NULL,size);}
static void managed_free(void *pointer){if(pointer){CHECK(live);--live;}free(pointer);}
static int fixture_init(z_stream *stream,int bits){++init_calls;CHECK(bits==47);return codec_mode==7?Z_MEM_ERROR:inflateInit2(stream,bits);}
static int fixture_process(z_stream *stream,int flush)
{
    CHECK(flush==0);
    if(codec_mode==1)return Z_OK;
    if(codec_mode==2){++stream->avail_in;return Z_OK;}
    if(codec_mode==3){++stream->avail_out;return Z_OK;}
    if(codec_mode==4){stream->avail_in=0;return Z_BUF_ERROR;}
    if(codec_mode==5){memset(stream->next_out,'x',stream->avail_out);stream->avail_out=0;return Z_OK;}
    return inflate(stream,flush);
}
static int fixture_end(z_stream *stream)
{
    if(rust_side){CHECK(!stream->next_in && !stream->avail_in && !stream->next_out && !stream->avail_out);++cleared;}
    ++ends;++end_calls;return inflateEnd(stream);
}
typedef struct {
    bool(*read)(FILE *,uint8_t *,size_t,size_t *);
    size_t(*raw)(void *,size_t,size_t,FILE *);
    int(*seek)(FILE *,long,int);
    void *(*resize)(void *,size_t);
    void(*release)(void *);
    int(*init)(z_stream *,int);
    int(*process)(z_stream *,int);
    int(*end)(z_stream *);
}gzip_file_ops;
_Static_assert(sizeof(gzip_file_ops)==64,"Rust gzip file operations ABI");
static const gzip_file_ops ops={fixture_read,fixture_raw_read,fixture_seek,managed_resize,managed_free,fixture_init,fixture_process,fixture_end};
#define z_readfile reference_readfile
#define is_gzip reference_is_gzip
#define malloc managed_malloc
#define realloc managed_resize
#define free managed_free
#define fread fixture_raw_read
#define fseek fixture_seek
#define zapret_inflate_init fixture_init
#define zapret_inflate fixture_process
#define zapret_inflate_end fixture_end
#include "gzip_file_reference.inc"
#undef z_readfile
#undef is_gzip
#undef malloc
#undef realloc
#undef free
#undef fread
#undef fseek
#undef zapret_inflate_init
#undef zapret_inflate
#undef zapret_inflate_end
int zapret_crt_z_readfile(FILE *,char **,size_t *,size_t);
bool zapret_crt_is_gzip(FILE *);
struct sample{int status;size_t length;char *data;size_t position;};
static FILE *binary_file(const uint8_t *data,size_t length)
{FILE *file=tmpfile();CHECK(file);CHECK(_setmode(_fileno(file),_O_BINARY)!=-1);if(length)CHECK(fwrite(data,1,length,file)==length);CHECK(!fseek(file,0,SEEK_SET));return file;}
static struct sample invoke(bool rust,const uint8_t *data,size_t length,size_t extra,bool real)
{
    CHECK(!live);read_calls=resize_calls=init_calls=end_calls=seek_calls=0;last_allocation=0;rust_side=rust;scripted=!real;script_input=data;script_length=length;script_offset=0;
    FILE *file=real?binary_file(data,length):(FILE *)(uintptr_t)1;struct sample value={0};value.data=(char *)(uintptr_t)0x1111;value.length=123;
    value.status=rust?zapret_engine_gzip_read(file,&value.data,&value.length,extra,&ops):reference_readfile(file,&value.data,&value.length,extra);
    CHECK(init_calls==1 && end_calls==(codec_mode==7?0:1));value.position=real?(size_t)ftell(file):script_offset;if(real)CHECK(!fclose(file));
    if(value.status==Z_STREAM_END){CHECK(live==(value.data!=NULL));if(extra){CHECK(value.data && last_allocation>=value.length+extra);memset(value.data+value.length,0xa5,extra);}}
    else CHECK(!live && !value.data);
    return value;
}
static void compare(const uint8_t *data,size_t length,size_t extra,bool real)
{
    struct sample old=invoke(false,data,length,extra,real);uint8_t *copy=NULL;
    if(old.status==Z_STREAM_END && old.length){copy=malloc(old.length);CHECK(copy);memcpy(copy,old.data,old.length);}managed_free(old.data);
    struct sample rust=invoke(true,data,length,extra,real);
    if(old.status!=rust.status || old.length!=rust.length || old.position!=rust.position){fprintf(stderr,"DETAIL encoded=%zu extra=%zu real=%d old=%d/%zu rust=%d/%zu position=%zu/%zu\n",length,extra,real,old.status,old.length,rust.status,rust.length,old.position,rust.position);CHECK(false);}
    if(rust.status==Z_STREAM_END && rust.length)CHECK(!memcmp(copy,rust.data,rust.length));
    managed_free(rust.data);free(copy);CHECK(!live);++cases;
}
static uint64_t random_state=0x677a697066696c65ULL;
static uint8_t next_byte(void){random_state^=random_state<<13;random_state^=random_state>>7;random_state^=random_state<<17;return (uint8_t)random_state;}
static size_t encode(const uint8_t *data,size_t length,uint8_t *output,size_t capacity,int bits,int level)
{
    z_stream stream={0};CHECK(!deflateInit2(&stream,level,Z_DEFLATED,bits,8,Z_DEFAULT_STRATEGY));stream.next_in=data;stream.avail_in=(uInt)length;stream.next_out=output;stream.avail_out=(uInt)capacity;
    CHECK(deflate(&stream,Z_FINISH)==Z_STREAM_END);size_t size=capacity-stream.avail_out;CHECK(!deflateEnd(&stream));return size;
}
static void probe_checks(void)
{
    static const uint8_t inputs[][5]={{0},{0x1f},{0x1f,0x8b},{0x1f,0x8c},{0,0x8b},{0x1f,0x8b,0,255,1}};
    for(unsigned id=0;id<6;++id)for(unsigned length=0;length<=5;++length)for(unsigned real=0;real<2;++real)for(unsigned failure=0;failure<3;++failure){
        bool results[2];for(unsigned side=0;side<2;++side){scripted=!real;script_input=inputs[id];script_length=length;script_offset=length;seek_calls=0;seek_failure=failure;
            FILE *file=real?binary_file(inputs[id],length):(FILE *)(uintptr_t)1;
            results[side]=side?zapret_engine_is_gzip(file,&ops):reference_is_gzip(file);
            CHECK(seek_calls==2);if(real)CHECK(!fclose(file));else if(failure!=2)CHECK(!script_offset);
        }CHECK(results[0]==results[1]);++probes;
    }seek_failure=0;scripted=false;
}
static void fault_checks(const uint8_t *encoded,size_t length)
{
    for(unsigned side=0;side<2;++side)for(unsigned fault=0;fault<9;++fault){fail_after=(int)fault;struct sample value=invoke(side!=0,encoded,length,64,false);CHECK(value.status==Z_STREAM_END || value.status==Z_MEM_ERROR);managed_free(value.data);CHECK(!live);++faults;}
    fail_after=-1;
    for(unsigned error=0;error<3;++error){read_error_after=(int)error;compare(encoded,length,64,false);++faults;}read_error_after=-1;
    for(int mode=1;mode<=6;++mode){codec_mode=mode;if(mode==5)fail_after=4;struct sample value=invoke(true,encoded,length,0,false);CHECK(value.status==(mode==1?Z_BUF_ERROR:mode==4?Z_DATA_ERROR:mode==5?Z_MEM_ERROR:-2));CHECK(!live);++repairs;fail_after=-1;}
    codec_mode=7;compare(encoded,length,64,false);++faults;codec_mode=0;
}
static void boundary_checks(void)
{
    char *data=(char *)(uintptr_t)0x1111;size_t length=123;_Alignas(8) uint8_t storage[80]={0};
    CHECK(zapret_engine_gzip_read(NULL,&data,&length,0,&ops)==-2 && !data && !length);++boundaries;
    CHECK(zapret_engine_gzip_read((FILE *)1,NULL,&length,0,&ops)==-2);++boundaries;
    CHECK(zapret_engine_gzip_read((FILE *)1,&data,NULL,0,&ops)==-2);++boundaries;
    CHECK(zapret_engine_gzip_read((FILE *)1,(void *)(storage+1),&length,0,&ops)==-2);++boundaries;
    CHECK(zapret_engine_gzip_read((FILE *)1,&data,(void *)(storage+1),0,&ops)==-2);++boundaries;
    CHECK(zapret_engine_gzip_read((FILE *)1,&data,&length,0,(void *)(storage+1))==-2);++boundaries;
    gzip_file_ops missing={0};CHECK(zapret_engine_gzip_read((FILE *)1,&data,&length,0,&missing)==-2);++boundaries;
    const size_t extras[]={SIZE_MAX,SIZE_MAX-131072,(size_t)PTRDIFF_MAX,(size_t)PTRDIFF_MAX-1};
    for(unsigned i=0;i<4;++i){data=(char *)(uintptr_t)0x1111;length=123;read_calls=resize_calls=init_calls=0;CHECK(zapret_engine_gzip_read((FILE *)1,&data,&length,extras[i],&ops)==Z_MEM_ERROR && !data && !length && !init_calls && !read_calls && !resize_calls);++repairs;}
    CHECK(!zapret_engine_is_gzip(NULL,&ops));++boundaries;CHECK(!zapret_engine_is_gzip((FILE *)1,&missing));++boundaries;CHECK(!zapret_engine_is_gzip((FILE *)1,(void *)(storage+1)));++boundaries;
}
static void geometric_growth(void)
{
    size_t size=2*1024*1024;uint8_t *data=malloc(size),*encoded=malloc(size+4096);CHECK(data && encoded);for(size_t i=0;i<size;++i)data[i]=(uint8_t)(i%7);size_t length=encode(data,size,encoded,size+4096,31,6);
    struct sample old=invoke(false,encoded,length,64,false);unsigned old_count=resize_calls;managed_free(old.data);
    struct sample rust=invoke(true,encoded,length,64,false);unsigned rust_count=resize_calls;managed_free(rust.data);CHECK(old.status==Z_STREAM_END && rust.status==Z_STREAM_END && old.length==size && rust.length==size && old_count>rust_count*2);
    printf("BENCH gzip_file_growth bytes=%zu old_resizes=%u rust_resizes=%u\n",size,old_count,rust_count);fault_checks(encoded,length);free(data);free(encoded);
}
static void native_check(const uint8_t *encoded,size_t length,const uint8_t *expected,size_t expected_length,bool gzip)
{
    FILE *file=binary_file(encoded,length);CHECK(zapret_crt_is_gzip(file)==gzip && ftell(file)==0);char *data=NULL;size_t size=0;
    CHECK(zapret_crt_z_readfile(file,&data,&size,64)==Z_STREAM_END && size==expected_length && data && (!size || !memcmp(data,expected,size)));
    memset(data+size,0xa5,64);free(data);CHECK(!fclose(file));++native_cases;
}
static void benchmark(void)
{
    const size_t sizes[]={2*1024*1024,32*1024*1024};
    LARGE_INTEGER frequency;CHECK(QueryPerformanceFrequency(&frequency));
    for(unsigned n=0;n<2;++n){size_t size=sizes[n];uint8_t *data=malloc(size),*encoded=malloc(size+4096);CHECK(data && encoded);for(size_t i=0;i<size;++i)data[i]=(uint8_t)(i%7);size_t length=encode(data,size,encoded,size+4096,31,6);
        for(unsigned round=0;round<9;++round){double ns[2];unsigned growth[2];
            for(unsigned k=0;k<2;++k){bool rust=(round&1)?k==0:k!=0;LARGE_INTEGER start,end;CHECK(QueryPerformanceCounter(&start));struct sample value=invoke(rust,encoded,length,0,true);CHECK(QueryPerformanceCounter(&end));CHECK(value.status==Z_STREAM_END && value.length==size && !memcmp(value.data,data,size));ns[rust]=(double)(end.QuadPart-start.QuadPart)*1e9/(double)frequency.QuadPart;growth[rust]=resize_calls;managed_free(value.data);}
            printf("BENCH gzip_file bytes=%zu round=%u old_ms=%.4f rust_ms=%.4f ratio=%.5f old_resizes=%u rust_resizes=%u real_ucrt=1\n",size,round,ns[0]/1e6,ns[1]/1e6,ns[1]/ns[0],growth[0],growth[1]);
        }free(data);free(encoded);
    }
}
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--benchmark")){benchmark();return 0;}
    uint8_t *data=malloc(2*1024*1024),*encoded=malloc(2*1024*1024+4096);CHECK(data && encoded);
    const size_t lengths[]={0,1,127,128,16383,16384,16385,65536,131071,131072,131073,2*1024*1024};
    const int formats[]={31,15,-15},levels[]={0,6};
    const size_t extras[]={0,1,64};
    for(unsigned pattern=0;pattern<2;++pattern){for(size_t i=0;i<2*1024*1024;++i)data[i]=pattern?next_byte():(uint8_t)(i%7);
        for(unsigned f=0;f<3;++f)for(unsigned level=0;level<2;++level)for(unsigned n=0;n<12;++n){size_t length=encode(data,lengths[n],encoded,2*1024*1024+4096,formats[f],levels[level]);
            for(unsigned e=0;e<3;++e){compare(encoded,length,extras[e],true);compare(encoded,length,extras[e],false);if(length>1)compare(encoded,length-1,extras[e],false);if(length>4)compare(encoded,length-4,extras[e],false);}
            encoded[length]=0xab;encoded[length+1]=0xcd;compare(encoded,length+2,0,false);
            if(f<2 && length>8){encoded[length-4]^=0xff;compare(encoded,length,0,false);encoded[length-4]^=0xff;}
        }
    }
    static const uint8_t invalid[]={0,1,2,3,4,255,0};for(unsigned n=0;n<=sizeof(invalid);++n)compare(invalid,n,0,true);
    for(unsigned format=0;format<2;++format)for(unsigned n=0;n<12;++n){size_t count=encode(data,lengths[n],encoded,2*1024*1024+4096,formats[format],6);native_check(encoded,count,data,lengths[n],format==0);}
    size_t a=encode((const uint8_t *)"first",5,encoded,4096,31,6);size_t b=encode((const uint8_t *)"second",6,encoded+a,4096,31,6);compare(encoded,a+b,64,true);native_check(encoded,a+b,(const uint8_t *)"first",5,true);
    read_limit=1;compare(encoded,a+b,0,false);read_limit=16384;
    size_t error_length=encode(data,300000,encoded,2*1024*1024+4096,31,0);
    const int errors[]={0,1,3,17};for(unsigned i=0;i<4;++i){read_error_after=errors[i];compare(encoded,error_length,64,false);++faults;}read_error_after=-1;
    probe_checks();boundary_checks();geometric_growth();free(data);free(encoded);CHECK(!live);
    printf("PASS gzip_file functions=2 cases=%u probes=%u boundaries=%u allocation_faults=%u defensive_repairs=%u ended_streams=%u cleared_io=%u reads=%u resizes=%u native_cases=%u live_allocations=0 real_ucrt=1\n",cases,probes,boundaries,faults,repairs,ends,cleared,reads,resizes,native_cases);return 0;
}
