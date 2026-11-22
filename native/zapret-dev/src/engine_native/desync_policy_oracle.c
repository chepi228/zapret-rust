/* MIT. Full independent old/new packet invocation contract on pinned LuaJIT. */
#include "desync_invocation_contract.inc"
#include "desync_panic_reference.inc"
#include "packet_queue.h"
static unsigned replay_callbacks,replay_returns,replay_sends,replay_fault;
static struct allocator *replay_allocator;
static struct rawpacket_queue replay_packets;
static uint8_t dpi_desync_packet_play(unsigned piece,unsigned count,size_t offset,uint32_t mark,
    const char *ifin,const char *ifout,const t_ctrack_positions *positions,const uint8_t *data,
    size_t length,uint8_t *changed,size_t *changed_length)
{
    CHECK(piece==replay_callbacks && count==2 && offset==piece*10 && mark==0x123);
    CHECK(!strcmp(ifin,"Wi-Fi") && !strcmp(ifout,"3.1") && positions);
    ++replay_callbacks;
    packet.data_pkt=data;packet.len_pkt=length;
    if(replay_fault){replay_allocator->armed=true;replay_allocator->limit=0;replay_allocator->calls=0;}
    uint8_t result=(native_side?candidate_desync:reference_desync)(&profile,mark,ifin,ifout,
        false,&track,positions,L7P_HTTP_REQ,L7_HTTP,&packet,NULL,NULL,443,changed,changed_length,
        piece,count,offset,NULL,0,NULL,0);
    ++replay_returns;
    return result;
}
bool rawsend(const struct sockaddr *destination,uint32_t mark,const char *ifout,
    const void *data,size_t length)
{
    CHECK(destination->sa_family==AF_INET && mark==0x321 && !strcmp(ifout,"3.1"));
    CHECK(data && length==40);++replay_sends;
    return replay_sends!=1; /* A failed send must not abandon the next packet. */
}
#include "replay_windows.inc"
static int replay_panic(lua_State *L)
{
    (void)L;
    if(replay_callbacks!=1 || replay_returns || calls)exit(98);
    fputs("LUA PANIC: THIS IS FATAL. DYING. replay setup allocation\n",stderr);
    exit(100);
}
static lua_State *prepare_replay(struct allocator *allocation,bool native,unsigned fault)
{
    seed=15;variant=4;operation=0;native_side=native;replay_fault=fault;
    replay_callbacks=replay_returns=replay_sends=0;replay_allocator=allocation;
    lua_State *L=lua_newstate(allocate,allocation);CHECK(L);prepare(L);
    lua_atpanic(L,replay_panic);
    for(unsigned n=0;n<3;++n){arguments[n].str2="plain";rules[n].payload_type=0;}
    track.pos.ipproto=IPPROTO_TCP;
    struct sockaddr_storage destination={.ss_family=AF_INET};
    rawpacket_queue_init(&replay_packets,0);
    for(unsigned n=0;n<2;++n){
        track.pos.client.seq_last=101+n*10;
        CHECK(rawpacket_queue(&replay_packets,&destination,0x123,0x321,
            "Wi-Fi","3.1",wire,40,10,&track.pos,false));
    }
    return L;
}
static int protected_replay(lua_State *L)
{
    (void)L;replay_queue(&replay_packets);return 0;
}
static void queue_contract(void)
{
    char before[sizeof(diagnostic)];
    for(unsigned side=0;side<2;++side){
        struct allocator allocation={0};lua_State *L=prepare_replay(&allocation,side!=0,0);
        CHECK(!replay_queue(&replay_packets));
        CHECK(replay_callbacks==2 && replay_returns==2 && replay_sends==2 && calls==2);
        CHECK(rawpacket_queue_empty(&replay_packets) && !context->valid && lua_gettop(L)==0);
        CHECK(strstr(diagnostic,"handler inspect failure"));
        if(!side)strcpy(before,diagnostic);else CHECK(!strcmp(before,diagnostic));
        rawpacket_queue_destroy(&replay_packets);lua_close(L);CHECK(!allocation.live);
    }
}
static void isolated_case(bool native,bool stress)
{
    struct allocator allocation={0};lua_State *L=prepare_replay(&allocation,native,1);
    if(stress){
        lua_pushcfunction(L,protected_replay);
        int status=lua_pcall(L,0,0,0);allocation.armed=false;
        CHECK(status==LUA_ERRMEM && allocation.rejected && replay_callbacks==1 && !replay_returns);
        /* External pcall deliberately sits below historical Rust replay frames.
         * This is a stress control, not a product entry or lifetime guarantee.
         * Isolate the skipped Rust packet owner in this process. */
        rawpacket_queue_destroy(&replay_packets);lua_close(L);CHECK(!allocation.live);
        exit(0);
    }
    replay_queue(&replay_packets);
    CHECK(false);
}
static void child_case(const wchar_t *argument,DWORD expected)
{
    wchar_t path[32768],command[32768];DWORD n=GetModuleFileNameW(NULL,path,32768);CHECK(n && n<32768);
    CHECK(_snwprintf(command,32768,L"\"%ls\" %ls",path,argument)>0);
    STARTUPINFOW startup={.cb=sizeof(startup)};PROCESS_INFORMATION child={0};
    CHECK(CreateProcessW(NULL,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&startup,&child));
    DWORD waited=WaitForSingleObject(child.hProcess,10000),code=0;
    if(waited!=WAIT_OBJECT_0){TerminateProcess(child.hProcess,97);WaitForSingleObject(child.hProcess,1000);}
    CHECK(waited==WAIT_OBJECT_0 && GetExitCodeProcess(child.hProcess,&code));
    CHECK(CloseHandle(child.hThread) && CloseHandle(child.hProcess));
    if(code!=expected)fprintf(stderr,"child %ls exit=0x%08lx expected=0x%08lx\n",argument,(unsigned long)code,(unsigned long)expected);
    CHECK(code==expected);
}
int main(int argc,char **argv)
{
    if(argc==2){
        if(!strcmp(argv[1],"--panic-old"))isolated_case(false,false);
        if(!strcmp(argv[1],"--panic-new"))isolated_case(true,false);
        if(!strcmp(argv[1],"--stress-old"))isolated_case(false,true);
        if(!strcmp(argv[1],"--stress-new"))isolated_case(true,true);
        if(!strcmp(argv[1],"--explicit-panic")){
            struct allocator allocation={0};lua_State *L=prepare_replay(&allocation,true,0);
            lua_atpanic(L,lua_panic);lua_pushliteral(L,"explicit native panic callback");
            lua_CFunction callback=lua_atpanic(L,NULL);CHECK(callback==lua_panic);callback(L);return 99;
        }
        return 2;
    }
    int status=invocation_contract_main();
    if(status)return status;
    queue_contract();child_case(L"--panic-old",0xe24c4a04u);child_case(L"--panic-new",0xe24c4a04u);
    child_case(L"--stress-old",0);child_case(L"--stress-new",0);
    child_case(L"--explicit-panic",100);
    puts("PASS desync_final complete_vm_entry=1 independent_reference=1 actual_queue=1 local_pcall_return=1 setup_fatal_parity=2 fatal_luajit_seh=0xe24c4a04 explicit_native_panic_exit100=1 external_pcall_stress_controls=2");
    return 0;
}
