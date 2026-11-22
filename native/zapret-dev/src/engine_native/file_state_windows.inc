/* MIT. Rust returns native errors; preserve the engine's errno boundary. */
uint32_t zapret_engine_file_size(const char *, int64_t *);
uint32_t zapret_engine_file_stamp(const char *, void *);
uint32_t zapret_engine_file_probe(const char *, int);
uint32_t zapret_engine_set_exedir(void);
uint32_t zapret_engine_realpath(const char *, char *, size_t);
_Static_assert(sizeof(file_mod_sig)==24 && offsetof(file_mod_sig,mod_time)==0 &&
    offsetof(file_mod_sig,size)==16 && sizeof(((file_mod_sig *)0)->mod_time.tv_nsec)==4 && sizeof(off_t)==8,
    "Rust file signature ABI");
static bool native_file_state_result(uint32_t error)
{
    if(!error)return true;
    if(error==ERROR_ARITHMETIC_OVERFLOW)errno=EOVERFLOW;
    else wf_error(error);
    return false;
}
bool file_size(const char *filename,off_t *size) {return native_file_state_result(zapret_engine_file_size(filename,size));}
bool file_mod_signature(const char *filename,file_mod_sig *signature) {return native_file_state_result(zapret_engine_file_stamp(filename,signature));}
bool file_open_test(const char *filename,int flags) {return native_file_state_result(zapret_engine_file_probe(filename,flags));}
bool set_env_exedir(const char *argv0) {(void)argv0;return native_file_state_result(zapret_engine_set_exedir());}
bool realpath_any(const char *filename,char *output) {return native_file_state_result(zapret_engine_realpath(filename,output,PATH_MAX));}
