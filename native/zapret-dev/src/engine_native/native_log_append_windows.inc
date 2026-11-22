/* MIT. Native FILE operations return observations, never call Rust with va_list. */
static int native_log_write_file(const char *filename,const char *format,va_list args,bool timestamp)
{
    zapret_log_entry state={0};int32_t observation=0;FILE *file=NULL;
    for(;;)switch(zapret_log_append_step(&state,timestamp,observation)){
        case 1:file=fopen(filename,"at");observation=file!=NULL;break;
        case 2:fprint_localtime(file);break;
        case 3:fprintf(file," : ");break;
        case 4:observation=vfprintf(file,format,args);break;
        case 5:fprintf(file,"\n");break;
        case 6:fclose(file);break;
        case 7:return state.result;
        default:abort();
    }
}

int DLOG_FILENAME_VA(const char *filename,const char *format,va_list args)
{
    return native_log_write_file(filename,format,args,false);
}
int LOG_APPEND(const char *filename,const char *format,va_list args)
{
    return native_log_write_file(filename,format,args,true);
}
