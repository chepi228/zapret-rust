/* MIT. Every operation below executes after the policy returns. */
static int DLOG_VA(const char *format,int syslog_priority,bool condup,va_list args)
{
    zapret_log_entry state={0};int32_t observation=0;va_list copy;
    for(;;)switch(zapret_log_entry_step(&state,condup,observation)){
        case 1:observation=params.debug;break;
        case 2:observation=params.debug_target;break;
        case 3:va_copy(copy,args);DLOG_CON_VA(format,syslog_priority,copy);va_end(copy);break;
        case 4:observation=DLOG_CON_VA(format,syslog_priority,args);break;
        case 5:log_buffered(file_log_function,syslog_priority,format,args);break;
        case 6:log_buffered(syslog_log_function,syslog_priority,format,args);break;
        case 8:return state.result;
        default:abort();
    }
}
