/* MIT. Instance keys are formatted in Rust before any VM operation. */
void zapret_desync_instance(const char *,uint32_t,uint32_t,char *,size_t);
void desync_instance(const char *function,unsigned int profile,unsigned int number,char *output,size_t capacity)
{zapret_desync_instance(function,profile,number,output,capacity);}
