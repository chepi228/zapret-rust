/* MIT. Shared and foreign icons remain outside the engine's ownership. */
uint32_t zapret_startup_icon(const void *);
static void WinSetIcon(void){(void)zapret_startup_icon(NULL);}
