/* MIT. The Lua system query is populated from native Windows observations. */
#pragma once
struct utsname {
    char sysname[65];
    char nodename[256];
    char release[65];
    char version[65];
    char machine[65];
};
int uname(struct utsname *value);
