/* MIT. Native reload policy uses a stable Rust record and existing C loaders. */
#if ZAPRET_RELOAD_HOSTS
static bool append_registered_hosts(struct zapret_list_file *file)
{
    return AppendHostList(&file->hostlist, file->filename);
}

static bool LoadHostList(struct zapret_list_file *file, bool *changed)
{
    return zapret_list_reload(file, changed, "hostlist",
        zapret_list_read_stamp, zapret_list_probe_read, append_registered_hosts);
}
#else
static bool append_registered_ips(struct zapret_list_file *file)
{
    return AppendIpset(&file->ipset, file->filename);
}

static bool LoadIpset(struct zapret_list_file *file)
{
    return zapret_list_reload(file, NULL, "ipset",
        zapret_list_read_stamp, zapret_list_probe_read, append_registered_ips);
}
#endif
#undef ZAPRET_RELOAD_HOSTS
