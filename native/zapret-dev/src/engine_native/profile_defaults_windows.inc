/* MIT. Fill only the unset protocol filters after Rust sets the IP defaults. */
bool zapret_profile_filter_defaults(struct desync_profile *, bool (*)(uint32_t, void *));
static bool profile_deny_empty(uint32_t kind, void *head)
{
    switch (kind) {
    case 4: case 5: return port_filters_deny_if_empty(head);
    case 6: return icmp_filters_deny_if_empty(head);
    default: return ipp_filters_deny_if_empty(head);
    }
}
static bool filter_defaults(struct desync_profile *profile)
{
    return zapret_profile_filter_defaults(profile, profile_deny_empty);
}
