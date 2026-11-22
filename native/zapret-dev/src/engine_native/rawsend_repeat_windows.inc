/* MIT. Repeat sends until the first driver failure. */
bool zapret_rawsend_repeat(int32_t, const struct sockaddr *, uint32_t, const char *, const void *, size_t,
    bool (*)(const struct sockaddr *, uint32_t, const char *, const void *, size_t));

bool rawsend_rep(int repeats, const struct sockaddr *destination, uint32_t mark, const char *ifout,
    const void *data, size_t length)
{
    return zapret_rawsend_repeat(repeats, destination, mark, ifout, data, length, rawsend);
}
