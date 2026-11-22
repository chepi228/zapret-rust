/* MIT. Bounds-checked file seek offsets without mutating the argument. */
bool zapret_parse_filespec(const char **, unsigned long long *);
static bool parse_filespec(const char **filename, unsigned long long *offset)
{
    if (zapret_parse_filespec(filename, offset)) return true;
    DLOG("offset read error: %s\n", *filename + 1);
    return false;
}
