/* Previous config expansion adapter, compiled only by the comparison fixture. */
#include "wordexp.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void wordfree(wordexp_t *result)
{
    if (!result) return;
    if (result->we_wordv) {
        free(result->we_wordv[0]);
        free(result->we_wordv);
    }
    result->we_wordc = 0;
    result->we_wordv = NULL;
    result->we_offs = 0;
}

int wordexp(const char *words, wordexp_t *result, int flags)
{
    if (!result) return WRDE_NOSPACE;
    if (flags & WRDE_REUSE) wordfree(result);
    result->we_wordc = 0;
    result->we_wordv = NULL;
    result->we_offs = 0;
    if (!words || (flags & ~(WRDE_NOCMD | WRDE_REUSE | WRDE_SHOWERR)) ||
        !(flags & WRDE_NOCMD)) return WRDE_NOSYS;

    size_t length = strnlen(words, 65537);
    if (length > 65536) return WRDE_NOSPACE;
    size_t required = 0, count = 0;
    int status = zapret_wordexp((const unsigned char *)words, length,
                               NULL, 0, &required, &count);
    if (status != WRDE_SUCCESS && status != WRDE_NOSPACE) return status;

    /* Environment and directory changes can alter expansion between sizing and
     * filling. Retry from the returned dimensions before publishing any pointer. */
    for (unsigned attempt = 0; attempt < 3; attempt++) {
        if (required > 4 * 1024 * 1024 || count > 16384) return WRDE_NOSPACE;
        unsigned char *data = required ? malloc(required) : NULL;
        if (required && !data) return WRDE_NOSPACE;
        size_t capacity = required;
        status = zapret_wordexp((const unsigned char *)words, length,
                               data, capacity, &required, &count);
        if (status == WRDE_NOSPACE && required > capacity) {
            free(data);
            continue;
        }
        if (status != WRDE_SUCCESS || count > 16384) {
            free(data);
            return status == WRDE_SUCCESS ? WRDE_NOSPACE : status;
        }
        char **vector = calloc(count + 1, sizeof(*vector));
        if (!vector) {
            free(data);
            return WRDE_NOSPACE;
        }
        size_t offset = 0;
        for (size_t i = 0; i < count; i++) {
            if (offset >= required) goto corrupt;
            const unsigned char *end = memchr(data + offset, 0, required - offset);
            if (!end) goto corrupt;
            vector[i] = (char *)data + offset;
            offset = (size_t)(end - data) + 1;
        }
        if (offset != required) goto corrupt;
        result->we_wordv = vector;
        result->we_wordc = count;
        return WRDE_SUCCESS;
    corrupt:
        free(vector);
        free(data);
        return WRDE_SYNTAX;
    }
    return WRDE_NOSPACE;
}
