#ifndef ZAPRET_NATIVE_WORDEXP_H
#define ZAPRET_NATIVE_WORDEXP_H

#include <stddef.h>

typedef struct {
    size_t we_wordc;
    char **we_wordv;
    size_t we_offs;
} wordexp_t;

#define WRDE_DOOFFS 0x0001
#define WRDE_APPEND 0x0002
#define WRDE_NOCMD 0x0004
#define WRDE_REUSE 0x0008
#define WRDE_SHOWERR 0x0010
#define WRDE_UNDEF 0x0020
enum {
    WRDE_SUCCESS, WRDE_NOSPACE, WRDE_BADCHAR, WRDE_BADVAL,
    WRDE_CMDSUB, WRDE_SYNTAX, WRDE_NOSYS
};

#ifdef __cplusplus
extern "C" {
#endif

/* Rust writes complete NUL-separated UTF-8 words only when capacity suffices.
 * A sizing call returns WRDE_NOSPACE with required/word_count populated.
 * Other errors leave both lengths zero and the output bytes untouched. */
int zapret_wordexp(const unsigned char *input, size_t length,
                  unsigned char *output, size_t capacity,
                  size_t *required, size_t *word_count);
int wordexp(const char *words, wordexp_t *result, int flags);
void wordfree(wordexp_t *result);

#ifdef __cplusplus
}
#endif
#endif
