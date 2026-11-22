/* Native CRT ownership and failure atomicity of the production C shim. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "wordexp.h"

int main(void)
{
    wordexp_t words = {0};
    for (unsigned i = 0; i < 1000; i++) {
        assert(wordexp("x 'two words' \"\" \\*.txt", &words, WRDE_NOCMD) == WRDE_SUCCESS);
        assert(words.we_wordc == 4 && !words.we_wordv[4]);
        assert(!strcmp(words.we_wordv[0], "x"));
        assert(!strcmp(words.we_wordv[1], "two words"));
        assert(!strcmp(words.we_wordv[2], ""));
        assert(!strcmp(words.we_wordv[3], "*.txt"));
        assert(wordexp("x 'unterminated", &words, WRDE_NOCMD | WRDE_REUSE) == WRDE_SYNTAX);
        assert(!words.we_wordc && !words.we_wordv && !words.we_offs);
        wordfree(&words);
        wordfree(&words);
    }
    assert(wordexp("x $(literal command) `literal command`", &words, WRDE_NOCMD) == WRDE_SUCCESS);
    assert(words.we_wordc == 5);
    assert(!strcmp(words.we_wordv[1], "$(literal"));
    assert(!strcmp(words.we_wordv[2], "command)"));
    wordfree(&words);

    unsigned char output[4] = {0xa5, 0xa5, 0xa5, 0xa5};
    size_t required = 0, count = 0;
    assert(zapret_wordexp((const unsigned char *)"x longword", 10,
                          output, sizeof(output), &required, &count) == WRDE_NOSPACE);
    assert(required == 11 && count == 2);
    assert(output[0] == 0xa5 && output[3] == 0xa5);
    assert(zapret_wordexp((const unsigned char *)"x '", 3,
                          output, sizeof(output), &required, &count) == WRDE_SYNTAX);
    assert(!required && !count && output[0] == 0xa5 && output[3] == 0xa5);
    puts("PASS 1000 native allocation/reuse/free cycles and atomic FFI failures");
    return 0;
}
