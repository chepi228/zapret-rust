#include <stdio.h>
#include <stdlib.h>
#include <wordexp.h>
int main(int argc, char **argv) {
    if (argc != 2) return 90;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 91;
    char text[65537];
    size_t n = fread(text,1,sizeof(text)-1,f);
    fclose(f);
    text[n] = 0;
    wordexp_t words = {0};
    int status = wordexp(text,&words,WRDE_NOCMD);
    printf("%d\n%zu\n",status,words.we_wordc);
    if (!status) {
        for (size_t i=0; i<words.we_wordc; i++) {
            for (unsigned char *p=(unsigned char*)words.we_wordv[i]; *p; p++) printf("%02x",*p);
            putchar('\n');
        }
    }
    wordfree(&words);
    return 0;
}
