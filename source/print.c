#include <stdio.h>
#include <assert.h>

#include "exploit.h"

// TODO: printf("%d %d\n", C->nrows, C->ncols);

void print_line_vector(mzd_t *v, int length, char *prefix)
{
    int b, i;

    //~ assert(v->nrows == length);
    //~ assert(v->ncols == 1);

    if(prefix)
        printf("%s", prefix);
    for(i=0; i<length; i++) {
        b = mzd_read_bit(v, i, 0);
        printf("%d ", b);
    }
    printf("\n");
} 

void print_column_vector(mzd_t *v, int length, char *prefix)
{
    int b, i;

    //~ assert(v->ncols == length);
    //~ assert(v->nrows == 1);

    if(prefix)
        printf("%s", prefix);
    for(i=0; i<length; i++) {
        b = mzd_read_bit(v, 0, i);
        printf("%d ", b);
    }
    printf("\n");
} 

void print_list(uint8_t *l, int length, char *prefix)
{
    int i;

    if(prefix)
        printf("%s", prefix);
    for(i=0; i<length; i++) {
        printf("%d ", l[i]);
    }
    printf("\n");
}

void print_uint64_array_as_hex(uint64_t p[], int n)
{
    int i;
    for(i=0; i<n; i++) {
        printf("%.16lx\n", p[i]);
    }
}
