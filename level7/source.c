#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


char c[68];

int m()
{
    int *v0;
    int *v1;

    v1 = time(NULL);
    v0 = &c;
    return printf("%s - %d\n");
}

struct struct_type
{
    int priority;
    char *name;
};


int main(int argc, char **argv)
{
    struct struct_type *i1, *i2;

    FILE *v8;

    i1 = malloc(sizeof(struct struct_type));
    i1->priority = 1;
    i1->name = malloc(8);

    i2 = malloc(sizeof(struct struct_type));
    i2->priority = 2;
    i2->name = malloc(8);

    strcpy(i1->name, argv[1]);
    strcpy(i2->name, argv[2]);
    v8 = fopen("/home/user/level8/.pass", "r");
    fgets(&c, 68, v8);
    puts("~~");
    return 0;
}