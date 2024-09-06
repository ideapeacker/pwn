#include <stdio.h>
#include <stdlib.h>

void backdoor(void)
{
    system("/bin/sh");
}

void vul_bypasscanary(int argc, char *argv[])
{
    int i = 0;
    char **v4 = argv;
    __uint64_t v7[3];
    __uint64_t v6;

    for (; i <= 5; ++i)
    {
        printf("number [%d]=", i, v4[i]);
        scanf("%lld", &v7[i]);
        v6 += v7[i];
    }
    printf("sum=%lld\n", v6);
}

int main(int argc, char *argv[])
{
    vul_bypasscanary(argc, argv);
    return 0;
}
