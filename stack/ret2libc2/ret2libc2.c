#include <stdio.h>
#include <string.h>

static int vul_func(void)
{
    char buffer[0x6c]; // 108
    return gets(buffer);
}

int main(int argc, const char *argv[])
{

    // 7c : 116

    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 1, 0);

    puts("No surprise anymore, system disappeard QQ.");
    puts("Can you find it !?");
    vul_func();
    return 0;
}