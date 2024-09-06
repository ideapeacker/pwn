#include <stdio.h>
#include <stdlib.h>

int backdoor(){
    system("/bin/sh");
    return 0;
}
int vul_leak_canary()
{
    unsigned char buffer[0x20];
    printf("Who are you?\n");
    read(0, buffer, 0x30);

    printf("Hello %s\n", buffer);
    printf("What do you want to do?\n");
    read(0, buffer, 0x300);
    printf("OK~\n");
    return 0;
}
int main(int argc, char *argv[])
{
    puts("test leak canary...!\n");
    vul_leak_canary();
    return 0;
}