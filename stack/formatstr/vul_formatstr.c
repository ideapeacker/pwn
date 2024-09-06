#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    char buffer[0x30];
    int n = read(0, buffer, 0x30);
    printf(buffer);
    return 0;
}