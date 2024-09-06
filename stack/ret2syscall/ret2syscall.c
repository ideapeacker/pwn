#include <stdio.h>
#include <string.h>

int main(int argc, const char * argv[]){

    char buffer[0x6c]; // 108
    // 7c : 116

    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 1, 0);

    puts("This time, no system() and NO SHELLCODE!!!");
    puts("What do you plan to do ?");
    
    gets(buffer);

    return 0;
}