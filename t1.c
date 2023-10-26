#include <stdio.h>

void say_hello(char *who)
{
    printf("hello, %s!\n", who);
}

char *my_name = "wb";

int main()
{
    say_hello(my_name);
    return 0;
}    
