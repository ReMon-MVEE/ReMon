#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    #define max 0x0001FFFF
    int register tmp;

    for (int register i = 0; i < max; ++i)
    {
        for (int register j = 0; j < max; ++j)
        {
            tmp = i << j;
        }
    }

    printf("Done!\n");

    return 0;
}
