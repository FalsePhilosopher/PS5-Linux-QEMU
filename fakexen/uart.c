#include "uart.h"

int getchar(void)
{
    int ans;
    while((ans = getchar_nonblocking()) < 0);
    return ans;
}

void putstr(const char* s)
{
    for(char c; c = *s++;)
        putchar(c);
}

void putint(uint64_t n)
{
    uint64_t q = 1;
    while(q < 10000000000000000000ull && n >= q)
        q *= 10;
    if(q > 1 && n < q)
        q /= 10;
    while(q)
    {
        int qq = n / q;
        putchar(qq + '0');
        n -= qq * q;
        q /= 10;
    }
}

void puthex(uint64_t n)
{
    uint64_t q = 0;
    while(q < 60 && n >= (1ull << q))
        q += 4;
    if(q > 0 && n < (1ull << q))
        q -= 4;
    for(;;)
    {
        int qq = (n >> q) & 15;
        if(qq >= 10)
            putchar(qq - 10 + 'a');
        else
            putchar(qq + '0');
        if(!q)
            break;
        q -= 4;
    }
}
