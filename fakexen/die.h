#pragma once
#include "uart.h"

static inline void die(const char* msg)
{
    putstr(msg);
    putchar('\r');
    putchar('\n');
    for(;;)
        asm volatile("");
}
