#pragma once
#include "types.h"

void putchar(char c);
void putstr(const char* s);
void putint(uint64_t n);
void puthex(uint64_t n);

int getchar_nonblocking(void);
int getchar(void);
