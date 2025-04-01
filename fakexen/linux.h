#pragma once
#include "types.h"
#include "e820.h"

void parse_linux_elf(uint64_t* phys_start, uint64_t* actual_phys_start, uint64_t* phys_end);
void boot_linux(void);
