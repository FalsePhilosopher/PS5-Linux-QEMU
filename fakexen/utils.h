#pragma once
#include "types.h"

void map_page(uint64_t cr3, uint64_t virt, uint64_t phys, int prot);
void map_hugepage(uint64_t cr3, uint64_t virt, uint64_t phys, int prot);
uint64_t virt2phys(uint64_t cr3, uint64_t virt, uint64_t* virt_start, uint64_t* virt_end);

int copy_from_kernel(uint64_t cr3, char* dst, uint64_t src, size_t sz);
int copy_to_kernel(uint64_t cr3, uint64_t dst, const char* src, size_t sz);
int zero_to_kernel(uint64_t cr3, uint64_t dst, size_t sz);
