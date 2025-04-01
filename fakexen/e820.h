#pragma once
#include "types.h"

struct e820_map
{
    uint64_t start;
    uint64_t size;
    uint32_t kind;
} __attribute__((packed));

enum { KIND_FREE = 1, KIND_RESERVED = 2 };
