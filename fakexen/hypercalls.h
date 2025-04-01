#pragma once
#include "types.h"
#include "e820.h"

void handle_hypercall_syscall(uint64_t* regs, uint64_t* iret_frame);
void set_e820_map_for_linux(struct e820_map* start, struct e820_map* end);
void get_e820_map_for_linux(struct e820_map** start, struct e820_map** end);

#define HYPERCALL __attribute__((no_caller_saved_registers))

HYPERCALL int hypercall_set_gdt(uint64_t* mfn, uint64_t size);
uint64_t fix_pte(uint64_t pte);

extern uint64_t irqs_enabled[4];
extern uint64_t event_array;
