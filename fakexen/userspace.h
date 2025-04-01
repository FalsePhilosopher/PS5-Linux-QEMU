#pragma once

uint64_t init_userspace_cr3(uint64_t);
void init_userspace_ist(void);
void arrange_jump_to_userspace(uint64_t* regs, uint64_t* iret_frame);
int parse_userspace_trap(uint64_t* regs, uint64_t** p_iret_frame, int* p_vector);
