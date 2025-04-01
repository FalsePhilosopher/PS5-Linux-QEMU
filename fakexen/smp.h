#pragma once
#include "types.h"

struct trap_info
{
    uint8_t vector;
    uint8_t flags;
    uint16_t cs;
    uint64_t address;
};

struct cpu_user_regs
{
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint32_t error_code;
    uint32_t entry_vector;
    uint64_t rip;
    uint16_t cs;
    uint16_t pad0;
    uint8_t saved_upcall_mask;
    uint8_t pad1[3];
    uint64_t rflags;
    uint64_t rsp;
    uint16_t ss;
    uint16_t es;
    uint16_t ds;
    uint16_t fs;
    uint16_t gs;
    uint64_t pad2[3];
};

struct vcpu_guest_context
{
    char fpu_ctxt[512];
    uint64_t flags;
    struct cpu_user_regs user_regs;
    struct trap_info trap_ctxt[256];
    uint64_t ldt_base;
    uint64_t ldt_ents;
    uint64_t gdt_frames[16];
    uint64_t gdt_ents;
    uint64_t kernel_ss;
    uint64_t kernel_sp;
    uint64_t ctrlreg[8];
    uint64_t debugreg[8];
    uint64_t event_callback_eip;
    uint64_t failsafe_callback_eip;
    uint64_t syscall_callback_eip;
    uint64_t vm_assist;
    uint64_t fs_base;
    uint64_t gs_base_kernel;
    uint64_t gs_base_user;
};

void smp_start_cpu(int which);
void smp_waitloop(int which);
int smp_is_cpu_up(int which);
