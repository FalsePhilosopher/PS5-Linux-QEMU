#pragma once
#include "types.h"

#define RESERVED_AREA_START 0xffff800000000000
#define RESERVED_AREA_END 0xffff880000000000
#define DMEM ((char*)0xffff800000000000)
#define DMEM_UC ((char*)0xffff808000000000)
#define FAKEXEN_START 0xffff810000000000
#define FAKEXEN_END 0xffff818000000000
#define NEW_KDATA_BASE 0xffff820000000000
#define IDT0 0xffff828000000000
#define GDT0 0xffff828000001000
#define IST_PAGE0 0xffff828000011000
#define TSS0 0xffff828000012000
#define VCPU_GUEST_CONTEXT_START0 0xffff828000013000
#define VCPU_GUEST_CONTEXT_END0 0xffff828000015000
#define LANDING_PAGE 0xffff828000015000
#define KERNEL_OFFSET 0x200000
#define PERCPU_OFFSET 0x400000
#define PFN_TO_MFN_START 0xffff830000000000
#define PFN_TO_MFN_END 0xffff838000000000
#define LINUX_LOWMEM_START 0xffff888000000000
#define LINUX_LOWMEM_END 0xffff890000000000

struct guest_state
{
    uint64_t cr3;
    uint64_t user_cr3;
    uint64_t lstar;
    uint64_t cstar;
    uint64_t ia32_pat;
    uint64_t ss0;
    uint64_t rsp0;
    uint64_t pfn_to_mfn_page;
    uint64_t dbgregs[6];
    uint64_t gsbase;
    uint64_t kgsbase;
    struct vcpu_info* vcpu_info;
    uint64_t* trap_table;
    uint64_t event_callback_eip;
    uint64_t failsafe_callback_eip;
    uint64_t event_control_block;
    uint64_t* pml1t_for_gdt;
    uint64_t n_flushes;
    int apic_id;
    int ipi_bind;
    int pending_event;
};

#define GUEST_STATE0 (TSS0 - sizeof(struct guest_state))
#define GUEST_STATE (*(struct guest_state __seg_gs*)8)
#define REMOTE_GUEST_STATE(cpu) ((struct guest_state*)(GUEST_STATE0 + (cpu) * PERCPU_OFFSET))
#define PERCPU(x) ((x) + GUEST_STATE.apic_id * PERCPU_OFFSET)

#define IDT PERCPU(IDT0)
#define GDT PERCPU(GDT0)
#define IST_PAGE PERCPU(IST_PAGE0)
#define TSS PERCPU(TSS0)
#define VCPU_GUEST_CONTEXT_START PERCPU(VCPU_GUEST_CONTEXT_START0)
#define VCPU_GUEST_CONTEXT_END PERCPU(VCPU_GUEST_CONTEXT_END0)

extern char kdata_base[];
extern uint64_t new_kdata_base;
extern uint64_t initial_cr3;
extern uint64_t initial_user_cr3;

#define GADGET(x) ((uint64_t)x + new_kdata_base - (uint64_t)kdata_base)
