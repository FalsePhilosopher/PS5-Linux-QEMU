#pragma once
#include "types.h"

struct vcpu_time_info
{
    uint32_t version;
    uint32_t pad0;
    uint64_t tsc_timestamp;
    uint64_t system_time;
    uint32_t tsc_to_system_mul;
    int8_t tsc_shift;
    uint8_t flags;
    uint8_t pad1[3];
};

struct arch_vcpu_info
{
    uint64_t cr2;
    uint64_t pad;
};

struct vcpu_info
{
    uint8_t evtchn_upcall_pending;
    uint8_t evtchn_upcall_mask;
    uint64_t evtchn_pending_sel;
    struct arch_vcpu_info arch;
    struct vcpu_time_info time;
};
