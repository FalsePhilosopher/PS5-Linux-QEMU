#pragma once

#define TSC_FREQ_HZ 1596300166

static inline uint64_t rdtsc(void)
{
    uint32_t a, d;
    asm volatile("rdtsc":"=a"(a),"=d"(d));
    return (uint64_t)d << 32 | a;
}

extern uint64_t tsc_value_at_boot;

static inline uint64_t muldiv(uint64_t a, uint64_t b, uint64_t c)
{
    //we have no libgcc, thus can't do __int128 division natively. this asm should do it though
    asm volatile("imulq %2\nidivq %3":"=a"(a):"a"(a),"r"(b),"r"(c):"rdx");
    return a;
}

static inline uint64_t system_time(uint64_t tsc)
{
    return muldiv(tsc - tsc_value_at_boot, 1000000000, TSC_FREQ_HZ);
}
