#include "timer.h"
#include "memmap.h"
#include "tsc.h"
#include "apic.h"

#define APIC_TIMER_HZ (TSC_FREQ_HZ/128)

void stop_periodic_timer(void)
{
    apic[0x320/4] = 4096;
}

void schedule_periodic_timer(uint64_t interval_ns)
{
    apic[0x320/4] = (1 << 17) | 0x20;
    apic[0x3e0/4] = 0;
    apic[0x380/4] = muldiv(interval_ns, APIC_TIMER_HZ, 1000000000);
}

void schedule_singleshot_timer(uint64_t interval_ns)
{
    uint64_t n_ticks = muldiv(interval_ns, APIC_TIMER_HZ, 1000000000);
    if(n_ticks < 10 || n_ticks != (uint32_t)n_ticks)
        n_ticks = 10;
    apic[0x320/4] = 0x20;
    apic[0x3e0/4] = 0;
    apic[0x380/4] = n_ticks;
}
