#include "ist_page.h"

#define IST(x) (*(char*)(IDT + 16 * (x) + 4))

#define GADGETS_ENABLED 1
#define GADGETS_DISABLED 6

static inline int enable_gadgets(void)
{
    int ans = IST(1);
    IST(1) = GADGETS_ENABLED;
    return ans;
}

static inline void disable_gadgets(int old)
{
    IST(1) = old;
}

extern char rdmsr_start[];
extern char wrmsr_ret[];

#define SET_GADGET(x) (*(uint64_t*)IST_RETURN_FRAME(IST_SLOT_INT179) = GADGET(x))

static inline void wrmsr(uint32_t msr, uint64_t value)
{
    int status = enable_gadgets();
    SET_GADGET(wrmsr_ret);
    asm volatile("int $179"::"c"(msr),"a"(value),"d"(value >> 32));
    disable_gadgets(status);
}

static inline uint64_t rdmsr(uint32_t msr)
{
    int status = enable_gadgets();
    SET_GADGET(rdmsr_start);
    uint32_t eax, edx;
    asm volatile("int $179":"=a"(eax),"=d"(edx):"c"(msr));
    disable_gadgets(status);
    return (uint64_t)edx << 32 | eax;
}
