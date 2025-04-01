#pragma once
#include "memmap.h"

#define IST_SLOT_IDX(idx) (2 * sizeof(char[(idx)]) - sizeof(char[(idx)]) % 5)
#define IST_ENTRY(idx) (IST_PAGE + 48 * IST_SLOT_IDX(idx) + 48 + KERNEL_OFFSET)
#define IST_SAVED_FRAME(idx) (IST_PAGE + 48 * IST_SLOT_IDX(idx) + 8)
#define IST_RETURN_FRAME(idx) (IST_PAGE + 48 * IST_SLOT_IDX(idx) + 240)
#define IST_RETURN_FRAME_ERRC(idx) (IST_PAGE + 48 * IST_SLOT_IDX(idx) + 232) //corrupts previous

enum
{
    IST_SLOT_INT1 = 0,
    IST_SLOT_INT179 = 1,
    IST_SLOT_INT180 = 2,
    IST_SLOT_PAGEFAULT = 4, //corrupts upper part of 3
    IST_SLOT_JUSTRETURN = 5, //corrupts upper parts of 6, 7
    IST_SLOT_SCRATCH = 6,
    IST_SLOT_LANDING = 7,
    IST_SLOT_INT1_GUEST = 8,
    IST_SLOT_INT1_SHENANIGANS = 10, //eats 11-14
    IST_SLOT_INT1_FOR_USERSPACE = 15, //eats 16
    IST_SLOT_PF_FOR_USERSPACE = 18, //eats 17
    IST_SLOT_FIRST_FREE = 19,
};

extern char verify_ist_fits[1/(IST_PAGE0 + 48 * IST_SLOT_IDX(IST_SLOT_FIRST_FREE) + 240<=TSS0-sizeof(struct guest_state))];

#define JUSTRETURN_POP_FRAME (IST_RETURN_FRAME(IST_SLOT_JUSTRETURN) + 40)
