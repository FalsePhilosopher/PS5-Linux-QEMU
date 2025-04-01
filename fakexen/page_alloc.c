#include "page_alloc.h"
#include "die.h"
#include "memmap.h"
#include "string.h"

uint64_t page_alloc_base;
uint64_t page_alloc_start;
uint64_t page_alloc_end;
static uint64_t page_alloc_freelist;

#define FREELIST_BUSY 1

uint64_t alloc_page(void)
{
    uint64_t ans;
    while((ans = __atomic_exchange_n(&page_alloc_freelist, FREELIST_BUSY, __ATOMIC_SEQ_CST)) == FREELIST_BUSY);
    if(!ans)
    {
        __atomic_store_n(&page_alloc_freelist, 0, __ATOMIC_SEQ_CST);
        ans = -1;
        while(!__atomic_compare_exchange_n(&page_alloc_start, &ans, ans + 4096, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
            if(ans == page_alloc_end)
                die("Out of pages!");
        memset(DMEM+ans, 0, 4096);
        return ans;
    }
    uint64_t next = *(uint64_t*)(DMEM + page_alloc_freelist);
    __atomic_store_n(&page_alloc_freelist, next, __ATOMIC_SEQ_CST);
    memset(DMEM+ans, 0, 4096);
    return ans;
}

void free_page(uint64_t addr)
{
    uint64_t expected = -1;
    while(!__atomic_compare_exchange_n(&page_alloc_freelist, &expected, addr, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        *(uint64_t*)(DMEM + addr) = expected;
}
