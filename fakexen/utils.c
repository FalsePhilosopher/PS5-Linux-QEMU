#include "utils.h"
#include "memmap.h"
#include "page_alloc.h"
#include "string.h"
#include "die.h"

static void do_map_page(uint64_t pml, uint64_t virt, uint64_t phys, int prot1, int prot2, int depth)
{
    pml |= 1;
    uint64_t* tgt = &pml;
    for(int i = 39; i >= depth; i -= 9)
    {
        if(!(*tgt & 1))
        {
            uint64_t page = alloc_page();
            *tgt = page | prot1;
        }
        else
            *tgt |= prot1;
        if((*tgt & 128))
            die("do_map_page: tried to remap over hugepage");
        if((*tgt & 512))
        {
            uint64_t old_page = *tgt & ((1ull << 52) - (1ull << 12));
            uint64_t new_page = alloc_page();
            memcpy(DMEM + new_page, DMEM + old_page, 4096);
            *tgt ^= old_page ^ new_page ^ 512;
        }
        uint64_t page = *tgt & ((1ull << 52) - (1ull << 12));
        uint64_t* page_mapping = (uint64_t*)(DMEM + page);
        tgt = page_mapping + ((virt >> i) & 511);
    }
    *tgt = phys | prot2;
}

void map_page(uint64_t cr3, uint64_t virt, uint64_t phys, int prot)
{
    do_map_page(cr3, virt, phys, prot, prot, 12);
}

void map_hugepage(uint64_t cr3, uint64_t virt, uint64_t phys, int prot)
{
    do_map_page(cr3, virt, phys, prot, prot | 128, 21);
}

uint64_t virt2phys(uint64_t cr3, uint64_t vaddr, uint64_t* virt_start, uint64_t* virt_end)
{
    for(int i = 39; i >= 12; i -= 9)
    {
        size_t idx = (vaddr >> i) & 511;
        uint64_t value = *(uint64_t*)(DMEM + cr3 + 8 * idx);
        value &= (1ull << 52) - 1;
        uint64_t mask = (1ull << i) - 1;
        if(i == 12 || (value & 128) || !(value & 1))
        {
            *virt_start = vaddr & ~mask;
            *virt_end = *virt_start + mask + 1;
            if(!(value & 1))
                return -1;
            return (value & ~mask) + (vaddr & mask);
        }
        cr3 = value & ((1ull << 52) - (1ull << 12));
    }
}

int copy_from_kernel(uint64_t cr3, char* dst, uint64_t src, size_t sz)
{
    uint64_t virt_start, virt_end;
    while(sz)
    {
        uint64_t phys = virt2phys(cr3, src, &virt_start, &virt_end);
        if(phys == (uint64_t)-1)
            return -1;
        size_t chk = sz;
        if(virt_end - src < chk)
            chk = virt_end - src;
        memcpy(dst, DMEM + phys, chk);
        dst += chk;
        src += chk;
        sz -= chk;
    }
    return 0;
}

int copy_to_kernel(uint64_t cr3, uint64_t dst, const char* src, size_t sz)
{
    uint64_t virt_start, virt_end;
    while(sz)
    {
        uint64_t phys = virt2phys(cr3, dst, &virt_start, &virt_end);
        if(phys == (uint64_t)-1)
            return -1;
        size_t chk = sz;
        if(virt_end - dst < chk)
            chk = virt_end - dst;
        memcpy(DMEM + phys, src, chk);
        dst += chk;
        src += chk;
        sz -= chk;
    }
    return 0;
}

int zero_to_kernel(uint64_t cr3, uint64_t dst, size_t sz)
{
    uint64_t virt_start, virt_end;
    while(sz)
    {
        uint64_t phys = virt2phys(cr3, dst, &virt_start, &virt_end);
        if(phys == (uint64_t)-1)
            return -1;
        size_t chk = sz;
        if(virt_end - dst < chk)
            chk = virt_end - dst;
        memset(DMEM + phys, 0, chk);
        dst += chk;
        sz -= chk;
    }
    return 0;
}
