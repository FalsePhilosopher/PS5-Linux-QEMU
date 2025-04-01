#include "linux.h"
#include "uart.h"
#include "die.h"
#include "memmap.h"
#include "ist_page.h"
#include "gadgets.h"
#include "string.h"
#include "utils.h"
#include "page_alloc.h"
#include "e820.h"
#include "hypercalls.h"
#include "exceptions.h"
#include "gdb_stub.h"
#include "tsc.h"

#define TSC_FREQ_FOR_LINUX ((1000000000ull << 32) / TSC_FREQ_HZ)

void jump_to_linux(uint64_t rsi);

extern char linux_start[];
extern char image_start[];
extern char hypercall_entry[];
extern char acpi_rsdp[];
extern char mov_cr3_rax_mov_ds[];

static uint64_t phys_start = -1;
static uint64_t phys_end;
static uint64_t virt_offset;
static uint64_t entry;

void parse_linux_elf(uint64_t* p_ps, uint64_t* p_aps, uint64_t* p_pe)
{
    uint64_t* elf_header = (uint64_t*)linux_start;
    uint64_t phoff = elf_header[4];
    uint16_t phnum = elf_header[7];
    uint64_t* phdr = (uint64_t*)(linux_start + phoff);
    uint32_t* note_start = 0;
    uint32_t* note_end = 0;
    for(size_t i = 0; i < phnum; i++, phdr += 7)
    {
        if((uint32_t)phdr[0] == 1)
        {
            uint64_t offset = phdr[1];
            uint64_t paddr = phdr[3];
            uint64_t memsz = phdr[5];
            if(paddr < phys_start)
                phys_start = paddr;
            if(paddr + memsz > phys_end)
                phys_end = paddr + memsz;
        }
        else if((uint32_t)phdr[0] == 4)
        {
            uint64_t offset = phdr[1];
            uint64_t filesz = phdr[5];
            note_start = (uint32_t*)(linux_start + offset);
            note_end = (uint32_t*)(linux_start + offset + filesz);
        }
    }
    for(uint32_t* i = note_start; i < note_end; i += 3 + (i[0] + 3) / 4 + (i[1] + 3) / 4)
        if(i[0] == 4 && i[3] == 'X' + 'e' * 256 + 'n' * 65536)
            if(i[2] == 1 && i[1] == 8)
                memcpy(&entry, i+4, 8);
            else if(i[2] == 3 && i[1] == 8)
                memcpy(&virt_offset, i+4, 8);
    if(!virt_offset || !entry)
        die("parse_linux_elf: Xen ELF notes not found");
    phys_start &= -4096;
    *p_aps = phys_start;
    phys_start -= 2097152;
    *p_ps = phys_start;
    *p_pe = phys_end;
}

static size_t parse_kallsyms(uint64_t start, uint64_t end, const char** names, uint64_t* addresses)
{
    putstr("Parsing kallsyms... ");
    uint64_t shorts[2] = {};
    size_t n_shorts = 0;
    size_t cnt = 0;
    uint16_t prev = 0;
    for(uint16_t* i = (uint16_t*)start; i < (uint16_t*)end; i++)
    {
        uint16_t cur = *i;
        if(cur == prev + 2)
            cnt++;
        else
        {
            if(cnt == 26)
            {
                if(n_shorts == 2)
                    die("parse_kallsyms: too many shorts");
                shorts[n_shorts++] = (uint64_t)i;
            }
            cnt = 0;
        }
        prev = cur;
    }
    if(n_shorts != 2)
        die("parse_kallsyms: too few shorts");
    if(shorts[1] != shorts[0] + 64)
        die("parse_kallsyms: shorts do not look like kallsyms_token_index");
    uint64_t kallsyms_token_index = shorts[0] - 184;
    char* kallsyms_token_table = (char*)(kallsyms_token_index - 1);
    while(!*kallsyms_token_table)
        kallsyms_token_table--;
    while(*kallsyms_token_table)
        kallsyms_token_table--;
    kallsyms_token_table++;
    kallsyms_token_table -= *(uint16_t*)(kallsyms_token_index + 510) - *(uint16_t*)kallsyms_token_index;
    uint64_t kallsyms_offsets = kallsyms_token_index + 512;
    kallsyms_offsets += (-kallsyms_offsets) & 7;
    uint64_t* ptr = (uint64_t*)kallsyms_offsets;
    while(*ptr != virt_offset + 0x1000000)
        ptr++;
    uint64_t n_symbols = ((uint64_t)ptr - kallsyms_offsets) / 4;
    ptr = (uint64_t*)((uint64_t)kallsyms_token_table - 8);
    while(*ptr != n_symbols && *ptr != n_symbols - 1)
        ptr--;
    n_symbols = *ptr;
    uint64_t kallsyms_num_syms = (uint64_t)ptr;
    uint64_t kallsyms_names = kallsyms_num_syms + 8;
    for(size_t i = 0; names[i]; i++)
    {
        const uint8_t* p = (uint8_t*)kallsyms_names;
        for(size_t j = 0; j < n_symbols; j++)
        {
            const char* name = names[i];
            size_t sz = 0;
            if(*p < 128)
                sz = *p++;
            else
            {
                sz = (*p++) & 127;
                sz |= (*p++) << 7;
            }
            const uint8_t* q = p + sz;
            while(p < q)
            {
                const char* name1 = kallsyms_token_table + *(uint16_t*)(kallsyms_token_index + 2 * (*p++));
                while(*name && *name1 && *name == *name1)
                {
                    name++;
                    name1++;
                }
                if(*name1)
                {
                    p = q;
                    goto cont;
                }
            }
            if(!*name)
            {
                int32_t offset = ~*(int32_t*)(kallsyms_offsets + 4 * j);
                addresses[i] = virt_offset + 0x1000000 + offset;
                goto cont1;
            }
        cont:;
        }
        putstr("parse_kallsyms: failed to find symbol ");
        putstr(names[i]);
        die("");
    cont1:;
    }
    putstr("done\r\n");
}

static int hook_set_phys_to_machine(uint64_t pfn, uint64_t mfn)
{
    if(pfn != mfn)
        die("hook_set_phys_to_machine: pfn != mfn");
    return 1;
}

static int hook_xen_set_identity_and_remap_chunk(uint64_t a, uint64_t b, uint64_t c)
{
    return 0; //ignored anyway
}

static void detour(uint64_t virtual_address, void* target)
{
    uint8_t* dst = (uint8_t*)(DMEM + (virtual_address - virt_offset));
    if(dst[0] == 0xf3 && dst[1] == 0x0f && dst[2] == 0x1e && dst[3] == 0xfa) //endbr64
        //linux issues a warning when clobbering endbr if the start of the function is not actually endbr
        dst += 4;
    *dst++ = 0xff;
    *dst++ = 0x25;
    *dst++ = 0;
    *dst++ = 0;
    *dst++ = 0;
    *dst++ = 0;
    memcpy(dst, &target, sizeof(target));
}

static void load_linux_elf(uint64_t elf)
{
    memset(DMEM+phys_start, 0, phys_end - phys_start);
    putstr("Loading Linux ELF (0x");
    puthex(phys_start);
    putstr("-0x");
    puthex(phys_end);
    putstr(")... ");
    uint64_t* elf_header = (uint64_t*)(DMEM + elf);
    uint64_t phoff = elf_header[4];
    uint16_t phnum = elf_header[7];
    uint64_t* phdr = (uint64_t*)(DMEM + elf + phoff);
    for(size_t i = 0; i < phnum; i++, phdr += 7)
    {
        if((uint32_t)phdr[0] == 1)
        {
            uint64_t offset = phdr[1];
            uint64_t paddr = phdr[3];
            uint64_t filesz = phdr[4];
            uint64_t memsz = phdr[5];
            memcpy(DMEM + paddr, DMEM + elf + offset, filesz);
            memset(DMEM + paddr + filesz, 0, memsz - filesz);
        }
    }
    putstr("done\r\n");
    const char* names[] = {"Tset_phys_to_machine", "txen_set_identity_and_remap_chunk", 0};
    uint64_t offsets[] = {0, 0};
    parse_kallsyms((uint64_t)DMEM + phys_start, (uint64_t)DMEM + phys_end, names, offsets);
    detour(offsets[0], hook_set_phys_to_machine);
    detour(offsets[1], hook_xen_set_identity_and_remap_chunk);
    /*uint64_t hypercall_trampoline = (uint64_t)hypercall_entry;
    memcpy(xen_hypercall_pv, &hypercall_trampoline, sizeof(hypercall_trampoline));*/
}

extern uint64_t page_alloc_base;
extern uint64_t page_alloc_end;

void boot_linux(void)
{
    init_vcpu_time();
    uint64_t elf = page_alloc_end + (uint64_t)linux_start - (uint64_t)image_start;
    load_linux_elf(elf);
    putstr("Preparing initial pagetables for Linux... ");
    uint64_t cr3 = initial_cr3;
    uint64_t alloc = phys_start;
    uint64_t args_page = alloc;
    alloc += 4096;
    for(uint64_t addr = 0; addr < phys_end; addr += 4096)
    {
        uint64_t pte = cr3 | 1;
        uint64_t* p = &pte;
        for(size_t i = 39; i >= 12; i -= 9)
        {
            if(!(*p & 1))
            {
                uint64_t page = alloc;
                alloc += 4096;
                memset(DMEM+page, 0, 4096);
                *p = page | 7;
            }
            uint64_t page = *p & ((1ull << 52) - (1ull << 12));
            p = (uint64_t*)(DMEM + page) + (((addr + virt_offset) >> i) & 511);
        }
        *p = addr | 7;
    }
    uint64_t new_cr3 = alloc;
    alloc += 4096;
    memcpy(DMEM+new_cr3, DMEM+cr3, 4096);
    GUEST_STATE.cr3 = new_cr3;
    int g = enable_gadgets();
    SET_GADGET(mov_cr3_rax_mov_ds);
    asm volatile("int $179"::"a"(new_cr3));
    disable_gadgets(g);
    putstr("done\r\n");
    putstr("Preparing arguments... ");
    uint64_t args_virt = virt_offset + args_page;
    memset((void*)args_virt, 0, 4096);
    uint64_t nr_pages = -1;
    struct e820_map* s;
    struct e820_map* e;
    get_e820_map_for_linux(&s, &e);
    for(struct e820_map* i = s; i < e; i++)
    {
        uint64_t q = (i->start + i->size + 4095) >> 12;
        if(q > nr_pages)
            nr_pages = q;
    }
    memcpy((void*)(args_virt+0x20), &nr_pages, 8);
    *(char*)(args_virt+0x30) = 2;
    uint64_t virt_start, virt_end;
    uint64_t ptr = virt2phys(cr3, (uint64_t)shared_page, &virt_start, &virt_end);
    memcpy((void*)(args_virt + 0x28), &ptr, 8);
    ptr = new_cr3 + virt_offset;
    memcpy((void*)(args_virt + 0x58), &ptr, 8);
    uint64_t n_pt_frames = (alloc - new_cr3) >> 12;
    memcpy((void*)(args_virt + 0x60), &n_pt_frames, 8);
    uint64_t mfn_list = PFN_TO_MFN_START;
    memcpy((void*)(args_virt + 0x68), &mfn_list, 8);
//#define CMDLINE "console=hvc0 pci=nocrs earlycon=xenboot acpi_rsdp=0x"
#define CMDLINE "console=hvc0 pci=nocrs acpi_rsdp=0x"
    memcpy((void*)(args_virt + 0x80), CMDLINE, sizeof(CMDLINE));
    char* cmdline_ptr = (char*)(args_virt + 0x80 + sizeof(CMDLINE) - 1);
    for(int i = 60; i >= 0; i -= 4)
    {
        int q = ((uint64_t)acpi_rsdp >> i) & 15;
        if(q >= 10)
            *cmdline_ptr++ = q - 10 + 'a';
        else
            *cmdline_ptr++ = q + '0';
    }
    *cmdline_ptr++ = 0;
#undef CMDLINE
    putstr("done\r\n");
    putstr("entry = 0x");
    puthex(entry);
    putstr("\r\nJumping to Linux...\r\n");
    uint64_t mask = ((1ull << 52) - (1ull << 12));
    uint64_t* jr_frame = (uint64_t*)JUSTRETURN_POP_FRAME;
    jr_frame[0] = 0; //rdx
    jr_frame[1] = 0; //rcx
    jr_frame[2] = 0; //rax
    jr_frame[3] = entry; //rip
    jr_frame[4] = 0xfff3; //cs
    jr_frame[5] = 2; //eflags
    jr_frame[6] = 0; //rsp
    jr_frame[7] = 0xffeb; //ss
    for(size_t i = 0; i < 16; i++)
    {
        shared_page[8*i] = 0xffff00; //interrupts are disabled
        shared_page[8*i+7] = TSC_FREQ_FOR_LINUX;
    }
    if(getchar_nonblocking() >= 0)
    {
        uint64_t regs[16] = {};
        regs[6] = args_virt;
        gdb_stub(regs, jr_frame+3);
    }
    jump_to_linux(args_virt);
}
