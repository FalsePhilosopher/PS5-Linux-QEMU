#include "types.h"
#include "uart.h"
#include "e820.h"
#include "string.h"
#include "die.h"
#include "memmap.h"
#include "ist_page.h"
#include "page_alloc.h"
#include "linux.h"
#include "utils.h"
#include "hypercalls.h"
#include "userspace.h"
#include "exceptions.h"
#include "smp.h"
#include "tsc.h"
#include "apic.h"
#include "pci.h"
#include "../../ps5-kstuff/structs.h"

struct segtree
{
    struct segtree* left;
    struct segtree* right;
    uint64_t left_pages;
    uint64_t right_pages;
    uint64_t largest_gap_offset;
    uint64_t largest_gap_size;
};

static struct segtree* alloc_start = (void*)(uintptr_t)-1;
static struct segtree* alloc_end = (void*)(uintptr_t)-1;
static struct segtree* freelist = 0;
static struct segtree* root = 0;

static inline struct segtree* make(void)
{
    struct segtree* ans;
    if(freelist)
    {
        ans = freelist;
        freelist = freelist->left;
    }
    else if(alloc_start == alloc_end)
        die("Failed to allocate segment tree node");
    else
        ans = alloc_start++;
    ans->left = 0;
    ans->right = 0;
    ans->left_pages = 0;
    ans->right_pages = 0;
    ans->largest_gap_offset = 0;
    ans->largest_gap_size = 0;
    return ans;
}

#define FULLY_FREE ((struct segtree*)1)

static inline void destroy(struct segtree* node)
{
    if(!node || node == FULLY_FREE)
        return;
    node->left = freelist;
    freelist = node;
}

static struct segtree empty = {};

//__attribute__((optimize(3)))
static struct segtree* mark_segment(struct segtree* node, uint64_t start, uint64_t end, uint64_t l, uint64_t r, int value)
{
    if(l < start)
        l = start;
    if(r > end)
        r = end;
    if(r <= l || (!node && !value) || (node == FULLY_FREE && value))
        return node;
    if(l == start && r == end)
    {
        destroy(node);
        return value ? FULLY_FREE : 0;
    }
    if(!node)
        node = make();
    else if(node == FULLY_FREE)
    {
        node = make();
        node->left = node->right = FULLY_FREE;
        node->left_pages = node->right_pages = node->largest_gap_size = end - start;
    }
    size_t mid = (start + end) / 2;
    if(l < mid)
        node->left = mark_segment(node->left, start, mid, l, r, value);
    if(r > mid)
        node->right = mark_segment(node->right, mid, end, l, r, value);
    if(!node->left && !node->right)
    {
        destroy(node);
        return 0;
    }
    if(node->left == FULLY_FREE && node->right == FULLY_FREE)
    {
        destroy(node);
        return FULLY_FREE;
    }
    struct segtree full = {
        .left_pages = mid - start,
        .right_pages = mid - start,
        .largest_gap_offset = 0,
        .largest_gap_size = mid - start,
    };
    struct segtree* left = node->left ? (node->left == FULLY_FREE ? &full : node->left) : &empty;
    struct segtree* right = node->right ? (node->right == FULLY_FREE ? &full : node->right) : &empty;
    node->left_pages = left->left_pages == full.left_pages ? full.left_pages + right->left_pages : left->left_pages;
    node->right_pages = right->right_pages == full.right_pages ? left->right_pages + full.right_pages : right->right_pages;
    node->largest_gap_offset = left->largest_gap_offset;
    node->largest_gap_size = left->largest_gap_size;
    if(right->largest_gap_size > node->largest_gap_size)
    {
        node->largest_gap_offset = mid - start + right->largest_gap_offset;
        node->largest_gap_size = right->largest_gap_size;
    }
    if(left->right_pages + right->left_pages > node->largest_gap_size)
    {
        node->largest_gap_offset = mid - start - left->right_pages;
        node->largest_gap_size = left->right_pages + right->left_pages;
    }
    return node;
}

static void test_memory(struct segtree* node, uint64_t start, uint64_t end, int write)
{
    enum { MAGIC = 0x1337414142421337 };
    if(!node)
        return;
    else if(node == FULLY_FREE && write)
    {
        for(uint64_t addr = start; addr < end; addr++)
        {
            uint64_t paddr = addr << 12;
            for(uint64_t* i = (uint64_t*)paddr; i < (uint64_t*)(paddr + 4096); i++)
                *i = MAGIC * (uint64_t)i;
        }
    }
    else if(node == FULLY_FREE && !write)
    {
        for(uint64_t addr = start; addr < end; addr++)
        {
            uint64_t paddr = addr << 12;
            for(uint64_t* i = (uint64_t*)paddr; i < (uint64_t*)(paddr + 4096); i++)
                if(*i != MAGIC * (uint64_t)i)
                {
                    putstr("warning: memory at 0x");
                    puthex((uint64_t)i);
                    putstr(" has been corrupted\r\n");
                }
        }
    }
    else
    {
        uint32_t mid = (start + end) / 2;
        test_memory(node->left, start, mid, write);
        test_memory(node->right, mid, end, write);
    }
}

extern struct e820_map e820_start[];
extern struct e820_map e820_end[];
extern char image_start[];
extern char image_end[];
extern char linux_start[];
extern char linux_end[];
extern char kdata_base[];
extern char idt[];
extern char gdt_array[];
extern char tss_array[];
extern char add_rsp_iret[];
extern char swapgs_add_rsp_iret[];
extern char doreti_iret[];
extern char mov_cr3_rax_mov_ds[];
extern char ltr_ax[];
extern char lgdt_rdi[];
extern char lidt_lldt[];
extern char justreturn_pop[];
extern char return_trampoline[];
extern char debug_handler[];
extern char page_fault_handler[];
extern char wrmsr_ret[];
extern char rdmsr_start[];
extern char lapic_map[];

static uint64_t walk_down(uint64_t cr3, uint64_t vaddr, uint64_t* virt_start, uint64_t* virt_end)
{
    for(int i = 39; i >= 12; i -= 9)
    {
        root = mark_segment(root, 0, 1ull << 48, cr3 >> 12, (cr3 >> 12) + 1, 0);
        size_t idx = (vaddr >> i) & 511;
        uint64_t value = *(uint64_t*)(cr3 + 8 * idx);
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

static void mark_range(uint64_t cr3, uint64_t start, uint64_t end)
{
    uint64_t virt_start, virt_end;
    for(uint64_t addr = start; addr < end;)
    {
        uint64_t phys = walk_down(cr3, addr, &virt_start, &virt_end);
        if(phys != (uint64_t)-1)
            root = mark_segment(root, 0, 1ull << 48, (virt_start + phys - addr) >> 12, (virt_end + phys - addr) >> 12, 0);
        addr = virt_end;
    }
}

extern uint64_t page_alloc_base;
extern uint64_t page_alloc_start;
extern uint64_t page_alloc_end;

void emit_e820(struct segtree* node, uint64_t start, uint64_t end, uint64_t* tmp, struct e820_map** cur, struct e820_map* limit)
{
    if(!node || node == FULLY_FREE)
        return;
    uint64_t mid = (start + end) / 2;
    emit_e820(node->left, start, mid, tmp, cur, limit);
    int left_free = node->left == FULLY_FREE || (node->left && node->left->right_pages);
    int right_free = node->right == FULLY_FREE || (node->right && node->right->left_pages);
    if(right_free && !left_free)
        *tmp = mid << 12;
    else if(left_free && !right_free)
    {
        uint64_t range_start = *tmp;
        uint64_t range_end = mid << 12;
        if(*cur < limit)
        {
            struct e820_map* ptr = (*cur)++;
            ptr->start = range_start;
            ptr->size = range_end - range_start;
            ptr->kind = KIND_FREE;
        }
    }
    emit_e820(node->right, mid, end, tmp, cur, limit);
}

uint64_t new_kdata_base;

struct acpi_rsdp
{
    char signature[8];
    uint8_t checksum;
    char oemid[6];
    uint8_t revision;
    uint32_t rsdt_address;
    uint32_t length;
    uint64_t xsdt_address;
} __attribute__((packed));

struct acpi_rsdt
{
    uint32_t signature;
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oemid[6];
    char oemtableid[8];
    uint32_t oemrevision;
    uint32_t creator_id;
    uint32_t creator_revision;
    uint32_t tables[];
} __attribute__((packed));

struct acpi_xsdt
{
    uint32_t signature;
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oemid[6];
    char oemtableid[8];
    uint32_t oemrevision;
    uint32_t creator_id;
    uint32_t creator_revision;
    uint64_t tables[];
} __attribute__((packed));

struct acpi_mcfg
{
    uint32_t signature;
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oemid[6];
    char oemtableid[8];
    uint32_t oemrevision;
    uint32_t creator_id;
    uint32_t creator_revision;
    uint64_t reserved;
    struct
    {
        uint64_t base_addr;
        uint16_t segment_group;
        uint8_t start_bus;
        uint8_t end_bus;
        uint32_t reserved;
    } __attribute__((packed)) fragments[];
} __attribute__((packed));

#define FIND_MCFG(name, type)\
static inline struct acpi_mcfg* find_mcfg_ ## name(struct type* sdt)\
{\
    size_t n_tables = (sdt->length - __builtin_offsetof(struct type, tables)) / sizeof(*sdt->tables);\
    for(size_t i = 0; i < n_tables; i++)\
    {\
        struct acpi_mcfg* table = (void*)(uintptr_t)sdt->tables[i];\
        if(table->signature == ('M' | ('C' << 8) | ('F' << 16) | ('G' << 24)))\
            return table;\
    }\
    return 0;\
}

FIND_MCFG(rsdt, acpi_rsdt)
FIND_MCFG(xsdt, acpi_xsdt)

#undef FIND_MCFG

static inline struct acpi_mcfg* find_mcfg(void)
{
    extern struct acpi_rsdp acpi_rsdp;
    if(acpi_rsdp.revision >= 2)
        return find_mcfg_xsdt((struct acpi_xsdt*)acpi_rsdp.xsdt_address);
    else
        return find_mcfg_rsdt((struct acpi_rsdt*)(uintptr_t)acpi_rsdp.rsdt_address);
}

uint64_t pci_cfg_bases[256];

static void print_msi(volatile uint32_t* cap_msi)
{
    uint64_t addr;
    uint16_t data;
    if((cap_msi[0] & (1 << 23)))
    {
        addr = (uint64_t)cap_msi[2] << 32 | cap_msi[1];
        data = cap_msi[3];
    }
    else
    {
        addr = cap_msi[1];
        data = cap_msi[2];
    }
    putstr("MSI(addr = 0x");
    puthex(addr);
    putstr(", data = 0x");
    puthex(data);
    putchar(')');
}

static void pci_disable_bus_master(void)
{
    struct acpi_mcfg* mcfg = find_mcfg();
    if(!mcfg)
        return;
    size_t n_fragments = (mcfg->length - __builtin_offsetof(struct acpi_mcfg, fragments)) / sizeof(*mcfg->fragments);
    for(size_t i = 0; i < n_fragments; i++)
    {
        volatile uint8_t* mmio_mapping = (volatile void*)(DMEM_UC + mcfg->fragments[i].base_addr);
        for(size_t bus = mcfg->fragments[i].start_bus; bus <= mcfg->fragments[i].end_bus; bus++)
        {
            pci_cfg_bases[bus] = mcfg->fragments[i].base_addr + (bus << 20);
            for(size_t device = 0; device < 32; device++)
                for(size_t function = 0; function < 8; function++)
                {
                    volatile uint32_t* fn = (volatile uint32_t*)(mmio_mapping + (bus << 20) + (device << 15) + (function << 12));
                    uint32_t vid_did = fn[0];
                    if((uint16_t)vid_did == 0xffff) //missing device
                        continue;
                    volatile uint32_t* cap_msi = pci_find_capability(bus, device, function, 5);
                    volatile uint32_t* cap_msix = pci_find_capability(bus, device, function, 17);
                    int msi = cap_msi && ((cap_msi[0] >> 16) & 1);
                    int msix = cap_msix && ((cap_msix[0] >> 31) & 1);
                    putstr("disabling device: bus=");
                    putint(bus);
                    putstr(", device=");
                    putint(device);
                    putstr(", function=");
                    putint(function);
                    putstr(": vendor id = 0x");
                    puthex((uint16_t)vid_did);
                    putstr(", device id = 0x");
                    puthex(vid_did >> 16);
                    if(msi || msix)
                    {
                        putstr(" (");
                        if(msi)
                        {
                            print_msi(cap_msi);
                            cap_msi[0] &= -65537;
                        }
                        if(msi && msix)
                            putstr(", ");
                        if(msix)
                        {
                            putstr("MSIX");
                            cap_msix[0] &= 0x7fffffff;
                        }
                        putstr(" enabled)");
                    }
                    fn[1] &= -5;
                    putchar('\r');
                    putchar('\n');
                }
        }
#if 0
        //prevent linux from accessing bus 64 (titania). titania's uart is our only working way of communication
        if(mcfg->fragments[i].start_bus < 64)
            mcfg->fragments[i].end_bus = 63;
        else if(mcfg->fragments[i].end_bus > 64)
            mcfg->fragments[i].start_bus = 65;
#endif
    }
    asm volatile("":::"memory");
}

uint64_t initial_cr3;
uint64_t initial_user_cr3;

void relocate(uint64_t cr3)
{
    putstr("\r\n\r\n### ps5-fakexen is starting ###\r\n\r\n");
    pci_disable_bus_master();
    putstr("Original E820 map:\r\n");
    for(struct e820_map* i = e820_start; i < e820_end; i++)
    {
        puthex(i->start);
        putchar('-');
        puthex(i->start+i->size);
        putchar(' ');
        putint(i->kind);
        putchar('\r');
        putchar('\n');
    }
    putstr("Building the memory map... ");
    uint64_t* cr3_map = (uint64_t*)(DMEM + cr3);
    cr3_map[3] = cr3_map[0] & -5;
    for(struct e820_map* i = e820_start; i < e820_end; i++)
        if(i->kind == KIND_FREE && i->start < (uint64_t)alloc_start)
        {
            uint64_t start = i->start;
            if(!start)
                start++;
            start = ((start - 1) | 7) + 1;
            alloc_start = (void*)start;
            alloc_end = alloc_start + (i->start + i->size - start) / sizeof(*alloc_start);
        }
    for(struct e820_map* i = e820_start; i < e820_end; i++)
        if(i->kind == KIND_FREE)
            root = mark_segment(root, 0, 1ull << 48, (i->start + 4095) >> 12, (i->start + i->size) >> 12, 1);
    for(struct e820_map* i = e820_start; i < e820_end; i++)
        if(i->kind != KIND_FREE)
            root = mark_segment(root, 0, 1ull << 48, (i->start + 4095) >> 12, (i->start + i->size) >> 12, 0);
    uint64_t virt_start, virt_end;
    walk_down(cr3, 0, &virt_start, &virt_end);
    walk_down(cr3, 1ull << 39, &virt_start, &virt_end);
    mark_range(cr3, (uint64_t)image_start, (uint64_t)image_end);
    uint64_t kdata_end = (uint64_t)kdata_base;
    if((uint64_t)idt + 4096 > kdata_end)
        kdata_end = (uint64_t)idt + 4096;
    if((uint64_t)gdt_array + 16*0x68 > kdata_end)
        kdata_end = (uint64_t)gdt_array + 16*0x68;
    if((uint64_t)tss_array + 16*0x68 > kdata_end)
        kdata_end = (uint64_t)tss_array + 16*0x68;
    mark_range(cr3, (uint64_t)kdata_base, kdata_end);
    uint64_t addr = (uint64_t)kdata_base - 4096;
    for(uint64_t phys; (phys = walk_down(cr3, addr, &virt_start, &virt_end)) != (uint64_t)-1;)
    {
        root = mark_segment(root, 0, 1ull << 48, (virt_start + phys - addr) >> 12, (virt_end + phys - addr) >> 12, 0);
        addr = virt_start - 4096;
    }
    root = mark_segment(root, 0, 1ull << 48, 0, 256, 0);
    root = mark_segment(root, 0, 1ull << 48, 1 << 20, 1ull << 48, 0);
    putstr("done\r\n");
    if(!root || root == FULLY_FREE)
        die("No usable memory found");
    putstr("Testing memory... ");
    test_memory(root, 0, 1ull << 48, 1);
    uint64_t tsc = rdtsc();
    while(tsc + 5ll * TSC_FREQ_HZ > rdtsc());
    test_memory(root, 0, 1ull << 48, 0);
    putstr("done\r\n");
    addr = root->largest_gap_offset << 12;
    uint64_t size = root->largest_gap_size << 12;
    uint64_t linux_phys_start, linux_actual_phys_start, linux_phys_end;
    parse_linux_elf(&linux_phys_start, &linux_actual_phys_start, &linux_phys_end);
    root = mark_segment(root, 0, 1ull << 48, linux_phys_start >> 12, (linux_phys_end + 4095) >> 12, 0);
    uint64_t image_size = (uint64_t)image_end - (uint64_t)image_start;
    uint64_t alloc_pool = 0x1000000;
    if(size < image_size + alloc_pool)
    {
        putstr("Want ");
        putint(image_size + alloc_pool);
        putstr(" bytes, but the largest gap is ");
        putint(size);
        putstr(" bytes\r\n");
        die("Gap too small!");
    }
    uint64_t image_addr = addr + alloc_pool;
    page_alloc_base = addr;
    page_alloc_start = addr;
    page_alloc_end = image_addr;
    uint64_t new_cr3 = alloc_page();
    uint64_t* new_cr3_map = (uint64_t*)(DMEM + new_cr3);
    new_cr3_map[3] = cr3_map[3];
    uint64_t dmem_map = alloc_page();
    new_cr3_map[256] = dmem_map | 7;
    uint64_t* dmem_map_map = (uint64_t*)(DMEM + dmem_map);
    for(size_t i = 0; i < 512; i++)
        dmem_map_map[i] = (i << 30) | 135;
    dmem_map = alloc_page();
    new_cr3_map[257] = dmem_map | 31;
    dmem_map_map = (uint64_t*)(DMEM + dmem_map);
    for(size_t i = 0; i < 512; i++)
        dmem_map_map[i] = (i << 30) | 159;
    for(uint64_t virt = (uint64_t)image_start, phys = image_addr; virt < (uint64_t)linux_start; virt += 4096, phys += 4096)
        map_page(new_cr3, virt, phys, 7);
    //we need to keep the 2mb misalignment of kdata_base, otherwise we can't use hugepages for remapping
    new_kdata_base = (NEW_KDATA_BASE | ((uint64_t)kdata_base & 0x1fffff)) - 0x200000;
    uint64_t ktext_max = 0;
    uint64_t ktext_min = -1;
    for(uint64_t old_virt = (uint64_t)kdata_base - 4096, new_virt = new_kdata_base - 4096, phys; (phys = virt2phys(cr3, old_virt, &virt_start, &virt_end)) != (uint64_t)-1; new_virt -= old_virt - virt_start + 4096, old_virt = virt_start - 4096)
    {
        if(phys + (virt_start - old_virt) < ktext_min)
            ktext_min = phys + (virt_start - old_virt);
        if(phys + (virt_end - old_virt) > ktext_max)
            ktext_max = phys + (virt_end - old_virt);
        if(virt_end - virt_start == (1 << 12))
            map_page(new_cr3, new_virt, phys, 1);
        else
        {
            virt_start = virt_end - (1 << 21);
            map_hugepage(new_cr3, new_virt + virt_start - old_virt, phys + virt_start - old_virt, 1);
        }
    }
    putstr("BSD kernel text is at physical address 0x");
    puthex(ktext_min);
    putstr("-0x");
    puthex(ktext_max);
    putchar('\r');
    putchar('\n');
    uint64_t zero_page = alloc_page();
    for(uint64_t virt = new_kdata_base; virt < NEW_KDATA_BASE; virt += 4096)
        map_page(new_cr3, virt, zero_page, 1);
    for(int i = 0; i < 3; i++)
    {
        uint64_t pml = alloc_page();
        uint64_t* pml_map = (uint64_t*)(DMEM + pml);
        for(size_t i = 0; i < 512; i++)
            pml_map[i] = zero_page | 513;
        zero_page = pml;
    }
    new_cr3_map[260] = zero_page | 513;
    uint64_t lapic_map_page = alloc_page();
    map_page(new_cr3, GADGET(lapic_map) & -4096, lapic_map_page, 1);
    *(uint64_t*)(lapic_map_page + (GADGET(lapic_map) & 4095)) = (uint64_t)DMEM + zero_page; //writes 0 anyway, so won't corrupt the page
    new_cr3_map[511] = *(uint64_t*)(DMEM + cr3 + 4088);
    zero_to_kernel(new_cr3, (uint64_t)idt, 4096);
    zero_to_kernel(new_cr3, (uint64_t)tss_array, 16 * 0x68);
    uint8_t idt_entry[16] = {[2] = 0x20, [4] = 1, [5] = 0xee};
    uint64_t gadget = (uint64_t)add_rsp_iret;
    memcpy(idt_entry, (uint8_t*)&gadget, 2);
    memcpy(idt_entry + 6, (uint8_t*)&gadget + 2, 6);
    copy_to_kernel(new_cr3, (uint64_t)idt + 16, idt_entry, 16);
    idt_entry[4] = 2;
    copy_to_kernel(new_cr3, (uint64_t)idt + 179 * 16, idt_entry, 16);
    idt_entry[4] = 3;
    copy_to_kernel(new_cr3, (uint64_t)idt + 180 * 16, idt_entry, 16);
    uint64_t stacks = alloc_page();
    uint64_t* stacks_map = (uint64_t*)(DMEM + stacks);
    uint64_t* int1_stack = stacks_map + 6;
    stacks_map[30] = (uint64_t)return_trampoline;
    stacks_map[31] = 0x43;
    stacks_map[32] = 0x3002;
    stacks_map[33] = 0;
    stacks_map[34] = 0x3b;
    uint64_t* int179_stack = stacks_map + 12;
    stacks_map[36] = (uint64_t)mov_cr3_rax_mov_ds;
    stacks_map[37] = 0x20;
    stacks_map[38] = 0x102;
    stacks_map[39] = 0;
    stacks_map[40] = 0;
    uint64_t* int180_stack = stacks_map + 18;
    stacks_map[42] = (uint64_t)ltr_ax;
    stacks_map[43] = 0x20;
    stacks_map[44] = 0x102;
    stacks_map[45] = 0;
    stacks_map[46] = 0;
    uint64_t ist[3] = {(uint64_t)int1_stack + (3ull << 39) - (uint64_t)DMEM, (uint64_t)int179_stack + (3ull << 39) - (uint64_t)DMEM, (uint64_t)int180_stack + (3ull << 39) - (uint64_t)DMEM};
    for(size_t i = 0; i < 16; i++)
        copy_to_kernel(new_cr3, (uint64_t)tss_array + 0x68 * i + 0x24, (void*)ist, sizeof(ist));
    for(size_t i = 0; i < 16; i++)
    {
        uint64_t new_idt = alloc_page();
        copy_from_kernel(new_cr3, DMEM+new_idt, (uint64_t)idt, 4096);
        map_page(new_cr3, IDT0+i*PERCPU_OFFSET, new_idt, 7);
        map_page(new_cr3, IDT0+i*PERCPU_OFFSET+KERNEL_OFFSET, new_idt, 1);
        for(size_t j = 0; j < 16; j++)
        {
            uint64_t page = alloc_page();
            if(j == 0)
            {
                copy_from_kernel(new_cr3, DMEM+page, (uint64_t)gdt_array + 0x68 * i, 0x68);
                uint8_t new_tss[16] = {0x68, [5] = 0x89};
                uint64_t new_tss_addr = TSS0 + i*PERCPU_OFFSET + KERNEL_OFFSET;
                memcpy(new_tss+2, (uint8_t*)&new_tss_addr, 3);
                memcpy(new_tss+7, (uint8_t*)&new_tss_addr+3, 5);
                memcpy(DMEM+page+16, new_tss, 16);
                copy_to_kernel(new_cr3, (uint64_t)gdt_array + 0x68 * i, DMEM+page, 0x68);
            }
            map_page(new_cr3, GDT0+i*PERCPU_OFFSET+4096*j, page, 7);
            map_page(new_cr3, GDT0+i*PERCPU_OFFSET+4096*j+KERNEL_OFFSET, page, 3);
        }
        uint64_t ist_page = alloc_page();
        map_page(new_cr3, IST_PAGE0+i*PERCPU_OFFSET, ist_page, 7);
        map_page(new_cr3, IST_PAGE0+i*PERCPU_OFFSET+KERNEL_OFFSET, ist_page, 3);
        uint64_t tss_page = alloc_page();
        map_page(new_cr3, TSS0+i*PERCPU_OFFSET, tss_page, 7);
        map_page(new_cr3, TSS0+i*PERCPU_OFFSET+KERNEL_OFFSET, tss_page, 3);
        copy_from_kernel(new_cr3, DMEM+tss_page, (uint64_t)tss_array + 0x68 * i, 0x68);
    }
    putstr("Building E820 memory map for Linux... ");
    root = mark_segment(root, 0, 1ull << 48, 0, 1ull << 48, 0);
    for(struct e820_map* i = e820_start; i < e820_end; i++)
        if(i->kind == KIND_FREE)
            root = mark_segment(root, 0, 1ull << 48, (i->start + 4095) >> 12, (i->start + i->size) >> 12, 1);
    for(struct e820_map* i = e820_start; i < e820_end; i++)
        if(i->kind != KIND_FREE)
            root = mark_segment(root, 0, 1ull << 48, (i->start + 4095) >> 12, (i->start + i->size) >> 12, 0);
    root = mark_segment(root, 0, 1ull << 48, page_alloc_base >> 12, ((uint64_t)linux_start + page_alloc_end - (uint64_t)image_start) >> 12, 0);
    mark_range(new_cr3, (uint64_t)image_start, new_kdata_base + 4096);
    mark_range(new_cr3, IDT0, IDT0 + 16 * PERCPU_OFFSET);
    uint64_t e820_page = alloc_page();
    struct e820_map* e820_for_linux_start = (struct e820_map*)(DMEM + e820_page);
    struct e820_map* e820_for_linux_end = e820_for_linux_start + 4096 / sizeof(*e820_for_linux_start);
    struct e820_map* e820_for_linux = e820_for_linux_start;
    uint64_t tmp = -1;
    root = mark_segment(root, 0, 1ull << 48, 0, 1, 0);
    root = mark_segment(root, 0, 1ull << 48, (1ull << 48) - 1, 1ull << 48, 0);
    root = mark_segment(root, 0, 1ull << 48, 1 << 20, 1ull << 48, 0);
    //test_memory(root, 0, 1ull << 48);
    emit_e820(root, 0, 1ull << 48, &tmp, &e820_for_linux, e820_for_linux_end);
    int linux_memory_available = 0;
    for(struct e820_map* i = e820_for_linux_start; i < e820_for_linux; i++)
        if(i->start <= linux_phys_start && i->start + i->size >= linux_phys_end)
            linux_memory_available = 1;
    if(!linux_memory_available)
    {
        putstr("memory ranges required by Linux (0x");
        puthex(linux_phys_start);
        putstr("-0x");
        puthex(linux_phys_end);
        putstr(") are not available!");
        for(struct e820_map* i = e820_for_linux_start; i < e820_for_linux; i++)
        {
            putchar('\r');
            putchar('\n');
            puthex(i->start);
            putchar('-');
            puthex(i->start + i->size);
            putchar(' ');
            putint(i->kind);
        }
        die("");
    }
    for(struct e820_map* i = e820_start; i < e820_end && e820_for_linux < e820_for_linux_end; i++)
        if(i->kind != KIND_FREE)
            *e820_for_linux++ = *i;
    e820_for_linux_end = e820_for_linux;
    set_e820_map_for_linux(e820_for_linux_start, e820_for_linux_end);
    putstr("done\r\n");
    uint64_t new_user_cr3 = init_userspace_cr3(new_cr3);
    asm volatile("":::"memory");
    putstr("Relocating to 0x");
    puthex(image_addr);
    putstr("... ");
    memcpy((void*)image_addr, image_start, (uint64_t)image_end - (uint64_t)image_start);
    putstr("done\r\n");
    asm volatile("":::"memory");
    __atomic_store_n((uint64_t*)((uint64_t)&initial_user_cr3 + image_addr - (uint64_t)image_start), new_user_cr3, __ATOMIC_SEQ_CST);
    __atomic_store_n((uint64_t*)((uint64_t)&initial_cr3 + image_addr - (uint64_t)image_start), new_cr3, __ATOMIC_SEQ_CST);
    __atomic_store_n(&initial_user_cr3, new_user_cr3, __ATOMIC_SEQ_CST);
    __atomic_store_n(&initial_cr3, new_cr3, __ATOMIC_SEQ_CST);
}

void set_cs_ss(uint64_t, uint64_t);

volatile uint32_t* apic;

void relocate_percpu(uint64_t cr3, uint64_t rsp)
{
    uint32_t eax, edx;
    eax = 11;
    asm volatile("cpuid":"=a"(eax),"=d"(edx):"a"(eax):"ecx","ebx");
    uint32_t apic_id = edx;
    struct guest_state* gs = REMOTE_GUEST_STATE(apic_id);
    //here we redefine GUEST_STATE to our local variable, so that GDT/IDT/etc. macros work before we have set gsbase
#undef GUEST_STATE
#define GUEST_STATE (*gs)
    GUEST_STATE.apic_id = apic_id;
    uint64_t* gdt = (uint64_t*)GDT;
    gdt[0xfff8/8] = 0x00af9a000000ffff; //kernel cs
    gdt[0xfff3/8] = 0x00affa000000ffff; //user cs
    gdt[0xffeb/8] = 0x00cff2000000ffff; //user ss
    gdt[0xffe0/8] = gdt[3]; //tss upper part
    gdt[0xffd8/8] = gdt[2]; //tss lower part
    gdt[0xffd0/8] = 0;
    gdt[0xffc8/8] = 0x0000820000000000;
    //idt: int1, int14, int179 & int180 are "add rsp, 0xe8; iretq" with different ist stacks
    uint8_t idt_entry[16] = {[2] = 0xf8, [3] = 0xff, [4] = 1, [5] = 0xee};
    uint64_t ptr = GADGET(swapgs_add_rsp_iret);
    memcpy(idt_entry, (uint8_t*)&ptr, 2);
    memcpy(idt_entry+6, (uint8_t*)&ptr + 2, 6);
    memcpy((char*)IDT + 16, idt_entry, 16);
    idt_entry[4] = 2;
    memcpy((char*)IDT + 16 * 179, idt_entry, 16);
    idt_entry[4] = 3;
    memcpy((char*)IDT + 16 * 180, idt_entry, 16);
    idt_entry[4] = 4;
    memcpy((char*)IDT + 16 * 14, idt_entry, 16);
    //setup fake iret frames for the aforementioned interrupts. should be self-explanatory
    uint64_t* frame = (uint64_t*)IST_RETURN_FRAME(IST_SLOT_INT179);
    frame[0] = 0;
    frame[1] = 0x20;
    frame[2] = 0x102;
    frame[3] = IST_ENTRY(20);
    frame[4] = 0;
    frame = (uint64_t*)IST_RETURN_FRAME(IST_SLOT_INT180);
    frame[0] = GADGET(justreturn_pop);
    frame[1] = 0xfff8;
    frame[2] = 2;
    frame[3] = JUSTRETURN_POP_FRAME + KERNEL_OFFSET;
    frame[4] = 0;
    frame = (uint64_t*)JUSTRETURN_POP_FRAME;
    frame[0] = 0; //rdx
    frame[1] = 0; //rcx
    frame[2] = 0; //rax
    frame[3] = 0; //rip
    frame[4] = 0; //cs
    frame[5] = 0; //eflags
    frame[6] = 0; //rsp
    frame[7] = 0; //ss
    frame = (uint64_t*)IST_RETURN_FRAME(IST_SLOT_INT1);
    frame[0] = GADGET(doreti_iret);
    frame[1] = 0x20;
    frame[2] = 2;
    frame[3] = IST_SAVED_FRAME(IST_SLOT_INT179) + KERNEL_OFFSET;
    frame[4] = 0;
    frame = (uint64_t*)IST_RETURN_FRAME_ERRC(IST_SLOT_PAGEFAULT);
    frame[0] = (uint64_t)page_fault_handler;
    frame[1] = 0xfff3;
    frame[2] = 0x3002;
    frame[3] = rsp;
    frame[4] = 0xffeb;
    frame = (uint64_t*)IST_RETURN_FRAME(IST_SLOT_INT1_GUEST);
    frame[0] = (uint64_t)debug_handler;
    frame[1] = 0xfff3;
    frame[2] = 0x3002;
    frame[3] = rsp;
    frame[4] = 0xffeb;
    *(uint64_t*)rsp = 0;
    *(uint64_t*)(rsp + 8) = apic_id * PERCPU_OFFSET;
    //write the ists to the tss
    uint64_t* ists = (uint64_t*)(TSS + 0x24);
    ists[0] = IST_ENTRY(IST_SLOT_INT1);
    ists[1] = IST_ENTRY(IST_SLOT_INT179);
    ists[2] = IST_ENTRY(IST_SLOT_INT180);
    ists[3] = IST_ENTRY(IST_SLOT_PAGEFAULT);
    ists[4] = IST_ENTRY(IST_SLOT_LANDING);
    ists[5] = IST_ENTRY(IST_SLOT_INT1_GUEST);
    //relocate gdt to our own address. have to copy gdtr to the ist page to avoid triggering smap
    uint8_t gdtr[10] = {0xff, 0xff};
    uint64_t gdtp = GDT + KERNEL_OFFSET;
    void* scratch = (void*)IST_SAVED_FRAME(IST_SLOT_SCRATCH);
    memcpy(gdtr+2, &gdtp, 8);
    memcpy(scratch, gdtr, 10);
    frame = (uint64_t*)IST_RETURN_FRAME(IST_SLOT_INT179);
    frame[0] = GADGET(lgdt_rdi);
    asm volatile("int $179"::"D"((uint64_t)scratch + KERNEL_OFFSET):"memory");
    set_cs_ss(0xfff3, 0xffeb);
    //same for idt
    uint8_t idtr[10] = {0xff, 0xff};
    uint64_t idtp = IDT + KERNEL_OFFSET;
    memcpy(idtr+2, &idtp, 8);
    memcpy(scratch, idtr, 10);
    frame[0] = GADGET(lidt_lldt);
    asm volatile("int $179"::"D"((uint64_t)scratch + KERNEL_OFFSET - pcb_idt):"memory");
    //now that we are on our own segments, we can wipe out the leftover entries from the bsd kernel
    memset(gdt, 0, 0xffd8);
    frame[1] = ((uint64_t*)IST_RETURN_FRAME(IST_SLOT_INT1))[1] = 0xfff8;
    frame[0] = GADGET(ltr_ax);
    asm volatile("int $179"::"a"(0xffd8):"memory");
    //idt: all entries except the above lead to the landing page, which is intentionally unmapped
    //we then parse the page fault's iret frame to determine which exception happened
    idt_entry[4] = 5;
    ptr = LANDING_PAGE + KERNEL_OFFSET;
    memcpy(idt_entry, (uint8_t*)&ptr, 2);
    memcpy(idt_entry+6, (uint8_t*)&ptr + 2, 6);
    for(size_t i = 0; i < 256; i++)
        if(i != 1 && i != 14 && i != 179 && i != 180)
        {
            idt_entry[0] = i;
            memcpy((char*)IDT + 16 * i, idt_entry, 16);
        }
    //syscall: set the handler to also land on the landing page
    //we don't really care about segment registers, descriptors are loaded with fixed values anyway
    frame[0] = GADGET(wrmsr_ret);
    asm volatile("int $179"::"c"(0xc0000082),"a"(LANDING_PAGE + KERNEL_OFFSET + 256),"d"((LANDING_PAGE + KERNEL_OFFSET + 256) >> 32));
    asm volatile("int $179"::"c"(0xc0000083),"a"(LANDING_PAGE + KERNEL_OFFSET + 257),"d"((LANDING_PAGE + KERNEL_OFFSET + 257) >> 32));
    asm volatile("int $179"::"c"(0xc0000084),"a"(0xfffffffd),"d"(0xffffffff));
    uint64_t gs_base = (uint64_t)REMOTE_GUEST_STATE(apic_id) - 8;
    asm volatile("int $179"::"c"(0xc0000102),"a"(gs_base),"d"(gs_base >> 32));
    //enable the APIC, if not done already
    frame[0] = GADGET(rdmsr_start);
    asm volatile("int $179":"=a"(eax),"=d"(edx):"c"(0x1b));
    apic = (volatile uint32_t*)(DMEM_UC + (((uint64_t)edx << 32) | (eax & -4096)));
    /*apic[0xe0/4] = -1;
    apic[0xd0/4] = (apic[0xd0/4] & 0xffffff) | 1;
    apic[0x320/4] = 0x10000;
    apic[0x340/4] = 0x10000;
    apic[0x350/4] = 0x10000;
    apic[0x360/4] = 0x10000;*/
    if(!(eax & 0x800))
    {
        eax |= 0x800;
        frame[0] = GADGET(wrmsr_ret);
        asm volatile("int $179"::"a"(eax),"c"(0x1b),"d"(edx));
    }
    /*apic[0x80/4] = 0;
    apic[0xf0/4] = 240;*/
    apic[0xf0/4] |= 0x100;
    apic[0xb0/4] = 0;
    //initialize GUEST_STATE
    memset(&GUEST_STATE, 0, sizeof(GUEST_STATE));
    GUEST_STATE.ia32_pat = 0x1050600070406;
    GUEST_STATE.trap_table = (uint64_t*)(DMEM + alloc_page());
    GUEST_STATE.apic_id = apic_id;
    init_userspace_ist();
    GUEST_STATE.vcpu_info = (struct vcpu_info*)(shared_page + 8 * apic_id);
    GUEST_STATE.pending_event = -1;
    GUEST_STATE.cr3 = initial_cr3;
    GUEST_STATE.user_cr3 = initial_user_cr3;
    uint64_t pml = initial_cr3;
    for(size_t i = 39; i > 12; i -= 9)
    {
        size_t idx = ((GDT+KERNEL_OFFSET) >> i) & 511;
        pml = *(uint64_t*)(DMEM + pml + 8 * idx);
        pml &= (1ull << 52) - (1ull << 12);
    }
    GUEST_STATE.pml1t_for_gdt = (uint64_t*)(DMEM + pml + 8 * (((GDT+KERNEL_OFFSET) >> 12) & 511));
    //we want to clear the leftover mappings from the bsd kernel
    //but to do that, we need to ensure that every core already got past the relocation
    static size_t counter;
    __atomic_fetch_add(&counter, 1, __ATOMIC_SEQ_CST);
    while(__atomic_load_n(&counter, __ATOMIC_SEQ_CST) != 16);
    //now clear the mappings
    memset(DMEM+cr3, 0, 2048);
    memset(DMEM+cr3+2048+64, 0, 2048-64);
    //reload cr3 to invalidate tlb
    frame[0] = GADGET(mov_cr3_rax_mov_ds);
    asm volatile("int $179"::"a"(cr3));
    //idt: set int1's ist to 6, so that we can catch "legitimate" int1's from the kernel
    *(char*)(IDT + 20) = 6;
    //now boot!
    if(apic_id == 0)
    {
        smp_start_cpu(0);
        boot_linux();
    }
    else
        smp_waitloop(apic_id);
}
