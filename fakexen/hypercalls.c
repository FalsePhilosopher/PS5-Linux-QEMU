#include "hypercalls.h"
#include "memmap.h"
#include "gadgets.h"
#include "gdb_stub.h"
#include "uart.h"
#include "string.h"
#include "timer.h"
#include "utils.h"
#include "smp.h"
#include "page_alloc.h"
#include "apic.h"
#include "userspace.h"
#include "pci.h"
#include "vcpu_info.h"
#include "tsc.h"

static void die(const char* str)
{
    putstr(str);
    putchar('\r');
    putchar('\n');
    asm volatile("hlt");
}

static void send_ipi(int target, uint8_t vector)
{
    while((apic[192] & 4096));
    apic[196] = (uint32_t)target << 24;
    apic[192] = 0x4000 | vector;
}

extern char mov_cr3_rax_mov_ds[];
extern char mov_rax_cr0[];
extern char mov_cr0_rax[];

static struct e820_map* map_start;
static struct e820_map* map_end;

void set_e820_map_for_linux(struct e820_map* s, struct e820_map* e)
{
    map_start = s;
    map_end = e;
}

void get_e820_map_for_linux(struct e820_map** s, struct e820_map** e)
{
    *s = map_start;
    *e = map_end;
}

static HYPERCALL uint32_t hypercall_xen_version(int which, void* param)
{
    if(which == 6) //XENVER_get_features
    {
        uint32_t* p = param;
        p[1] = p[0] ? 0 : 162;
        return 0;
    }
    else if(which == 0) //XENVER_version
        return 0;
    else if(which == 1) //XENVER_extraversion
    {
        static const char version[16] = "-ps5-fakexen";
        memcpy(param, version, 16);
        return 0;
    }
    else
        die("hypercall_xen_version: unknown which");
}

struct xen_memory_map
{
    uint32_t n_entries;
    struct e820_map* buffer;
};

struct xen_machphys_mapping
{
    uint64_t v_start;
    uint64_t v_end;
    uint64_t max_mfn;
};

static HYPERCALL uint64_t hypercall_memory_op(int which, void* param)
{
    if(which == 12) //XENMEM_machphys_mapping
    {
        //we're always using identity mapping, so the m2p and p2m tables are the same and we can alias them together
        struct xen_machphys_mapping* p = param;
        p->v_start = PFN_TO_MFN_START;
        p->v_end = PFN_TO_MFN_END;
        p->max_mfn = (p->v_end - p->v_start) / 8 - 1;
        return 0;
    }
    else if(which == 9 /* XENMEM_memory_map */ || which == 10 /* XENMEM_machine_memory_map */)
    {
        struct xen_memory_map* xmm = param;
        uint32_t n = xmm->n_entries;
        if(map_end - map_start < n)
            n = map_end - map_start;
        memcpy(xmm->buffer, map_start, n * sizeof(*map_start));
        memset(xmm->buffer + n * sizeof(*map_start), 0, (xmm->n_entries - n) * sizeof(*map_start));
        xmm->n_entries = n;
        return 0;
    }
    else if(which == 4) //XENMEM_maximum_reservation
        return -1;
    else if(which == 1) //XENMEM_decrease_reservation
        return 0; //this causes a WARN (which the kernel can't even handle at this point)...
    else if(which == 11) //XENMEM_exchange
        return -1; //stub, always error out
    else
        die("hypercall_memory_op: unknown which");
}

uint64_t fix_pte(uint64_t pte)
{
    if(!(pte & 1))
        return pte;
    pte |= 4;
    pte &= -257; //XXX: may hurt performance
    if((pte & (1ull << 58))) //"saved dirty" bit in linux, but xom bit on the ps5
    {
        pte &= ~(1ull << 58);
        pte |= 64; //replace with a real dirty bit
    }
    return pte;
}

static void do_update_va_mapping(uint64_t cr3, uint64_t va, uint64_t pte)
{
    for(int i = 39; i >= 21; i -= 9)
    {
        uint64_t entry = *(uint64_t*)(DMEM + cr3 + 8 * ((va >> i) & 511));
        if(!(entry & 1))
        {
            if(pte == 0) //updating a nonexistent page to nothing is fine
                return;
            die("hypercall_update_va_mapping: requested to update a nonexistent page");
            return;
        }
        if((entry & 128))
        {
            die("hypercall_update_va_mapping: requested to update a hugepage");
            return;
        }
        cr3 = entry & ((1ull << 52) - (1ull << 12));
    }
    *(uint64_t*)(DMEM + cr3 + 8 * ((va >> 12) & 511)) = fix_pte(pte);
}

static HYPERCALL int hypercall_update_va_mapping(uint64_t va, uint64_t pte, int flags)
{
    if(va >= RESERVED_AREA_START && va < RESERVED_AREA_END)
        die("hypercall_update_va_mapping: attempt to update reserved address");
    do_update_va_mapping(GUEST_STATE.cr3, va, pte);
    if(flags == 1 || flags == 2 || flags == 5)
    {
        if(flags == 5)
            putstr("hypercall_update_va_mapping: TODO: flags == 5\r\n");
        int g = enable_gadgets();
        SET_GADGET(mov_cr3_rax_mov_ds);
        asm volatile("int $179"::"a"(GUEST_STATE.cr3));
        disable_gadgets(g);
    }
    else if(flags != 0)
        die("hypercall_update_va_mapping: non-zero flags passed");
    return 0;
}

HYPERCALL int hypercall_set_gdt(uint64_t* mfn, uint64_t size)
{
    if(size > 512)
        die("TODO: gdt > page size");
    do_update_va_mapping(GUEST_STATE.cr3, GDT, (mfn[0] << 12) | 7);
    do_update_va_mapping(GUEST_STATE.cr3, GDT+KERNEL_OFFSET, (mfn[0] << 12) | 3);
    do_update_va_mapping(GUEST_STATE.user_cr3, GDT+KERNEL_OFFSET, (mfn[0] << 12) | 3);
    int g = enable_gadgets();
    SET_GADGET(mov_cr3_rax_mov_ds);
    asm volatile("int $179"::"a"(GUEST_STATE.cr3));
    disable_gadgets(g);
    uint64_t* gdt = (uint64_t*)GDT;
    for(size_t i = 0; i < size; i++)
        if((gdt[i] & (1ull << 47)))
            gdt[i] |= 3ull << 45;
    return 0;
}

static HYPERCALL int hypercall_set_segment_base(uint64_t which, uint64_t value)
{
    if(which == 0) //SEGBASE_FS
        wrmsr(0xc0000100, value);
    else if(which == 1) //SEGBASE_GS_USER
        GUEST_STATE.kgsbase = value;
    else if(which == 2) //SEGBASE_GS_KERNEL
    {
        GUEST_STATE.gsbase = value;
        wrmsr(0xc0000101, value);
    }
    else if(which == 3) //SEGBASE_GS_USER_SEL
    {
        uint64_t kgsbase = rdmsr(0xc0000102);
        int g = enable_gadgets();
        SET_GADGET(wrmsr_ret);
        asm volatile("mov %0, %%gs"::"a"((uint16_t)value));
        asm volatile("int $179"::"c"(0xc0000102),"a"(kgsbase),"d"(kgsbase>>32));
        disable_gadgets(g);
    }
    else
        die("hypercall_set_segment_base: unknown segment");
    return 0;
}

static HYPERCALL int hypercall_set_trap_table(const struct trap_info* traps)
{
    if(!traps)
    {
        memset(GUEST_STATE.trap_table, 0, 256 * sizeof(*GUEST_STATE.trap_table));
        return 0;
    }
    while(traps->cs)
    {
        GUEST_STATE.trap_table[traps->vector] = traps->address;
        traps++;
    }
    return 0;
}

static HYPERCALL int hypercall_console_io(int cmd, size_t len, char* str)
{
    if(cmd == 0) //CONSOLEIO_write
    {
        if(gdb_stub_active())
        {
            uint64_t args[3] = {1, (uint64_t)str, len};
            gdb_stub_syscall("write", 3, args);
        }
        else
        {
            for(size_t i = 0; i < len; i++)
                putchar(str[i]);
        }
        return 0;
    }
    else if(cmd == 1) //CONSOLEIO_read
    {
        if(gdb_stub_active())
            return 0;
        else
        {
            for(size_t i = 0; i < len; i++)
            {
                int q = getchar_nonblocking();
                if(q < 0)
                    return i;
                str[i] = q;
            }
            return len;
        }
    }
    die("console_io: unsupported cmd");
}

struct mmuext_op
{
    uint32_t cmd;
    uint64_t phys;
    uint64_t virt;
};

static void pin_table(uint64_t table, int level)
{
    uint64_t* pml = (uint64_t*)(DMEM + table);
    for(size_t i = 0; i < 512; i++)
    {
        if(level == 3 && (i >= 256 && i < 264))
            continue;
        uint64_t q = pml[i];
        if((q & 1))
        {
            pml[i] = q | 4;
            if(level && !(q & 128))
                pin_table(q & ((1ull << 52) - (1ull << 12)), level - 1);
        }
    }
}

static HYPERCALL int hypercall_mmuext_op(struct mmuext_op* ops, uint32_t count, uint32_t* pdone, uint32_t foreigndom)
{
    if(foreigndom != 0x7ff0) //DOMID_SELF
        die("hypercall_mmuext_op: foreign domain requested");
    if(pdone)
        die("hypercall_mmuext_op: TODO: wtf is pdone??");
    for(uint32_t i = 0; i < count; i++)
    {
        if(ops[i].cmd < 4) //we trust the kernel, thus do not care about pinning
            //except we do. we need to walk through this pagetable and set the user bit on every pte
            pin_table(ops[i].phys << 12, ops[i].cmd);
        else if(ops[i].cmd == 4) //MMUEXT_UNPIN_TABLE
            //and here we *actually* don't care
            continue;
        else if(ops[i].cmd == 5) //MMUEXT_NEW_BASEPTR
        {
            uint64_t cr3 = initial_cr3;
            uint64_t new_cr3 = ops[i].phys << 12;
            /*memcpy(DMEM + cr3, DMEM + new_cr3, 2048);
            memcpy(DMEM + cr3 + 2048 + 64, DMEM + new_cr3 + 2048 + 64, 2048 - 64);*/
            memcpy(DMEM + new_cr3 + 2048, DMEM + cr3 + 2048, 64);
            int g = enable_gadgets();
            SET_GADGET(mov_cr3_rax_mov_ds);
            asm volatile("int $179"::"a"(new_cr3));
            disable_gadgets(g);
            GUEST_STATE.cr3 = new_cr3;
        }
        else if(ops[i].cmd == 6 /*MMUEXT_TLB_FLUSH_LOCAL*/ || ops[i].cmd == 7 /*MMUEXT_INVLPD_LOCAL*/)
        {
            int g = enable_gadgets();
            SET_GADGET(mov_cr3_rax_mov_ds);
            asm volatile("int $179"::"a"(GUEST_STATE.cr3));
            disable_gadgets(g);
        }
        else if(ops[i].cmd == 15) //MMUEXT_NEW_USER_BASEPTR
        {
            uint64_t cr3 = initial_user_cr3;
            uint64_t new_cr3 = ops[i].phys << 12;
            /*memcpy(DMEM + cr3, DMEM+new_cr3, 2048);
            memcpy(DMEM + cr3 + 2048 + 64, DMEM + new_cr3 + 2048 + 64, 2048 - 64);*/
            memcpy(DMEM + new_cr3 + 2048, DMEM + cr3 + 2048, 64);
            GUEST_STATE.user_cr3 = new_cr3;
        }
        else if(ops[i].cmd == 13) //MMUEXT_SET_LDT
            putstr("MMUEXT_SET_LDT: TODO: stub\r\n");
        else if(ops[i].cmd == 8 /*MMUEXT_TLB_FLUSH_MULTI*/ || ops[i].cmd == 9 /*MMUEXT_INVLPG_MULTI*/)
        {
            static uint64_t counter = 0;
            __atomic_fetch_add(&counter, 1, __ATOMIC_RELAXED);
            putstr("CPU #");
            putint(GUEST_STATE.apic_id);
            putstr(" entered shootdown, mask = 0x");
            uint16_t mask = *(uint16_t*)ops[i].virt;
            puthex(mask);
            putchar('\r');
            putchar('\n');
            //die("hui vam");
            for(int i = 0; i < 16; i++)
                if(i != GUEST_STATE.apic_id && (mask & (1 << i)))
                {
                    __atomic_fetch_add(&REMOTE_GUEST_STATE(i)->n_flushes, 1, __ATOMIC_RELAXED);
                    send_ipi(i, 0x92);
                }
            int g = enable_gadgets();
            SET_GADGET(mov_cr3_rax_mov_ds);
            uint64_t* own_flushes = &REMOTE_GUEST_STATE(GUEST_STATE.apic_id)->n_flushes;
            for(int i = 0; i < 16; i++)
                if(i != GUEST_STATE.apic_id && (mask & (1 << i)))
                {
                    struct guest_state* gs = REMOTE_GUEST_STATE(i);
                    while(__atomic_load_n(&REMOTE_GUEST_STATE(i)->n_flushes, __ATOMIC_RELAXED))
                    {
                        if(__atomic_exchange_n(own_flushes, 0, __ATOMIC_RELAXED))
                            asm volatile("int $179"::"a"(GUEST_STATE.cr3));
                    }
                }
            if((mask & (1 << GUEST_STATE.apic_id)))
                asm volatile("int $179"::"a"(GUEST_STATE.cr3));
            disable_gadgets(g);
            putstr("CPU #");
            putint(GUEST_STATE.apic_id);
            putstr(" exited shootdown (");
            putint(__atomic_sub_fetch(&counter, 1, __ATOMIC_RELAXED));
            putstr(")\r\n");
        }
        else
            die("hypercall_mmuext_op: unknown cmd");
    }
    return 0;
}

struct apic_op
{
    uint64_t base;
    uint32_t reg;
    uint32_t value;
};

struct physdev_map_pirq
{
    uint16_t domid;
    int type;
    int index;
    int pirq;
    int bus;
    int devfn;
    int entry_nr;
    uint64_t table_base;
};

volatile uint32_t* pci_find_capability(int bus, int dev, int fn, int which)
{
    uint64_t base_addr = pci_cfg_bases[(uint8_t)bus] + ((uint64_t)(dev & 31) << 15) + ((uint64_t)(fn & 7) << 12);
    volatile uint32_t* device = (volatile uint32_t*)(DMEM_UC + base_addr);
    if((uint16_t)device[0] == 0xffff)
        return 0;
    if(!(device[1] & 0x100000))
        return 0;
    size_t cap_offset = (uint8_t)device[13];
    while(cap_offset)
    {
        volatile uint32_t* cap = (volatile uint32_t*)(DMEM_UC + base_addr + cap_offset);
        uint32_t id = cap[0];
        if((uint8_t)id == which)
            return cap;
        cap_offset = (uint8_t)(id >> 8);
    }
    return 0;
}

static int allocate_pirq(void)
{
    static int pirq = 0x21;
    int ans = __atomic_load_n(&pirq, __ATOMIC_RELAXED);
    for(;;)
    {
        int remainder = ans+1;
        if(remainder >= 0x50)
            remainder = 0x21;
        if(__atomic_compare_exchange_n(&pirq, &ans, remainder, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            return ans;
    }
}

struct physdev_irq_status_query
{
    uint32_t irq;
    uint32_t flags;
};

uint64_t irqs_enabled[4];

static HYPERCALL int hypercall_physdev_op(int cmd, void* arg)
{
    if(cmd == 6) //PHYSDEVOP_set_iopl
        return 0; //XXX: stub
    else if(cmd == 8) //PHYSDEVOP_apic_read
    {
        struct apic_op* op = arg;
        *(volatile uint32_t*)(DMEM_UC + op->base) = op->reg;
        op->value = *(volatile uint32_t*)(DMEM_UC + op->base + 16);
        return 0;
    }
    else if(cmd == 10 || cmd == 28)
    {
        putstr("hypercall_physdev_op: TODO: irq-related hypercalls (cmd = ");
        putint(cmd);
        putstr(")\r\n");
        return 0;
    }
    else if(cmd == 13) //PHYSDEVOP_map_pirq
    {
        struct physdev_map_pirq* pirq = arg;
        int vec = pirq->pirq;
        if(pirq->type != 3) //MAP_PIRQ_TYPE_MSI_SEG
        {
            putstr("PHYSDEVOP_map_pirq: TODO: unknown type\r\n");
            return 0;
        }
        volatile uint32_t* cap_msi = pci_find_capability(pirq->bus, pirq->devfn/8, pirq->devfn%8, 5);
        volatile uint32_t* cap_msix = pci_find_capability(pirq->bus, pirq->devfn/8, pirq->devfn%8, 17);
        if(cap_msix)
            cap_msix[0] &= 0x7fffffff;
        if(!cap_msi)
        {
            putstr("PHYSDEVOP_map_pirq: warning: PCI device does not support MSI\r\n");
            return -1;
        }
        uint64_t old_addr;
        uint16_t old_data;
        if((cap_msi[0] & (1 << 23)))
        {
            old_addr = (uint64_t)cap_msi[2] << 32 | cap_msi[1];
            old_data = cap_msi[3];
        }
        else
        {
            old_data = cap_msi[1];
            old_data = cap_msi[2];
        }
        if(vec < 0 && (old_addr == 0xfee00000 && old_data >= 32 && old_data < 256))
            vec = old_data;
        if(vec < 0)
            vec = allocate_pirq(); //will loop after a few dozen attempts, let's hope this does not happen
        cap_msi[0] |= 0x800000; //64-bit
        cap_msi[1] = 0xfee00000;
        cap_msi[2] = 0;
        cap_msi[3] = vec;
        cap_msi[0] |= 0x10000; //enable
        putstr("PHYSDEVOP_map_pirq: using IRQ #");
        putint(vec);
        putstr(" for device ");
        puthex(pirq->bus);
        putchar(':');
        puthex(pirq->devfn/8);
        putchar(':');
        puthex(pirq->devfn%8);
        putchar('\r');
        putchar('\n');
        pirq->pirq = vec;
        return 0;
    }
    else if(cmd == 5)
    {
        struct physdev_irq_status_query* irq = arg;
        irq->flags = 2;
        return 0;
    }
    else if(cmd == 24 || cmd == 25) //pci-related calls
        //these seem to be purely informational callbacks to xen, probably safe to ignore
        return 0;
    die("hypercall_physdev_op: unknown cmd");
}

struct vcpu_register_vcpu_info
{
    uint64_t mfn;
    uint32_t offset;
};

static HYPERCALL int hypercall_vcpu_op(int cmd, int cpu, void* arg)
{
    if(cmd == 5) //VCPUOP_register_runstate_memory_area
    {
        putstr("VCPUOP_register_runstate_memory_area: TODO: stub\r\n");
        return 0;
    }
    else if(cmd == 3) //VCPUOP_is_up
        return (uint32_t)cpu < 16 ? smp_is_cpu_up(cpu) : -1;
    else if(cmd == 10) //VCPUOP_register_vcpu_info
    {
        struct vcpu_register_vcpu_info* p = arg;
        uint64_t vcpu_info = (uint64_t)DMEM + 4096 * p->mfn + p->offset;
        struct guest_state* gs = REMOTE_GUEST_STATE(cpu);
        memcpy((void*)vcpu_info, gs->vcpu_info, sizeof(struct vcpu_info));
        gs->vcpu_info = (void*)vcpu_info;
        return 0;
    }
    else if(cmd == 7) //VCPUOP_stop_periodic_timer
    {
        if(cpu != GUEST_STATE.apic_id)
            die("VCPUOP_stop_periodic_timer: remote cpu\r\n");
        stop_periodic_timer();
        return 0;
    }
    else if(cmd == 9) //VCPUOP_stop_singleshot_timer
    {
        putstr("VCPUOP_stop_singleshot_timer: TODO: stub\r\n");
        return 0;
    }
    else if(cmd == 8) //VCPUOP_set_singleshot_timer
    {
        if(cpu != GUEST_STATE.apic_id)
            die("VCPUOP_set_singleshot_timer: remote cpu\r\n");
        schedule_singleshot_timer(*(uint64_t*)arg - system_time(rdtsc()));
        return 0;
    }
    else if(cmd == 0) //VCPUOP_initialise
    {
        _Static_assert(sizeof(struct vcpu_guest_context) <= VCPU_GUEST_CONTEXT_END - VCPU_GUEST_CONTEXT_START);
        for(uint64_t i = VCPU_GUEST_CONTEXT_START0; i < VCPU_GUEST_CONTEXT_START + sizeof(struct vcpu_guest_context); i += 4096)
        {
            uint64_t page = alloc_page();
            map_page(initial_cr3, i + cpu * PERCPU_OFFSET, page, 7);
            size_t chk = VCPU_GUEST_CONTEXT_START + sizeof(struct vcpu_guest_context) - i;
            if(chk > 4096)
                chk = 4096;
            memcpy(DMEM+page, (char*)arg + i - VCPU_GUEST_CONTEXT_START, chk);
        }
        return 0;
    }
    else if(cmd == 1) //VCPUOP_up
    {
        smp_start_cpu(cpu);
        return 0;
    }
    else if(cmd == 11) //VCPUOP_send_nmi
    {
        //we can't really use real nmis because of the nasty iret behavior
        //so just sent int 0x91 instead
        send_ipi(cpu, 0x91);
        return 0;
    }
    die("hypercall_vcpu_op: unsupported cmd");
}

struct mmu_update
{
    uint64_t ptr;
    uint64_t val;
};

static HYPERCALL int hypercall_mmu_update(struct mmu_update* ureqs, uint32_t count, uint32_t* pdone, uint32_t foreigndom)
{
    if(foreigndom != 0x7ff0) //DOMID_SELF
    {
        die("hypercall_mmu_update: foreign domain requested");
        return -1;
    }
    if(pdone)
    {
        die("hypercall_mmu_update: TODO: wtf is pdone??");
        return -1;
    }
    for(size_t i = 0; i < count; i++)
    {
        uint64_t val = fix_pte(ureqs[i].val);
        if((ureqs[i].ptr & 7) == 2)
            //this should be done *atomically*, but how do we do that if we possibly have to update an arbitrary number of unrelated pagetables at once? stop-the-world?
            val = (val & -97) | (*(uint64_t*)(DMEM + ureqs[i].ptr) & 96);
        else if((ureqs[i].ptr & 7))
        {
            die("hypercall_mmu_update: unsupported operation mode");
            return -1;
        }
        uint64_t ptr = ureqs[i].ptr & -8;
        *(uint64_t*)(DMEM + ptr) = val;
    }
    //XXX: always flush the local TLB on MMU update
    int g = enable_gadgets();
    SET_GADGET(mov_cr3_rax_mov_ds);
    asm volatile("int $179"::"a"(GUEST_STATE.cr3));
    disable_gadgets(g);
    return 0;
}

static HYPERCALL int hypercall_vm_assist(uint32_t cmd, uint32_t type)
{
    if(cmd == 0) // VMASSIST_CMD_enable
    {
        if(type == 2) //VMASST_TYPE_writable_pagetables
            return 0; //stub, but who fucking cares?
        else if(type == 5) //VMASST_TYPE_runstate_update_flag
        {
            putstr("VMASST_TYPE_runstate_update_flag: TODO: stub\r\n");
            return 0;
        }
        die("VMASSIST_CMD_enable: unknown type");
    }
    else
        die("hypercall_vm_assist: unknown cmd");
}

struct callback_register
{
    uint16_t type;
    uint16_t flags;
    uint64_t address;
};

static HYPERCALL int hypercall_callback_op(int cmd, struct callback_register* reg)
{
    if(cmd == 0) //CALLBACKOP_register
    {
        if(reg->type == 0) //CALLBACKTYPE_event
            GUEST_STATE.event_callback_eip = reg->address;
        else if(reg->type == 1) //CALLBACKTYPE_failsafe
            GUEST_STATE.failsafe_callback_eip = reg->address;
        else if(reg->type == 2) //CALLBACKTYPE_syscall
            GUEST_STATE.lstar = reg->address;
        else if(reg->type == 7) //CALLBACKTYPE_syscall32
            GUEST_STATE.cstar = reg->address;
        else
        {
            putstr("hypercall_callback_op: TODO: unknown callback #");
            putint(reg->type);
            putchar('\r');
            putchar('\n');
        }
        return 0;
    }
    die("hypercall_callback_op: unknown cmd");
}

struct xen_platform_op
{
    uint32_t cmd;
    uint32_t interface_version;
    union
    {
        struct
        {
            uint32_t xen_cpuid;
            uint32_t max_present;
            uint32_t flags;
            uint32_t apic_id;
            uint32_t acpi_id;
        };
    };
};

static HYPERCALL int hypercall_platform_op(struct xen_platform_op* op)
{
    if(op->cmd == 55) //XENPF_get_cpuinfo
    {
        op->max_present = 15;
        op->flags = 0;
        op->apic_id = op->acpi_id = op->xen_cpuid;
        return 0;
    }
    else if(op->cmd == 62) //TODO: what it even is???
        return 0;
    putstr("hypercall_platform_op: TODO: stub (cmd=");
    putint(op->cmd);
    putstr(", interface_version=0x");
    puthex(op->interface_version);
    putstr(")\r\n");
    return -1;
}

static HYPERCALL int hypercall_get_debugreg(int which)
{
    which %= 8;
    if(which >= 6)
        which -= 2;
    return GUEST_STATE.dbgregs[which];
}

struct multicall_entry
{
    uint64_t op;
    uint64_t result;
    uint64_t args[6];
};

typedef uint64_t(*hypercall_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
extern hypercall_t hypercalls[64];

static HYPERCALL int hypercall_multicall(struct multicall_entry* entries, uint32_t nr_calls)
{
    for(uint32_t i = 0; i < nr_calls; i++)
    {
        if(entries[i].op >= 64 || !hypercalls[entries[i].op])
            die("hypercall_multicall: unknown hypercall");
        entries[i].result = hypercalls[entries[i].op](entries[i].args[0], entries[i].args[1], entries[i].args[2], entries[i].args[3], entries[i].args[4], entries[i].args[5]);
    }
    return 0;
}

static HYPERCALL int hypercall_update_descriptor(uint64_t maddr, uint64_t value)
{
    *(uint64_t*)(DMEM + maddr) = value;
    return 0;
}

static HYPERCALL int hypercall_stack_switch(uint16_t ss, uint64_t rsp)
{
    if((ss & 7) || ss >= 0x1000)
        die("hypercall_stack_switch: invalid kernel selector");
    GUEST_STATE.ss0 = ss;
    GUEST_STATE.rsp0 = rsp;
    return 0;
}

static HYPERCALL int hypercall_set_debugreg(int which, uint64_t value)
{
    which %= 8;
    if(which >= 6)
        which -= 2;
    if(which < 4 && (value >= RESERVED_AREA_START && value < RESERVED_AREA_END))
        die("tried to set invalid debug register");
    GUEST_STATE.dbgregs[which] = value;
    return 0;
}

struct evtchn_bind_virq
{
    uint32_t virq;
    uint32_t vcpu;
    uint32_t port;
};

struct evtchn_bind_pirq
{
    uint32_t pirq;
    uint32_t flags;
    uint32_t port;
};

struct evtchn_bind_ipi
{
    uint32_t vcpu;
    uint32_t port;
};

struct evtchn_send
{
    uint32_t port;
};

struct evtchn_init_control
{
    uint64_t control_gfn;
    uint32_t offset;
    uint32_t vcpu;
    uint64_t link_bits;
};

struct evtchn_expand_array
{
    uint64_t array_gfn;
};

uint64_t event_array;

//event channel mapping:
// 32-255 pirq (1:1)
// 256-... per-cpu virqs ([virq][cpu])
// 512-... per-cpu ipis
static HYPERCALL int hypercall_event_channel_op(int cmd, void* arg)
{
    if(cmd == 11) //EVTCHNOP_init_control
    {
        struct evtchn_init_control* req = arg;
        REMOTE_GUEST_STATE(req->vcpu)->event_control_block = (req->control_gfn << 12) | req->offset;
        return 0;
    }
    else if(cmd == 12) //EVTCHNOP_expand_array
    {
        struct evtchn_expand_array* req = arg;
        if(event_array)
            die("EVTCHNOP_expand_array: more than one page is not supported\r\n");
        event_array = req->array_gfn << 12;
        return 0;
    }
    else if(cmd == 1) //EVTCHNOP_bind_virq
    {
        struct evtchn_bind_virq* req = arg;
        req->port = 256 + 16 * req->virq + req->vcpu;
        return 0;
    }
    else if(cmd == 13) //EVTCHNOP_set_priority
    {
        putstr("EVTCHNOP_set_priority: TODO: stub\r\n");
        return 0;
    }
    else if(cmd == 7) //EVTCHNOP_bind_ipi
    {
        struct evtchn_bind_ipi* req = arg;
        struct guest_state* gs = REMOTE_GUEST_STATE(req->vcpu);
        req->port = 512 + 16 * (gs->ipi_bind++) + req->vcpu;
        if(req->port >= 768)
            die("EVTCHNOP_bind_ipi: tried to allocate too many IPIs");
        return 0;
    }
    else if(cmd == 4) //EVTCHNOP_send
    {
        struct evtchn_send* req = arg;
        if(req->port >= 512)
        {
            send_ipi(req->port & 15, ((req->port >> 4) & 15) + 0x81);
        }
        else
        {
            putstr("fatal: vcpu #");
            putint(GUEST_STATE.apic_id);
            putstr(" tried to send to event channel #");
            putint(req->port);
            die(" which is not an IPI channel");
        }
        return 0;
    }
    else if(cmd == 6) //EVTCHNOP_alloc_unbound
    {
        putstr("EVTCHNOP_alloc_unbound: TODO: stub\r\n");
        ((uint32_t*)arg)[1] = 1;
        return 0;
    }
    else if(cmd == 8) //EVTCHNOP_bind_vcpu
    {
        putstr("EVTCHNOP_bind_vcpu: TODO: stub\r\n");
        return 0;
    }
    else if(cmd == 2) //EVTCHNOP_bind_pirq
    {
        struct evtchn_bind_pirq* req = arg;
        if(req->pirq < 32 || req->pirq >= 256)
            die("EVTCHNOP_bind_pirq: TODO: invalid IRQ requested");
        else
        {
            req->port = req->pirq;
            irqs_enabled[req->port / 64] |= 1ull << (req->port % 64);
        }
        return 0;
    }
    else if(cmd == 3 /*EVTCHNOP_close*/ || cmd == 9 /*EVTCHNOP_unmask*/)
        return 0; //no need to handle closes
    putstr("hypercall_event_channel_op: unknown cmd ");
    putint(cmd);
    die("");
}

static HYPERCALL int hypercall_fpu_taskswitch(int set)
{
    int g = enable_gadgets();
    SET_GADGET(mov_rax_cr0);
    uint64_t cr0;
    asm volatile("int $179":"=a"(cr0));
    if(set)
        cr0 |= 8;
    else
        cr0 &= -9;
    SET_GADGET(mov_cr0_rax);
    asm volatile("int $179"::"a"(cr0));
    disable_gadgets(g);
    return 0;
}

static HYPERCALL int hypercall_xenpmu_op(void)
{
    putstr("hypercall_xenpmu_op: TODO: stub\r\n");
    return -1;
}

static HYPERCALL int hypercall_sched_op(int cmd, int arg)
{
    if(cmd == 0) //SCHEDOP_yield
        return 0;
    else if(cmd == 1) //SCHEDOP_block
        //TODO: should actually call hlt somehow
        return 0;
    die("hypercall_sched_op: unknown cmd");
}

static HYPERCALL int hypercall_grant_table_op(int cmd, void* arg, int flags)
{
    if(cmd == 2) //GNTTABOP_setup_table
        return 0;
    putstr("hypercall_grant_table_op: TODO: stub\r\n");
    return -1;
}

hypercall_t hypercalls[64] = {
    [0] = (hypercall_t)hypercall_set_trap_table,
    [1] = (hypercall_t)hypercall_mmu_update,
    [2] = (hypercall_t)hypercall_set_gdt,
    [3] = (hypercall_t)hypercall_stack_switch,
    [5] = (hypercall_t)hypercall_fpu_taskswitch,
    [7] = (hypercall_t)hypercall_platform_op,
    [8] = (hypercall_t)hypercall_set_debugreg,
    [9] = (hypercall_t)hypercall_get_debugreg,
    [10] = (hypercall_t)hypercall_update_descriptor,
    [12] = (hypercall_t)hypercall_memory_op,
    [13] = (hypercall_t)hypercall_multicall,
    [14] = (hypercall_t)hypercall_update_va_mapping,
    [17] = (hypercall_t)hypercall_xen_version,
    [18] = (hypercall_t)hypercall_console_io,
    [20] = (hypercall_t)hypercall_grant_table_op,
    [21] = (hypercall_t)hypercall_vm_assist,
    [24] = (hypercall_t)hypercall_vcpu_op,
    [25] = (hypercall_t)hypercall_set_segment_base,
    [26] = (hypercall_t)hypercall_mmuext_op,
    [29] = (hypercall_t)hypercall_sched_op,
    [30] = (hypercall_t)hypercall_callback_op,
    [32] = (hypercall_t)hypercall_event_channel_op,
    [33] = (hypercall_t)hypercall_physdev_op,
    [40] = (hypercall_t)hypercall_xenpmu_op,
};

const uint32_t hlt_instr = 0xfeeb; //0xfdebf4;

void handle_hypercall_syscall(uint64_t* regs, uint64_t* iret_frame)
{
    uint32_t which = regs[0];
    if(which == 23) //__HYPERVISOR_iret
    {
        uint64_t* guest_iret_frame = (uint64_t*)iret_frame[3];
        regs[0] = guest_iret_frame[0];
        regs[11] = guest_iret_frame[1];
        regs[1] = guest_iret_frame[2];
        memcpy(iret_frame, guest_iret_frame+4, 40);
        if((iret_frame[2] & 512))
            GUEST_STATE.vcpu_info->evtchn_upcall_mask = 0;
        else
            GUEST_STATE.vcpu_info->evtchn_upcall_mask = 0xff;
        iret_frame[1] |= 3;
        if((guest_iret_frame[5] & 3))
        {
            iret_frame[2] |= 2;
            arrange_jump_to_userspace(regs, iret_frame);
            return;
        }
        iret_frame[4] |= 3;
        if(iret_frame[4] == 3)
            iret_frame[4] = 0xffeb;
        return;
    }
    if(which == 29 /* sched_op */ && (int)regs[7] == 1 /* SCHEDOP_block */)
    {
        regs[0] = 0;
        regs[2] = iret_frame[0];
        iret_frame[0] = (uint64_t)&hlt_instr;
        iret_frame[2] |= 512;
        GUEST_STATE.vcpu_info->evtchn_upcall_mask = 0;
        return;
    }
    if(which >= sizeof(hypercalls) / sizeof(*hypercalls) || !hypercalls[which])
        die("TODO: unknown hypercall");
    else
        regs[0] = hypercalls[which](regs[7], regs[6], regs[2], regs[10], regs[8], regs[9]);
}
