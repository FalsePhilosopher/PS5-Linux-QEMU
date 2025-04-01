#include "types.h"
#include "ist_page.h"
#include "die.h"
#include "hypercalls.h"
#include "gadgets.h"
#include "exceptions.h"
#include "utils.h"
#include "page_alloc.h"
#include "gdb_stub.h"
#include "string.h"
#include "apic.h"
#include "userspace.h"
#include "vcpu_info.h"
#include "tsc.h"

extern char mov_rax_cr0[];
extern char mov_rdi_cr2[];
extern char mov_cr3_rax_mov_ds[];
extern char swapgs_add_rsp_iret[];

static void inject_event(uint64_t* regs, uint64_t* iret_frame, int event_nr, int from_userspace);

static void return_from_exception(uint64_t* regs, uint64_t* iret_frame)
{
    if(iret_frame[1] != 0xfff8)
    {
        if(!GUEST_STATE.vcpu_info->evtchn_upcall_mask)
        {
            iret_frame[2] |= 512;
            if(GUEST_STATE.pending_event >= 0)
            {
                if(!(iret_frame[1] & 3))
                    die("cannot inject an event when returning to userspace");
                int event = GUEST_STATE.pending_event;
                GUEST_STATE.pending_event = -1;
                inject_event(regs, iret_frame, event, 0);
                return;
            }
        }
        else
            iret_frame[2] &= -513;
    }
    disable_gadgets(GADGETS_DISABLED);
    uint64_t* justreturn_frame = (uint64_t*)JUSTRETURN_POP_FRAME;
    justreturn_frame[0] = regs[2];
    justreturn_frame[1] = regs[1];
    justreturn_frame[2] = regs[0];
    justreturn_frame[3] = iret_frame[0];
    justreturn_frame[4] = iret_frame[1];
    justreturn_frame[5] = iret_frame[2];
    justreturn_frame[6] = iret_frame[3];
    justreturn_frame[7] = iret_frame[4];
}

static void inject_interrupt(uint64_t* regs, uint64_t* iret_frame, int have_error_code, uint64_t handler, int from_userspace)
{
    uint64_t* real_frame = iret_frame + !!have_error_code;
    if(!GUEST_STATE.vcpu_info->evtchn_upcall_mask)
        real_frame[2] |= 512;
    else
        real_frame[2] &= ~513;
    if(!from_userspace)
        real_frame[1] &= -4;
    uint64_t rsp = (from_userspace ? GUEST_STATE.rsp0 : real_frame[3]) & -16;
    if(real_frame == iret_frame)
    {
        rsp -= 40;
        memcpy((void*)rsp, real_frame, 40);
    }
    else
    {
        rsp -= 48;
        memcpy((void*)rsp, iret_frame, 48);
    }
    uint64_t rcx_r11[2] = {regs[1], regs[11]};
    rsp -= 16;
    memcpy((void*)rsp, rcx_r11, 16);
    uint64_t return_frame[5] = {handler, 0xfff3, 2, rsp, 0xffeb};
    GUEST_STATE.vcpu_info->evtchn_upcall_mask = 0xff;
    return_from_exception(regs, return_frame);
}

static void pfn_to_mfn_set_page(uint64_t page)
{
    uint64_t old_page = GUEST_STATE.pfn_to_mfn_page;
    if(old_page == page)
        return;
    if(!old_page)
    {
        uint64_t q = alloc_page();
        map_page(GUEST_STATE.cr3, page, q, 7);
    }
    else
    {
        uint64_t* old_map = (uint64_t*)old_page;
        uint64_t old_offset = (old_page - PFN_TO_MFN_START) / 8;
        for(size_t i = 0; i < 512; i++)
            if((old_map[i] ^ old_offset+i) & ((1ull << 62) - 1))
                die("kernel changed pfn_to_mfn mappings");
        uint64_t mask = ((1ull << 52) - (1ull << 12));
        uint64_t* pml4t_map = (uint64_t*)(DMEM + GUEST_STATE.cr3);
        uint64_t pml3t = pml4t_map[262];
        uint64_t* pml3t_map = (uint64_t*)(DMEM + (pml3t & mask));
        uint64_t pml2t = pml3t_map[(old_page >> 30) & 511];
        uint64_t* pml2t_map = (uint64_t*)(DMEM + (pml2t & mask));
        uint64_t pml1t = pml2t_map[(old_page >> 21) & 511];
        uint64_t* pml1t_map = (uint64_t*)(DMEM + (pml1t & mask));
        uint64_t the_page = pml1t_map[(old_page >> 12) & 511];
        pml3t_map[(old_page >> 30) & 511] = 0;
        pml3t_map[(page >> 30) & 511] = pml2t;
        pml2t_map[(old_page >> 21) & 511] = 0;
        pml2t_map[(page >> 21) & 511] = pml1t;
        pml1t_map[(old_page >> 12) & 511] = 0;
        pml1t_map[(page >> 12) & 511] = the_page;
        SET_GADGET(mov_cr3_rax_mov_ds);
        asm volatile("int $179"::"a"(GUEST_STATE.cr3):"memory");
    }
    GUEST_STATE.pfn_to_mfn_page = page;
    uint64_t* new_map = (uint64_t*)page;
    uint64_t new_offset = (page - PFN_TO_MFN_START) / 8;
    for(size_t i = 0; i < 512; i++)
        new_map[i] = new_offset + i;
}

struct evtchn_fifo_control_block
{
    uint32_t ready;
    uint32_t reserved;
    uint32_t head[16];
};

static void inject_event(uint64_t* regs, uint64_t* iret_frame, int event_nr, int from_userspace)
{
    if(GUEST_STATE.vcpu_info->evtchn_upcall_mask)
    {
        if(GUEST_STATE.pending_event >= 0)
            die("inject_event: another event is pending");
        //return first, otherwise we'll end up in infinite recursion
        return_from_exception(regs, iret_frame);
        GUEST_STATE.pending_event = event_nr;
        return;
    }
    struct evtchn_fifo_control_block* ctrl = (void*)(DMEM + GUEST_STATE.event_control_block);
    uint32_t* ev_arr = (uint32_t*)(DMEM + event_array);
    if(!(ctrl->ready & 1))
    {
        ctrl->ready |= 1;
        ctrl->head[0] = event_nr;
        ev_arr[event_nr] |= 0x80000000;
    }
    else
        die("TODO: tried to inject an event but the queue is not empty");
    GUEST_STATE.vcpu_info->evtchn_upcall_pending = 1;
    inject_interrupt(regs, iret_frame, 0, GUEST_STATE.event_callback_eip, from_userspace);
    //gdb_stub(regs, (uint64_t*)JUSTRETURN_POP_FRAME + 3);
}

extern uint32_t hlt_instr;

static inline int try_emulate_pagetable_write(uint64_t* regs, uint64_t* iret_frame)
{
    if(iret_frame[0] != 7)
        return 0;
    uint8_t* rip = (uint8_t*)iret_frame[1];
    int rex = 0;
    for(;;)
    {
        if(*rip >= 0x40 && *rip < 0x50)
            rex = *rip++;
        else if(*rip == 0xf0 || *rip == 0x3e)
            rip++;
        else
            break;
    }
    int opcode = *rip++;
    if(opcode == 0x0f)
        opcode = 0x100 + *rip++;
    if(opcode != 0x87 //xchg
    && opcode != 0x1b1) //cmpxchg
        return 0;
    int mrm = *rip++;
    if(mrm >= 0xc0) //reg-reg operation
        return 0;
    int reg = (mrm >> 3) & 7;
    int base = mrm & 7;
    int scale = 0;
    int index = 4;
    if(base == 4)
    {
        int sib = *rip++;
        base = sib & 7;
        index = (sib >> 3) & 7;
        scale = sib >> 6;
        if((rex & 2))
            index += 8;
    }
    if((rex & 1))
        base += 8;
    if((rex & 4))
        reg += 8;
    regs[4] = iret_frame[4];
    uint64_t address = regs[base] + ((index == 4 ? 0 : regs[index]) << scale);
    if(mrm >= 0x80)
    {
        int32_t displacement;
        memcpy(&displacement, rip, 4);
        rip += 4;
        address += displacement;
    }
    else if(mrm >= 0x40)
        address += (int8_t)*rip++;
    if(!(rex & 8))
        return 0;
    uint64_t virt_start, virt_end;
    uint64_t phys_addr = virt2phys(GUEST_STATE.cr3, address, &virt_start, &virt_end);
    uint64_t* linear_addr = (uint64_t*)(DMEM + phys_addr);
    if(opcode == 0x87)
        regs[reg] = __atomic_exchange_n(linear_addr, fix_pte(regs[reg]), __ATOMIC_RELAXED);
    else if(opcode == 0x1b1)
    {
        if(__atomic_compare_exchange_n(linear_addr, &regs[0], fix_pte(regs[reg]), 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            iret_frame[3] |= 64;
        else
            iret_frame[3] &= -65;
    }
    else
        return 0;
    iret_frame[4] = regs[4];
    iret_frame[1] = (uint64_t)rip;
    return_from_exception(regs, iret_frame+1);
    return 1;
}

static inline void update_vcpu_time(void)
{
    uint64_t tsc = rdtsc();
    struct vcpu_time_info* time = &GUEST_STATE.vcpu_info->time;
    time->version += 2; //bottom bit is used to mark the busy status
    time->tsc_timestamp = tsc;
    time->system_time = system_time(tsc);
}

uint64_t tsc_value_at_boot;

void init_vcpu_time(void)
{
    tsc_value_at_boot = rdtsc();
    struct vcpu_time_info* time = &GUEST_STATE.vcpu_info->time;
    memset(time, 0, sizeof(*time));
    uint64_t mul = (1000000000ull << 32) / TSC_FREQ_HZ;
    int8_t shift = 0;
    while(mul >= (1ull << 31))
    {
        shift++;
        mul /= 2;
    }
    time->tsc_to_system_mul = mul;
    time->tsc_shift = shift;
    update_vcpu_time();
}

static inline void print_apic(void)
{
    putstr("ISR:");
    for(size_t i = 0x100; i < 0x180; i += 16)
    {
        putchar(' ');
        puthex(apic[i/4]);
    }
    putstr("\r\nTMR:");
    for(size_t i = 0x180; i < 0x200; i += 16)
    {
        putchar(' ');
        puthex(apic[i/4]);
    }
    putstr("\r\nIRR:");
    for(size_t i = 0x200; i < 0x280; i += 16)
    {
        putchar(' ');
        puthex(apic[i/4]);
    }
    putstr("\r\nTPR: ");
    puthex(apic[0x80/4]);
    putchar('\r');
    putchar('\n');
}

void exception_handler(uint64_t* regs, uint64_t* iret_frame, int vector)
{
    update_vcpu_time();
    int g = enable_gadgets();
    int from_userspace = 0;
    if(vector == 14)
    {
        //we may have entered here via a landing page
        uint64_t rip = iret_frame[1];
        uint16_t cs = iret_frame[2];
        if(rip == LANDING_PAGE + KERNEL_OFFSET + 256 && (cs & 3) == 0) //syscall instruction
        {
            //rewrite the iret_frame, as if we caught the syscall itself
            //rip is right after the syscall instruction, rsp is untouched
            iret_frame[1] = regs[1];
            iret_frame[2] = 0xfff3;
            iret_frame[3] = regs[11];
            iret_frame[5] = 0xffeb;
            handle_hypercall_syscall(regs, iret_frame+1);
            return_from_exception(regs, iret_frame+1);
            return;
        }
        else if(rip >= LANDING_PAGE + KERNEL_OFFSET && rip < LANDING_PAGE + KERNEL_OFFSET + 256 && cs == 0xfff8)
        {
            vector = (uint8_t)rip;
            iret_frame = (uint64_t*)(iret_frame[4] - KERNEL_OFFSET);
        }
        else if(iret_frame[1] == GADGET(mov_cr3_rax_mov_ds) + 8 && iret_frame[2] == 0xfff8) //trap from userspace
        {
            if(parse_userspace_trap(regs, &iret_frame, &vector))
            {
parsed_userspace:
                from_userspace = 1;
                if(vector == 256)
                    inject_interrupt(regs, iret_frame+1, 0, GUEST_STATE.lstar, 1);
                else if(vector == 257)
                    inject_interrupt(regs, iret_frame+1, 0, GUEST_STATE.cstar, 1);
                else if(vector == 128) //int 0x80
                    inject_interrupt(regs, iret_frame, 0, GUEST_STATE.trap_table[0x80], 1);
                else
                {
                    if(vector == 14)
                    {
                        uint64_t cr2;
                        SET_GADGET(mov_rdi_cr2);
                        asm volatile("int $179":"=D"(cr2));
                        //no need to check corner cases here, userspace is not kernel
                        GUEST_STATE.vcpu_info->arch.cr2 = cr2;
                    }
                    goto exception_from_userspace;
                }
                return;
            }
        }
        else
        {
            SET_GADGET(mov_rdi_cr2);
            uint64_t cr2;
            asm volatile("int $179":"=D"(cr2));
            if(cr2 >= PFN_TO_MFN_START && cr2 < PFN_TO_MFN_END && 0)
            {
                pfn_to_mfn_set_page(cr2 & -4096);
                SET_GADGET(mov_cr3_rax_mov_ds);
                asm volatile("int $179"::"a"(GUEST_STATE.cr3):"memory");
                return_from_exception(regs, iret_frame+1);
                return;
            }
            else if(cr2 >= LINUX_LOWMEM_START && cr2 < LINUX_LOWMEM_END)
            {
                //linux is writing a pagetable entry without using hypercalls. not good, but we can tolerate it
                if(try_emulate_pagetable_write(regs, iret_frame))
                    return;
                else
                    die("damnit...");
            }
            GUEST_STATE.vcpu_info->arch.cr2 = cr2;
        }
    }
    else if(vector == 1 && iret_frame[0] == GADGET(mov_cr3_rax_mov_ds) + 3 && iret_frame[1] == 0xfff8)
    {
        if(parse_userspace_trap(regs, &iret_frame, &vector))
            goto parsed_userspace;
    }
    uint64_t* real_frame = (uint64_t*)((uint64_t)iret_frame | 8);
    uint64_t rip_at_entry = real_frame[0];
    if(rip_at_entry == (uint64_t)&hlt_instr || rip_at_entry == (uint64_t)&hlt_instr + 1)
        rip_at_entry = real_frame[0] = regs[2];
    if((rip_at_entry >= RESERVED_AREA_START && rip_at_entry < FAKEXEN_END) || g == GADGETS_ENABLED || !(real_frame[1] & 3))
    {
        putstr("fatal error: exception caught within fakexen\r\n");
    print_exception:
        regs[4] = real_frame[3];
        if(!gdb_stub_active())
        {
            putstr("rip = 0x");
            puthex(rip_at_entry);
            putstr(", rip[int179] = 0x");
            puthex(*(uint64_t*)IST_SAVED_FRAME(IST_SLOT_INT179));
            putstr(", vector = ");
            putint(vector);
            putstr(", error_code = 0x");
            puthex(real_frame[-1]);
            putstr("\r\nregisters:");
            for(size_t i = 0; i < 15; i++)
            {
                putstr(" 0x");
                puthex(regs[i]);
            }
            putstr("\r\nstack dump:");
            for(uint64_t rsp = real_frame[3]; (rsp & -4096) == (real_frame[3] & -4096); rsp += 8)
            {
                putstr(" 0x");
                puthex(*(uint64_t*)rsp);
            }
            putstr("\r\n");
        }
        gdb_stub(regs, real_frame);
        return_from_exception(regs, real_frame);
        return;
    }
    if(vector == 13)
    {
    gp_emulate:
        if((int64_t)iret_frame[1] != (((int64_t)iret_frame[1] << 16) >> 16))
            die("GP: rip is non-canonical, wtf???");
        uint8_t* rip = (uint8_t*)iret_frame[1];
        if(rip[0] == 0x0f && rip[1] == 0x30) //wrmsr
        {
            uint32_t msr = regs[1];
            uint64_t value = regs[2] << 32 | (uint32_t)regs[0];
            if(msr == 0xc0000100 || msr == 0xc0000103)
                wrmsr(msr, value);
            else if(msr == 0xc0000101)
            {
                GUEST_STATE.gsbase = value;
                wrmsr(msr, value);
            }
            else if(msr == 0xc0000102)
                GUEST_STATE.kgsbase = value;
            else
            {
                putstr("TODO: write of 0x");
                puthex(value);
                putstr(" to unknown msr 0x");
                puthex(msr);
                putchar('\r');
                putchar('\n');
            }
            iret_frame[1] += 2;
            return_from_exception(regs, iret_frame+1);
            return;
        }
        else if(rip[0] == 0x0f && rip[1] == 0x20) //mov r.., cr.
        {
            uint8_t reg = rip[2] & 7;
            uint8_t creg = (rip[2] >> 3) & 7;
            uint64_t value;
            if(creg == 0)
            {
                SET_GADGET(mov_rax_cr0);
                asm volatile("int $179":"=a"(value));
            }
            else if(creg == 2)
            {
                value = GUEST_STATE.vcpu_info->arch.cr2;
            }
            else if(creg == 3)
                value = GUEST_STATE.cr3;
            else if(creg == 4)
            {
                //putstr("mov r.., cr4: TODO: stub\r\n");
                value = 0;
            }
            else
                die("mov r.., cr.: unknown cr register");
            regs[4] = iret_frame[3];
            regs[reg] = creg;
            iret_frame[3] = regs[4];
            iret_frame[1] += 3;
            return_from_exception(regs, iret_frame+1);
            return;
        }
        else if(rip[0] == 0x0f && rip[1] == 0x22 && rip[2] == 0xe7) //mov cr4, rdi
        {
            putstr("mov cr4, rdi: TODO: stub (rdi = 0x");
            puthex(regs[7]);
            putstr(")\r\n");
            iret_frame[1] += 3;
            return_from_exception(regs, iret_frame+1);
            return;
        }
        else if(rip[0] == 0x0f && rip[1] == 0x32) //rdmsr
        {
            uint32_t msr = regs[1];
            uint64_t value;
            if(msr == 0xc0000100 || msr == 0xc0000103
            || msr == 0x1b) //IA32_APIC_BASE
                value = rdmsr(msr);
            else if(msr == 0xc0000101)
                value = GUEST_STATE.gsbase;
            else if(msr == 0xc0000102)
                value = GUEST_STATE.kgsbase;
            else
            {
                putstr("TODO: read from unknown msr 0x");
                puthex(msr);
                putchar('\r');
                putchar('\n');
                /*if(msr == 0x8b)
                    die("meow meow prrr");*/
                value = 0;
            }
            regs[0] = (uint32_t)value;
            regs[2] = value >> 32;
            iret_frame[1] += 2;
            return_from_exception(regs, iret_frame+1);
            return;
        }
        //IO space is RAZ/WI for now
        else if(rip[0] == 0xee /* out [dx], al */ || rip[0] == 0xef /* out [dx], eax */)
        {
            iret_frame[1]++;
            return_from_exception(regs, iret_frame+1);
            return;
        }
        else if((rip[0] == 0x66 && rip[1] == 0xef) /* out [dx], ax */ || rip[0] == 0xe6 /* out imm8, al */)
        {
            iret_frame[1] += 2;
            return_from_exception(regs, iret_frame+1);
            return;
        }
        else if(rip[0] == 0xec) //in al, [dx]
        {
            regs[0] &= -256;
            iret_frame[1]++;
            return_from_exception(regs, iret_frame+1);
            return;
        }
        else if(rip[0] == 0xed) //in eax, [dx]
        {
            regs[0] = 0;
            iret_frame[1]++;
            return_from_exception(regs, iret_frame+1);
            return;
        }
        else if(rip[0] == 0x66 && rip[1] == 0xed) //in ax, [dx]
        {
            regs[0] &= -65536;
            iret_frame[1] += 2;
            return_from_exception(regs, iret_frame+1);
            return;
        }
        else if(rip[0] == 0xe4) //in al, imm8
        {
            regs[0] &= -256;
            iret_frame[1] += 2;
            return_from_exception(regs, iret_frame+1);
            return;
        }
        else if(rip[0] == 0xfa) //cli
        {
#if 0
            GUEST_STATE.vcpu_info->evtchn_upcall_mask = 0xff;
            iret_frame[1]++;
#else
            copy_to_kernel(GUEST_STATE.cr3, iret_frame[1], "\x90", 1);
#endif
            return_from_exception(regs, iret_frame+1);
            return;
        }
        else if(rip[0] == 0x0f && rip[1] == 0x01 && rip[2] == 0xd1) //xsetbv
        {
            putstr("xsetbv: TODO: stub\r\n");
            iret_frame[1] += 3;
            return_from_exception(regs, iret_frame+1);
            return;
        }
    }
    else if(vector == 6)
    {
        uint8_t* rip = (uint8_t*)iret_frame[0];
        if(rip[0] == 0x0f && rip[1] == 0x0b && rip[2] == 'x' && rip[3] == 'e' && rip[4] == 'n') // XEN_EMULATE_PREFIX
        {
            //we don't need to emulate anything, so just run the instruction as is
            //(or do we?)
            rip += 5;
            iret_frame[0] += 5;
            //indeed we do
            if(rip[0] == 0x0f && rip[1] == 0xa2) //cpuid
            {
                iret_frame[0] += 2;
                if((uint32_t)regs[0] == 0x40000000)
                {
                    uint32_t ebx_ecx_edx[3];
                    memcpy(ebx_ecx_edx, "XenVMMXenVMM", 12);
                    regs[0] = 2;
                    regs[1] = ebx_ecx_edx[1];
                    regs[2] = ebx_ecx_edx[2];
                    regs[3] = ebx_ecx_edx[0];
                }
                else
                {
                    uint32_t leaf = regs[0];
                    asm volatile("cpuid":"=a"(regs[0]),"=c"(regs[1]),"=d"(regs[2]),"=b"(regs[3]):"a"(leaf));
                    if(leaf == 1)
                        regs[2] &= ~(1u << 3); //mask PSE
                    else if(leaf == 7)
                        regs[3] &= ~(1u << 0); //mask FSGSBASE
                    else if(leaf == 0x80000001)
                    {
                        regs[1] &= ~(1u << 2); //mask SVM
                        regs[2] &= ~(1u << 26); //mask GB pages
                    }
                }
            }
            return_from_exception(regs, iret_frame);
            return;
        }
        else if((rip[0] == 0x0f && rip[1] == 0x01 && rip[2] == 0xca)  //clac
             || (rip[0] == 0x0f && rip[1] == 0x01 && rip[2] == 0xcb)) //stac
        {
            copy_to_kernel(GUEST_STATE.cr3, iret_frame[0], "\x90\x90\x90", 3);
            return_from_exception(regs, iret_frame);
            return;
        }
        else if(!(rip[0] == 0x0f && rip[1] == 0x0b))
        {
            int possible_1byte = (rip[-1] >= 0xec && rip[-1] <= 0xef);
            int possible_2byte = (rip[-2] == 0xe4 || rip[-2] == 0xe6);
            if(possible_1byte && possible_2byte)
                die("exception_handler: ambiguous in/out decoding (both instructions possible)");
            else if(possible_1byte || possible_2byte)
            {
                if(possible_1byte)
                    rip--;
                else
                    rip -= 2;
                if(rip[-1] == 0x66)
                    die("exception_handler: ambiguous in/out decoding (0x66 prefix)");
                iret_frame[0] = (uint64_t)rip;
                iret_frame--;
                goto gp_emulate;
            }
        }
    }
    else if(vector == 14 && iret_frame[0] == 1 && iret_frame[2] == 0xfff3) //page fault on kernel access, but cs is usermode
    {
        //nasty qemu workaround: iretq does not work in ring3 if smap is enabled
        uint8_t* rip = (uint8_t*)iret_frame[1];
        if(rip[0] == 0x48 && rip[1] == 0xcf) //iretq
        {
            uint64_t* guest_rsp = (uint64_t*)iret_frame[4]; //let's hope that it is intact
            if(((int64_t)guest_rsp[0] == (int64_t)(guest_rsp[0] << 16) >> 16) && guest_rsp[1] == 0xfff3 && (guest_rsp[2] & 2) && guest_rsp[4] == 0xffeb) //sanity check
            {
                return_from_exception(regs, guest_rsp);
                return;
            }
        }
    }
    else exception_from_userspace: if(vector == 240) //remnants of the ipi used to start up cores
    {
        apic[0xb0 / 4] = 0;
        if(from_userspace)
            arrange_jump_to_userspace(regs, iret_frame);
        return_from_exception(regs, iret_frame);
        return;
    }
    else if(vector >= 0x81 && vector < 0x91)
    {
        apic[0xb0 / 4] = 0;
        int channel = 512 + 16 * (vector - 0x81) + GUEST_STATE.apic_id;
        inject_event(regs, iret_frame, channel, from_userspace);
        return;
    }
    else if(vector == 0x91) //fake nmi
    {
        apic[0xb0 / 4] = 0;
        vector = 2;
    }
    else if(vector == 0x92) //tlb shootdown
    {
        apic[0xb0 / 4] = 0;
        if(from_userspace)
            //we've already flushed the tlb by reloading cr3, no need to do it again
            arrange_jump_to_userspace(regs, iret_frame);
        //gcc does not seem to support atomics on gs-relative pointers
        //which is weird, because there's no actual reason they couldn't work
        else if(__atomic_exchange_n(&REMOTE_GUEST_STATE(GUEST_STATE.apic_id)->n_flushes, 0, __ATOMIC_RELAXED))
        {
            SET_GADGET(mov_cr3_rax_mov_ds);
            asm volatile("int $179"::"a"(GUEST_STATE.cr3));
        }
        return_from_exception(regs, iret_frame);
        return;
    }
    else if(vector == 0x20)
    {
        apic[0xb0 / 4] = 0;
        inject_event(regs, iret_frame, 256 + GUEST_STATE.apic_id, from_userspace);
        return;
    }
    else if(vector >= 32)
    {
        if(vector < 256 && (irqs_enabled[vector / 64] & (1ull << (vector % 64))))
            inject_event(regs, iret_frame, vector, from_userspace);
        else
        {
            if(vector != 86) //a lot of interrupt spam on that one, ignore it to unclutter the logs
            {
                putstr("IRQ received, vector = ");
                putint(vector);
                putchar('\r');
                putchar('\n');
            }
            if(from_userspace)
                arrange_jump_to_userspace(regs, iret_frame);
            return_from_exception(regs, iret_frame);
        }
        apic[0xb0 / 4] = 0;
        return;
    }
    if(gdb_stub_active() || !GUEST_STATE.trap_table[vector] || vector >= 32)
        goto print_exception;
    inject_interrupt(regs, iret_frame, iret_frame != real_frame, GUEST_STATE.trap_table[vector], from_userspace);
}


__attribute__((no_caller_saved_registers)) void swapgs_on_exception(uint64_t percpu_offset)
{
    //we need to swapgs back to our "real" stack. everything that uses gsbase is broken at this point, so we redefine the GUEST_STATE macro ourselves
    //for this reason, this function is the last
#undef GUEST_STATE
#define GUEST_STATE (*(struct guest_state*)(GUEST_STATE0 + percpu_offset))
    int g = IST(1);
    IST(1) = GADGETS_ENABLED;
    SET_GADGET(swapgs_add_rsp_iret);
    asm volatile("int $179");
    IST(1) = g;
}
