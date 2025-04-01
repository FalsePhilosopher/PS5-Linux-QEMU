#include "memmap.h"
#include "ist_page.h"
#include "userspace.h"
#include "page_alloc.h"
#include "utils.h"
#include "string.h"
#include "die.h"
#include "gadgets.h"

extern char add_rsp_iret[];
extern char justreturn[];
extern char justreturn_pop[];
extern char mov_cr3_rax_mov_ds[];
extern char doreti_iret[];

#define SHENANIGAN_START (IST_SAVED_FRAME(IST_SLOT_INT1_SHENANIGANS) - 8)
#define SHENANIGAN_INT1_POP SHENANIGAN_START
#define SHENANIGAN_PF_PUSH (SHENANIGAN_INT1_POP + 64)
#define SHENANIGAN_PF_POP (SHENANIGAN_PF_PUSH + 72)
#define SHENANIGAN_END (SHENANIGAN_PF_POP + 64)
#define MAGIC_STACK 0x52455355 // 'USER'

//extern char verify_shenanigan_fits[1/(IST_SAVED_FRAME(15) >= SHENANIGAN_END)];

uint64_t init_userspace_cr3(uint64_t cr3)
{
    uint64_t user_cr3 = alloc_page();
    uint64_t* user_cr3_mapped = (uint64_t*)(DMEM + user_cr3);
    uint64_t* kernel_cr3_mapped = (uint64_t*)(DMEM + cr3);
    for(size_t i = 256; i < 261; i++)
        user_cr3_mapped[i] = kernel_cr3_mapped[i] & -5; //clear the user bit, to make sure that only ring0 has access
    for(size_t cpu = 0; cpu < 16; cpu++)
    {
        uint64_t virt_start, virt_end;
        for(uint64_t i = 0; i < 65536; i += 4096)
            map_page(user_cr3, GDT0+cpu*PERCPU_OFFSET+KERNEL_OFFSET+i, virt2phys(cr3, GDT0+cpu*PERCPU_OFFSET+KERNEL_OFFSET+i, &virt_start, &virt_end), 3);
        map_page(user_cr3, IST_PAGE0+cpu*PERCPU_OFFSET+KERNEL_OFFSET, virt2phys(cr3, IST_PAGE0+cpu*PERCPU_OFFSET+KERNEL_OFFSET, &virt_start, &virt_end), 3);
        uint64_t user_idt = alloc_page();
        uint8_t idt_entry[16] = {0, 0, 0xf8, 0xff, 0, 0x8e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        uint64_t ptr = GADGET(add_rsp_iret);
        memcpy(idt_entry, (uint8_t*)&ptr, 2);
        memcpy(idt_entry+6, (uint8_t*)&ptr + 2, 6);
        idt_entry[4] = 1;
        memcpy(DMEM+user_idt+16, idt_entry, 16);
        ptr = GADGET(add_rsp_iret);
        memcpy(idt_entry, (uint8_t*)&ptr, 2);
        memcpy(idt_entry+6, (uint8_t*)&ptr + 2, 6);
        idt_entry[4] = 2;
        memcpy(DMEM+user_idt+14*16, idt_entry, 16);
        idt_entry[4] = 3;
        ptr = LANDING_PAGE + KERNEL_OFFSET;
        memcpy(idt_entry, (uint8_t*)&ptr, 2);
        memcpy(idt_entry+6, (uint8_t*)&ptr + 2, 6);
        for(size_t i = 0; i < 256; i++)
            if(i != 1 && i != 14)
            {
                idt_entry[5] = (i == 3 || i == 128) ? 0xee : 0x8e;
                idt_entry[0] = i;
                memcpy(DMEM+user_idt+16*i, idt_entry, 16);
            }
        map_page(user_cr3, IDT0+cpu*PERCPU_OFFSET+KERNEL_OFFSET, user_idt, 1);
        uint64_t user_tss = alloc_page();
        map_page(user_cr3, TSS0+cpu*PERCPU_OFFSET+KERNEL_OFFSET, user_tss, 3);
    }
    return user_cr3;
}

void init_userspace_ist(void)
{
    uint64_t virt_start, virt_end;
    uint64_t user_tss = virt2phys(initial_user_cr3, TSS + KERNEL_OFFSET, &virt_start, &virt_end);
    uint64_t* frame = (uint64_t*)IST_RETURN_FRAME(IST_SLOT_INT1_FOR_USERSPACE);
    //int1 jumps to the shenanigan page
    //rsp and ss will be filled in when entering userspace, fill with invalid values for now
    frame[0] = GADGET(justreturn);
    frame[1] = 0xfff8;
    frame[2] = 2;
    frame[3] = 0;
    frame[4] = 1;
    //...to here
    frame = (uint64_t*)(IST_RETURN_FRAME(IST_SLOT_INT1_FOR_USERSPACE) + 56);
    frame[0] = GADGET(justreturn_pop);
    frame[1] = 0xfff8;
    frame[2] = 2;
    frame[3] = SHENANIGAN_INT1_POP + KERNEL_OFFSET;
    frame[4] = 0;
#if 0
    frame = (uint64_t*)SHENANIGAN_INT1_POP;
    frame[3] = GADGET(add_rsp_iret);
    frame[4] = 0xfff8;
    frame[5] = 2;
    frame[6] = SHENANIGAN_INT1_IRET + KERNEL_OFFSET - 0xe8;
    frame[7] = 0;
#endif
    //pf also jumps to the shenanigan page
    frame = (uint64_t*)IST_RETURN_FRAME_ERRC(IST_SLOT_PF_FOR_USERSPACE);
    frame[0] = GADGET(justreturn);
    frame[1] = 0xfff8;
    frame[2] = 2;
    frame[3] = SHENANIGAN_PF_PUSH + 32 + KERNEL_OFFSET;
    frame[4] = 0;
    //...to here
    frame = (uint64_t*)(SHENANIGAN_PF_PUSH + 32);
    frame[0] = GADGET(justreturn_pop);
    frame[1] = 0xfff8;
    frame[2] = 2;
    frame[3] = SHENANIGAN_PF_POP + KERNEL_OFFSET;
    frame[4] = 0;
    frame = (uint64_t*)SHENANIGAN_PF_POP;
    frame[0] = 0;
    frame[1] = 0;
    frame[2] = initial_cr3;
    frame[3] = GADGET(mov_cr3_rax_mov_ds);
    frame[4] = 0xfff8;
    frame[5] = 0x102;
    frame[6] = MAGIC_STACK;
    frame[7] = 0;
    uint64_t* ists = (uint64_t*)(DMEM + user_tss + 0x24);
    ists[0] = IST_ENTRY(IST_SLOT_INT1_FOR_USERSPACE);
    ists[1] = IST_ENTRY(IST_SLOT_PF_FOR_USERSPACE);
    ists[2] = IST_ENTRY(IST_SLOT_LANDING);
}

void arrange_jump_to_userspace(uint64_t* regs, uint64_t* iret_frame)
{
    uint64_t* frame = (uint64_t*)IST_RETURN_FRAME(IST_SLOT_INT1_FOR_USERSPACE);
    frame[3] = IST_RETURN_FRAME(IST_SLOT_INT1_FOR_USERSPACE) + 56 + KERNEL_OFFSET;
    frame[4] = 0;
    frame = (uint64_t*)SHENANIGAN_INT1_POP;
    frame[0] = regs[2];
    frame[1] = regs[1];
    frame[2] = regs[0];
    frame = (uint64_t*)SHENANIGAN_PF_POP;
    frame[2] = GUEST_STATE.cr3;
    memcpy((void*)(SHENANIGAN_INT1_POP + 24), iret_frame, 40);
    regs[0] = GUEST_STATE.user_cr3;
    regs[1] = 0;
    regs[2] = 1; //corrupts ss in int1's iret frame
    iret_frame[0] = GADGET(mov_cr3_rax_mov_ds);
    iret_frame[1] = 0xfff8;
    iret_frame[2] = 0x102;
    iret_frame[3] = 0;
    iret_frame[4] = 0;
    *GUEST_STATE.pml1t_for_gdt &= -2;
    //swapgs!
    int g = enable_gadgets();
    SET_GADGET(wrmsr_ret);
    asm volatile("int $179"::"c"(0xc0000101),"a"(GUEST_STATE.kgsbase),"d"(GUEST_STATE.kgsbase>>32));
    disable_gadgets(g);
}

int parse_userspace_trap(uint64_t* regs, uint64_t** p_iret_frame, int* p_vector)
{
    uint64_t* iret_frame = *p_iret_frame;
    if(*p_vector == 14)
        iret_frame++;
    if(iret_frame[3] != MAGIC_STACK)
        return 0;
    int vector = 14;
    uint64_t* frame = (uint64_t*)SHENANIGAN_PF_PUSH;
    regs[0] = frame[3];
    regs[1] = frame[2];
    regs[2] = frame[1];
    iret_frame = (uint64_t*)(IST_SAVED_FRAME(IST_SLOT_PF_FOR_USERSPACE) - 8);
    if(iret_frame[1] >= LANDING_PAGE + KERNEL_OFFSET && iret_frame[1] < LANDING_PAGE + KERNEL_OFFSET + 4096)
    {
        vector = iret_frame[1] & 4095;
        if(vector >= 256) //syscall-like trap
        {
            iret_frame[1] = regs[1];
            iret_frame[2] = 0xfff3;
            iret_frame[3] = regs[11];
            iret_frame[5] = 0xffeb;
        }
        else
            iret_frame = (uint64_t*)(iret_frame[4] - KERNEL_OFFSET);
    }
    if(iret_frame[1] == GADGET(doreti_iret) && iret_frame[2] == 0xfff8)
    {
        if(vector == 13 && iret_frame[4] == IST_RETURN_FRAME(IST_SLOT_INT1_FOR_USERSPACE) + KERNEL_OFFSET)
        {
            vector = 1;
            iret_frame = (uint64_t*)IST_SAVED_FRAME(IST_SLOT_INT1_FOR_USERSPACE);
        }
        else
            memcpy(iret_frame + 1, (void*)(iret_frame[4] - KERNEL_OFFSET), 40);
    }
    uint64_t* real_frame = (uint64_t*)((uint64_t)iret_frame | 8);
    if(!(real_frame[1] & 3))
        die("parse_userspace_trap: trap comes from kernel function");
    *p_iret_frame = iret_frame;
    *p_vector = vector;
    //swapgs!
    int g = enable_gadgets();
    SET_GADGET(wrmsr_ret);
    asm volatile("int $179"::"c"(0xc0000101),"a"(GUEST_STATE.gsbase),"d"(GUEST_STATE.gsbase>>32));
    disable_gadgets(g);
    *GUEST_STATE.pml1t_for_gdt |= 1;
    return 1;
}
