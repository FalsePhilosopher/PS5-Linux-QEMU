#include "types.h"
#include "uart.h"
#include "memmap.h"
#include "gadgets.h"
#include "smp.h"
#include "string.h"
#include "hypercalls.h"

static uint32_t startup[16];

int smp_is_cpu_up(int which)
{
    return __atomic_load_n(startup+which, __ATOMIC_RELAXED);
}

void smp_start_cpu(int which)
{
    __atomic_store_n(startup+which, 1, __ATOMIC_RELEASE);
}

extern char mov_cr3_rax_mov_ds[];

void ap_jump_to_linux(struct cpu_user_regs* regs);

void smp_waitloop(int which)
{
    enable_gadgets();
    while(!smp_is_cpu_up(which));
    putstr("CPU #");
    putint(which);
    putstr(" is starting...\r\n");
    struct vcpu_guest_context* ctx = (void*)VCPU_GUEST_CONTEXT_START;
    uint64_t new_cr3 = ctx->ctrlreg[3];
    /*memcpy(DMEM+GUEST_STATE.initial_cr3, DMEM+new_cr3, 2048);
    memcpy(DMEM+GUEST_STATE.initial_cr3+2048+64, DMEM+new_cr3+2048+64, 2048-64);*/
    memcpy(DMEM+new_cr3+2048, DMEM+initial_cr3+2048, 64);
    SET_GADGET(mov_cr3_rax_mov_ds);
    asm volatile("int $179"::"a"(new_cr3):"memory");
    GUEST_STATE.cr3 = new_cr3;
    for(size_t i = 0; i < 256; i++)
        if(ctx->trap_ctxt[i].cs)
            GUEST_STATE.trap_table[ctx->trap_ctxt[i].vector] = ctx->trap_ctxt[i].address;
    hypercall_set_gdt(ctx->gdt_frames, ctx->gdt_ents);
    GUEST_STATE.lstar = ctx->syscall_callback_eip;
    GUEST_STATE.event_callback_eip = ctx->event_callback_eip;
    GUEST_STATE.failsafe_callback_eip = ctx->failsafe_callback_eip;
    wrmsr(0xc0000100, ctx->fs_base);
    wrmsr(0xc0000101, GUEST_STATE.gsbase = ctx->gs_base_kernel);
    GUEST_STATE.kgsbase = ctx->gs_base_user;
    uint64_t* jr_frame = (uint64_t*)JUSTRETURN_POP_FRAME;
    jr_frame[0] = ctx->user_regs.rdx;
    jr_frame[1] = ctx->user_regs.rcx;
    jr_frame[2] = ctx->user_regs.rax;
    jr_frame[3] = ctx->user_regs.rip;
    jr_frame[4] = ctx->user_regs.cs | 3;
    jr_frame[5] = ctx->user_regs.rflags;
    jr_frame[6] = ctx->user_regs.rsp;
    jr_frame[7] = ctx->user_regs.ss | 3;
    disable_gadgets(GADGETS_DISABLED);
    ap_jump_to_linux(&ctx->user_regs);
}
