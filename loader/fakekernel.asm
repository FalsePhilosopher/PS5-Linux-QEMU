use64

%macro symbol 2
db %1, 0
dq (%2) - fakekernel_start
%endmacro

global fakekernel_start
global fakekernel_end

fakekernel_start:
symbol "swapgs_add_rsp_iret", swapgs_add_rsp_iret
symbol "add_rsp_iret", add_rsp_iret
symbol "doreti_iret", doreti_iret
symbol "wrmsr_ret", wrmsr_ret
symbol "nop_ret", nop_ret
symbol "justreturn", justreturn
symbol "justreturn_pop", justreturn_pop
symbol "mov_cr3_rax_mov_ds", mov_cr3_rax_mov_ds
symbol "mov_rdi_cr3", mov_rdi_cr3
symbol "mov_rax_cr0", mov_rax_cr0
symbol "mov_cr0_rax", mov_cr0_rax
symbol "lidt_lldt", lidt_lldt
symbol "ltr_ax", ltr_ax
symbol "lgdt_rdi", lgdt_rdi
symbol "mov_rdi_cr2", mov_rdi_cr2
symbol "rdmsr_start", rdmsr_start
symbol "kdata_base", kdata_base
symbol "idt", idt
symbol "gdt_array", gdt_array
symbol "tss_array", tss_array
symbol "lapic_map", lapic_map
symbol "loader_retpoline", loader_retpoline
db 0

swapgs_add_rsp_iret:
swapgs
add_rsp_iret:
add rsp, 0xe8
doreti_iret:
iretq

as_lapic_eoi:
cmp dword [rel x2apic_mode], 0
jne .x2apic
mov rax, [rel lapic_map]
mov dword [rax+0xb0], 0
ret
.x2apic:
mov ecx, 0x80b
xor eax, eax
xor edx, edx
wrmsr_ret:
wrmsr
nop_ret:
ret

justreturn:
push rax
push rcx
push rdx
call as_lapic_eoi
justreturn_pop:
pop rdx
pop rcx
pop rax
jmp doreti_iret

mov_cr3_rax_mov_ds:
mov cr3, rax
mov eax, 0x28
mov ds, ax
db 0xeb, 0xfe

mov_rdi_cr3:
mov rdi, cr3
mov eax, 0x28
mov ds, ax
db 0xeb, 0xfe

mov_rax_cr0:
mov rax, cr0
db 0xeb, 0xfe

mov_cr0_rax:
mov cr0, rax
db 0xeb, 0xfe

lidt_lldt:
lidt [rdi+0xea]
lldt [rdi+0xf4]
db 0xeb, 0xfe

ltr_ax:
ltr ax
db 0xeb, 0xfe

lgdt_rdi:
lgdt [rdi]
db 0xeb, 0xfe

mov_rdi_cr2:
mov rdi, cr2
db 0xeb, 0xfe

rdmsr_start:
rdmsr
db 0xeb, 0xfe

loader_retpoline:
mov r8, rdi
lea rdi, [rel temp_stack]
mov rsi, rsp
mov rcx, 5
rep movsq
lea rsp, [rel temp_stack]
mov rax, cr4
or rax, 0x300e00
mov cr4, rax
mov rdi, r8
xor eax, eax
xor ecx, ecx
xor esi, esi
xor r8d, r8d
iretq

kdata_base:
x2apic_mode:
dq 0
lapic_map:
dq 0

idt:
times 4096 dq 0

gdt_array:
%rep 16
dq 0
dq 0
dq 0
dq 0
db 0xff, 0xff, 0, 0, 0, 0x9a, 0xaf, 0 ; 0x20
dq 0
dq 0
db 0xff, 0xff, 0, 0, 0, 0xf3, 0xcf, 0 ; 0x3b
db 0xff, 0xff, 0, 0, 0, 0xfa, 0xaf, 0 ; 0x43
db 0x68, 0x00, 0, 0, 0, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 0x48
dq 0
dq 0
%endrep

tss_array:
times 16*0x68 dq 0

temp_stack:
times 5 dq 0

fakekernel_end:
