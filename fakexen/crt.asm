section .text
use64

global _start
global putchar
global getchar_nonblocking
global memcpy
global memset
global return_trampoline
global set_cs_ss
global debug_handler
global page_fault_handler
global shared_page
global int180
extern relocate
extern initial_cr3
extern relocate_percpu
extern page_alloc_start
extern exception_handler
extern swapgs_on_exception

; rdi = cr3
_start:
mov rax, rdi
mov rsi, rdi
add rdi, 2048
mov rcx, 3
rep movsq
mov rdi, rax
lea rcx, [rel .proper_address]
mov rax, 0xffff800000000000
add rax, rcx
jmp rax
.proper_address:
lock inc dword [rel entered]
.wait_entry:
pause
cmp dword [rel entered], 16
jnz .wait_entry
mov eax, 11
cpuid
mov eax, edx
shl eax, 13
mov ebp, eax
lea rcx, [rel stacks+8192]
lea rsp, [rax+rcx]
test edx, edx
jnz .not_bsp
pushfq
pop rsi
test rsi, 0x3000
jz .not_qemu

%macro OUTB 2
mov al, (%2)
mov dx, 0x3f8+(%1)
out dx, al
%endmacro

; patches for running on QEMU
; need to patch (at least) putchar, getchar, & set_cs_ss (QEMU bug!!!)
mov word [rel putchar], (putchar_qemu - putchar - 2) * 256 + 0xeb
mov word [rel getchar_nonblocking], (getchar_qemu - getchar_nonblocking - 2) * 256 + 0xeb
mov word [rel set_cs_ss.retf], 0x9090
; initialize the ISA serial port
OUTB 1, 0
OUTB 3, 0x80
OUTB 0, 3
OUTB 1, 0
OUTB 3, 3
OUTB 2, 0xc7
OUTB 4, 0x0b
OUTB 4, 0x1e
OUTB 0, 0xae
OUTB 4, 0x0f
mov dx, 0x3f8
in al, dx

%undef OUTB

.not_qemu:
call relocate
mov eax, 11
xor ecx, ecx
cpuid
.not_bsp:
mov esi, edx
lea rdx, [rel initial_cr3]
.wait_relocation:
pause
mov rdi, [rdx]
test rdi, rdi
jz .wait_relocation
mov rax, rdi
mov rcx, [rel page_alloc_start]
mov r8, rsp
lea r9, [rel .after_set_cr3]
int 179 ; mov cr3, rax
.after_set_cr3:
mov [rdx], rax
xor eax, eax
lock cmpxchg [rel page_alloc_start], rcx
lea r9, [rel .call_main]
mov ax, 0x10
int 180 ; ltr ax
.call_main:
lock inc dword [rel entered]
.wait_relocation_on_all_cores:
pause
cmp dword [rel entered], 32
jnz .wait_relocation_on_all_cores
push dword 0
push dword 0
mov rsi, rsp
call relocate_percpu
.halt:
jmp .halt

putchar:
mov rax, 0xffff8080c1010100
.wait:
test dword [rax+12], 0x800
jnz .wait
movzx edi, dil
mov dword [rax+4], edi
ret

putchar_qemu:
mov al, dil
.nop_here:
out 0xe9, al
ret
nop
mov dx, 0x3fd
.wait:
in al, dx
test al, 0x20
jz .wait
mov al, dil
mov dx, 0x3f8
out dx, al
ret

getchar_nonblocking:
mov rax, 0xffff8080c1010100
test dword [rax+12], 16
jz .no_char
mov eax, [rax]
movzx eax, al
ret
.no_char:
xor eax, eax
dec eax
ret

getchar_qemu:
mov dx, 0x3fd
in al, dx
test al, 1
jz getchar_nonblocking.no_char
mov dword [rel putchar_qemu.nop_here], 0x90909090
mov dx, 0x3f8
in al, dx
movzx eax, al
ret

memcpy:
mov rcx, rdx
mov rax, rdi
shr rcx, 3
rep movsq
mov cl, dl
and cl, 7
rep movsb
ret

memset:
mov rcx, rdx
mov eax, esi
mov rsi, rdi
rep stosb
mov rax, rsi
ret

return_trampoline:
mov rsp, r8
jmp r9

set_cs_ss:
push rdi
lea rdi, [rel .target2]
push rdi
.retf:
retf
add qword [rsp], .target - .target2
jmp far qword [rsp]
.target:
add rsp, 16
.target2:
mov eax, esi
mov ss, ax
xor eax, eax
mov ds, ax
mov es, ax
mov fs, ax
mov gs, ax
ret

debug_handler:
cmp dword [rsp], 0
jnz .recurrent
mov dword [rsp], 1
.after_fixup:
push r15
push r14
push r13
push r12
push r11
push r10
push r9
push r8
push rdi
push rsi
push rbp
push dword 0
push rbx
push rdx
push rcx
push rax
mov rdi, rsp
mov rsi, (0xffff828000011000 + 48 * 13 + 8) ; IST_SAVED_FRAME(IST_SLOT_INT1_GUEST)
add rsi, [rsp+136]
mov rdx, 1
cld
call exception_handler
jmp return_to_guest
.recurrent:
sub rsp, 4096
push rdi
push dword 0
mov rdi, [rsp+4120]
mov [rsp+24], rdi
call swapgs_on_exception
pop rdi
pop rdi
jmp .after_fixup

page_fault_handler:
cmp dword [rsp], 0
jnz pf_recurrent
mov dword [rsp], 1
pf_after_fixup:
push r15
push r14
push r13
push r12
push r11
push r10
push r9
push r8
push rdi
push rsi
push rbp
push dword 0
push rbx
push rdx
push rcx
push rax
mov rdi, rsp
mov rsi, (0xffff828000011000 + 48 * 4) ; IST_SAVED_FRAME(IST_SLOT_PAGEFAULT) - 8
add rsi, [rsp+136]
mov rdx, 14
cld
call exception_handler
return_to_guest:
pop rax
pop rcx
pop rdx
pop rbx
pop rbp
pop rbp
pop rsi
pop rdi
pop r8
pop r9
pop r10
pop r11
pop r12
pop r13
pop r14
pop r15
mov dword [rsp], 0
int180:
int 180
pf_recurrent:
sub rsp, 4096
push rdi
push dword 0
mov rdi, [rsp+4120]
mov [rsp+24], rdi
call swapgs_on_exception
pop rdi
pop rdi
jmp pf_after_fixup

section .data
align 4096
stacks:
times 16*8192 db 0
shared_page:
times 4096 db 0
entered:
dd 0
