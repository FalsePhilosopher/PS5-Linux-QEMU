section .text
use64

global jump_to_linux
global ap_jump_to_linux
global hypercall_entry
extern putstr
extern hypercalls

jump_to_linux:
mov rsi, rdi
xor eax, eax
xor ecx, ecx
xor edx, edx
xor ebx, ebx
xor ebp, ebp
xor edi, edi
xor r8d, r8d
xor r9d, r9d
xor r10d, r10d
xor r11d, r11d
xor r12d, r12d
xor r13d, r13d
xor r14d, r14d
xor r15d, r15d
int 180

ap_jump_to_linux:
mov rsp, rdi
pop r15
pop r14
pop r13
pop r12
pop rbp
pop rbx
pop r11
pop r10
pop r9
pop r8
pop rax
pop rcx
pop rdx
pop rsi
pop rdi
int 180

hypercall_entry:
push rcx
mov eax, eax
lea rcx, [rel hypercalls]
mov rcx, [rel rcx+8*rax]
test rcx, rcx
jz .die
mov rax, rcx
mov rcx, r10
call rax
pop rcx
ret
.die:
mov ebp, eax
lea rdi, [rel .die_s]
call putstr
.hang:
jmp .hang
.die_s:
db "TODO: unknown hypercall", 13, 10, 0
