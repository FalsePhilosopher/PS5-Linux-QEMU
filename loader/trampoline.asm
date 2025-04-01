use64

global trampoline_start
global trampoline_end

trampoline_start:
jmp dword trampoline_entry
trampoline_entry:
; save passed parameters
mov [rel gdtr+2], rdx
mov [rel idtr+2], rcx
mov [rel stack], rsi
mov [rel retpoline], r8

; get pointer to local apic
mov ecx, 0x1b
rdmsr
and eax, 0xfffff000
shl rdx, 32
or rdx, rax

; copy cr3 to 0x9000
mov edi, 0x9000
mov rsi, cr3
mov [rel the_cr3], rsi
mov ecx, 512
rep movsq

; configure the realmode trampoline
add dword [rel trampoline_entry-4], ipi_entry - trampoline_entry + 2

; send ipis to other cores
mov eax, 0x1000000
mov esi, 0x4500
mov edi, 0x4608
.the_loop:
test dword [rdx+0x300], 0x1000
jnz .the_loop
mov [rdx+0x310], eax
mov [rdx+0x300], esi
mov ecx, 1000000
.small_wait:
loop .small_wait
.inner_loop:
test dword [rdx+0x300], 0x1000
jnz .inner_loop
mov [rdx+0x310], eax
mov [rdx+0x300], edi
add eax, 0x1000000
cmp eax, 0x10000000
jb .the_loop

; initialize the current core
core_init:
mov ecx, 0xc0000080 ; IA32_EFER
rdmsr
or eax, 0x801
wrmsr
mov eax, 11
cpuid
mov eax, edx
imul eax, eax, 10
lea rbp, [rel gdtr]
mov rcx, [rbp+2]
imul edx, edx, 0x68
add rcx, rdx
mov [rbp+rax+2], rcx
lgdt [rbp+rax]
lidt [rel idtr]
mov eax, 0x48
ltr ax
xor eax, eax
mov ds, ax
mov es, ax
mov ss, ax
mov fs, ax
mov gs, ax
lea rsp, [rel stack]
mov al, 0xff
out 0x21, al
out 0xa1, al
xor eax, eax
xor ecx, ecx
xor edx, edx
xor ebx, ebx
xor ebp, ebp
xor esi, esi
mov rdi, cr3
jmp qword [rel retpoline]
stack:
dq 0
dq 0x43
dq 0x3002
dq 0
dq 0x3b
gdtr:
%rep 16
dw 0x67
dq 0
%endrep
idtr:
dw 0xfff
dq 0
the_cr3:
dq 0
retpoline:
dq 0

ipi_entry:
use16
jmp 0:0x8000 + (.cont - trampoline_start)
.cont:
cli
mov ax, cs
mov ds, ax
mov es, ax
mov fs, ax
mov gs, ax
lgdt [0x8000+(temp_gdtr - trampoline_start)]
mov ecx, 0xc0000080
rdmsr
or eax, 0x500
wrmsr
mov eax, 0x9000
mov cr3, eax
mov eax, cr4
or eax, 32
mov cr4, eax
mov eax, cr0
or eax, 0x80000003
mov cr0, eax
jmp 8:0x8000 + (.cont2 - trampoline_start)
.cont2:
use64
mov rax, [rel the_cr3]
mov cr3, rax
jmp core_init

temp_gdtr:
dw 15
dd 0x8000 + (temp_gdt - trampoline_start)

temp_gdt:
dq 0
db 0xff, 0xff, 0, 0, 0, 0x9a, 0xaf, 0

trampoline_end:
