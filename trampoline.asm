use64

global trampoline_start
global trampoline_end

trampoline_start:
mov rdi, 0xdeadbeefdeadbeef ; cr3
mov rax, 0xdeadbeefdeadbeef ; entrypoint
mov rcx, 0xdeadbeefdeadbeef ; LAPIC base

%macro putchar 1
;mov r8, 0x80c1010100
;%%wait_uart:
;test dword [r8+12], 0x800
;jnz %%wait_uart
;mov dword [r8+4], %1
%endmacro

putchar '?'

; store the entrypoint (for later use)
mov [rel entry], rax

; get the uncached alias of the LAPIC base
mov rdx, 0x8000000000
lea rsi, [rcx+rdx]

; determine our own CPU id & add ourselves to the "cpu started" mask
mov eax, 11
cpuid
mov ecx, edx
mov eax, 1
shl eax, cl
lock xadd dword [rel cpu_mask], eax
test eax, eax
jnz .not_first_cpu

; "boot" cpu sends IPI to other cores, which are still running *BSD (for now)
; int1 is turned into int240 by the receiving LAPIC, which causes #GP and brings us here

xor eax, eax
mov ecx, 1
.ipi_loop:
cmp eax, 0x10000000
jae .not_first_cpu ; we're done
putchar '.'
test [rel cpu_mask], ecx
jnz .skip_current_cpu
.ipi_wait_loop:
test dword [rsi+0x300], 4096
jnz .ipi_wait_loop
mov [rsi+0x310], eax
mov dword [rsi+0x300], 0x40f0
.wait:
test [rel cpu_mask], ecx
jz .wait
putchar ' '
.skip_current_cpu:
add eax, 0x1000000
add ecx, ecx
jmp .ipi_loop

.not_first_cpu:
; wait for all CPUs to come up
cmp dword [rel cpu_mask], 0xffff
jne .not_first_cpu

; prepare arguments and jump to the real entrypoint
putchar ';'
xor eax, eax
xor ecx, ecx
xor edx, edx
xor ebx, ebx
xor ebp, ebp
xor esi, esi
xor r8d, r8d
xor r9d, r9d
xor r10d, r10d
xor r11d, r11d
xor r12d, r12d
xor r13d, r13d
xor r14d, r14d
xor r15d, r15d
jmp [rel entry]

align 4
cpu_mask:
dd 0

align 8
entry:
dq 0

trampoline_end:
times 4096-(trampoline_end-trampoline_start) db ""
