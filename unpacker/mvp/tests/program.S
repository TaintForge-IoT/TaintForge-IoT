.section .rodata
short_message: .ascii "SHORT\n"
accept_message: .ascii "ACCEPT\n"
reject_message: .ascii "REJECT\n"
state_message: .ascii "BADSTATE\n"
file_name: .asciz "input.bin"
reference_table: .incbin "table.bin"

.section .text
.global _start
_start:
    cmpl $TABLE_MAGIC, reference_table
    jne bad_state
    cmpl $0, run_count
    jne bad_state
    incl run_count
    mov $3, %eax
    xor %ebx, %ebx
.if VARIANT == 1
    mov $5, %eax
    mov $file_name, %ebx
    xor %ecx, %ecx
    xor %edx, %edx
    int $0x80
    test %eax, %eax
    js short_input
    mov %eax, %ebx
    mov $3, %eax
.endif
    mov $input_buffer, %ecx
    mov $64, %edx
    int $0x80
    test %eax, %eax
    js short_input
.if VARIANT == 0
    mov %eax, %edx
    mov $input_buffer, %ecx
    xor %edi, %edi
    jmp emit
.elseif VARIANT == 1
    cmp $5, %eax
    jl short_input
    cmpl $0x3a474643, input_buffer
    jne reject
    movzbl input_buffer+4, %eax
    sub $48, %eax
    cmp $9, %eax
    ja reject
    jmp accept
.else
    cmp $4, %eax
    jl short_input
    cmpw $0x4654, input_buffer
    jne reject
    movzbl input_buffer+2, %eax
    movzbl input_buffer+3, %edx
    add %edx, %eax
    cmp $100, %eax
    jne reject
.endif
accept:
    mov $accept_message, %ecx
    mov $7, %edx
    xor %edi, %edi
    jmp emit
reject:
    mov $reject_message, %ecx
    mov $7, %edx
    mov $1, %edi
    jmp emit
short_input:
    mov $short_message, %ecx
    mov $6, %edx
    mov $2, %edi
    jmp emit
bad_state:
    mov $state_message, %ecx
    mov $9, %edx
    mov $4, %edi
emit:
    mov $4, %eax
    mov $1, %ebx
    int $0x80
    mov $1, %eax
    mov %edi, %ebx
    int $0x80
    .fill 8192, 1, 0x90

.section .data
    .long 0x13579bdf
.section .bss
.global run_count
run_count: .skip 4
input_buffer: .skip 64
.section .note.GNU-stack,"",@progbits
