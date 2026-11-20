
.section .rodata
.balign 4
target_word: .long payload_page
input_name: .asciz "/etc/afl-input"
.global payload_source, payload_end, branch_one, branch_two
payload_source:
    movl $64, %ecx
handoff_work:
    decl %ecx
    jnz handoff_work
    movl $5, %eax
    movl $input_name, %ebx
    xorl %ecx, %ecx
    int $0x80
    testl %eax, %eax
    js failed_input
    movl %eax, %esi
    movl %eax, %ebx
    movl $3, %eax
    movl $buffer, %ecx
    movl $4096, %edx
    int $0x80
    testl %eax, %eax
    jle failed_input
    movl %eax, %ebp
    xorl %edi, %edi
    cmpb $65, buffer
branch_one:
    jne emit_result
    incl %edi
    cmpl $2, %ebp
    jl emit_result
    cmpb $70, buffer+1
branch_two:
    jne emit_result
    incl %edi
    cmpl $3, %ebp
    jl emit_result
    cmpb $76, buffer+2
    jne emit_result
    incl %edi
    cmpl $4, %ebp
    jl emit_result
    cmpb $33, buffer+3
    jne emit_result
    incl %edi
emit_result:
    movl %edi, %eax
    movb %al, output_byte
    movl %esi, %ebx
    movl $6, %eax
    int $0x80
    movl $4, %eax
    movl $1, %ebx
    movl $output_byte, %ecx
    movl $1, %edx
    int $0x80
    movl %edi, %ebx
    movl $1, %eax
    int $0x80
failed_input:
    movl $78, %ebx
    movl $1, %eax
    int $0x80
payload_end:
    .space 512, 0x90

.section .text
.global _start, hybrid_ir_start
_start:
    /* Register the executable mapping before copying the fixed payload.
     * The same startup runs under DTA, file DSE and warm AFL. */
    movl $125, %eax
    movl $payload_page, %ebx
    movl $4096, %ecx
    movl $7, %edx
    int $0x80
    testl %eax, %eax
    jne failed_entry
    .set copy_offset, 0
    .rept 128
    movl payload_source+copy_offset, %eax
    movl %eax, payload_page+copy_offset
    .set copy_offset, copy_offset+4
    .endr
    movl target_word, %eax
hybrid_ir_start:
    cmpl $payload_page, %eax
    jne failed_entry
    jmp *%eax
failed_entry:
    movl $77, %ebx
    movl $1, %eax
    int $0x80

/* Fixed benign test code is copied without an mprotect syscall before input.
 * This test-only RWX segment is recorded in the fixture manifest. */
.section .payload,"awx",@progbits
.balign 4096
.global payload_page
payload_page: .space 4096
.section .bss
buffer: .space 4096
output_byte: .space 1
.section .note.GNU-stack,"",@progbits
