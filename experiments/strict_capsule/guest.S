.section .rodata
.balign 4
.global target_word
target_word: .long payload_page
input_name: .asciz "/etc/afl-input"
marker_name: .asciz "/tmp/afl-marker"
payload_source:
    movl $STRICT_HANDOFF_LOOPS, %ecx
payload_work:
    subl $1, %ecx
    jnz payload_work
payload_input:
    movl $5, %eax
    movl $input_name, %ebx
    xorl %ecx, %ecx
    int $0x80
    testl %eax, %eax
    js payload_failed
    movl %eax, %ebx
    movl $3, %eax
    movl $input_buffer, %ecx
    movl $4096, %edx
    int $0x80
    testl %eax, %eax
    jle payload_failed
    movl $6, %eax
    int $0x80
    cmpb $65, input_buffer
    jne payload_other
    movl $1, %edi
    jmp payload_marker
payload_other:
    movl $2, %edi
payload_marker:
    movl $5, %eax
    movl $marker_name, %ebx
    movl $193, %ecx
    movl $0600, %edx
    int $0x80
    testl %eax, %eax
    js payload_failed
    movl %eax, %ebx
    movl $6, %eax
    int $0x80
    xorl %ebx, %ebx
    movl $1, %eax
    int $0x80
payload_failed:
    movl $78, %ebx
    movl $1, %eax
    int $0x80
    .balign 4, 0x90
payload_end:
    .space 512, 0x90

.section .text
.global _start, strict_ir_start
_start:
    movl $125, %eax
    movl $payload_page, %ebx
    movl $4096, %ecx
    movl $3, %edx
    int $0x80
    testl %eax, %eax
    jne failed
    .set copy_offset, 0
    .rept 128
    movl payload_source+copy_offset, %eax
    movl %eax, payload_page+copy_offset
    .set copy_offset, copy_offset+4
    .endr
    movl $125, %eax
    movl $payload_page, %ebx
    movl $4096, %ecx
    movl $5, %edx
    int $0x80
    testl %eax, %eax
    jne failed
    movl target_word, %eax
strict_ir_start:
.if STRICT_NEGATIVE
    nop
.else
    cmpl $payload_page, %eax
    jne failed
.endif
    jmp *%eax
failed:
    movl $77, %ebx
    movl $1, %eax
    int $0x80

.section .payload,"aw",@progbits
.balign 4096
.global payload_page
payload_page: .space 4096
.section .bss
.balign 4
input_buffer: .space 4096
.section .note.GNU-stack,"",@progbits
