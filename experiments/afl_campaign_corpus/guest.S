/* Benign self-copying parsers; fault controls are enabled separately. */
.section .text
.global _start
_start:
    movl $input_name, input_pointer
    movl $marker_name, marker_pointer
    movl $prepared_name, prepared_pointer
    cmpl $2, (%esp)
    jl paths_ready
    movl 8(%esp), %eax
    movl %eax, input_pointer
    cmpl $3, (%esp)
    jl paths_ready
    movl 12(%esp), %eax
    movl %eax, marker_pointer
    cmpl $4, (%esp)
    jl paths_ready
    movl 16(%esp), %eax
    movl %eax, prepared_pointer
paths_ready:
    movl $5, %eax
    movl prepared_pointer, %ebx
    movl $1089, %ecx
    movl $0600, %edx
    int $0x80
    testl %eax, %eax
    js startup_failed
    movl %eax, %ebx
    movl $4, %eax
    movl $prepared_byte, %ecx
    movl $1, %edx
    int $0x80
    cmpl $1, %eax
    jne startup_failed
    movl $6, %eax
    int $0x80
.if LEAK_FD
    movl $5, %eax
    movl prepared_pointer, %ebx
    xorl %ecx, %ecx
    int $0x80
    testl %eax, %eax
    js startup_failed
.endif
    movl $PREP_LOOPS, %ecx
    testl %ecx, %ecx
    jz unpack
preparation_loop:
    decl %ecx
    jnz preparation_loop
unpack:
    movl $125, %eax
    movl $payload_page, %ebx
    movl $4096, %ecx
    movl $3, %edx
    int $0x80
    testl %eax, %eax
    jne startup_failed
    movl $payload_source, %esi
    movl $payload_page, %edi
    movl $payload_end-payload_source, %ecx
    cld
    rep movsb
    movl $125, %eax
    movl $payload_page, %ebx
    movl $4096, %ecx
    movl $5, %edx
    int $0x80
    testl %eax, %eax
    jne startup_failed
    movl $payload_page, %eax
    call *%eax
startup_failed:
    movl $97, %ebx
    movl $1, %eax
    int $0x80
.section .rodata
input_name: .asciz "/etc/afl-input"
marker_name: .asciz "/tmp/afl-marker"
prepared_name: .asciz "/tmp/afl-prepared"
prepared_byte: .byte 80
marker_byte: .byte 75
payload_source:
    /* Let Phase 1 select the OEP before yielding to the observer. */
    movl $1000, %ecx
retirement_window:
    decl %ecx
    jnz retirement_window
    movl $5, %eax
    movl input_pointer, %ebx
    xorl %ecx, %ecx
    int $0x80
    testl %eax, %eax
    js child_failed
    movl %eax, %ebx
    movl $3, %eax
    movl $buffer, %ecx
    movl $4096, %edx
    int $0x80
    testl %eax, %eax
    jle child_failed
    movl %eax, %ebp
    movl $6, %eax
    int $0x80
    incl mutation_counter
    cmpl $1, mutation_counter
    jne dirty_memory
    movl $5, %eax
    movl marker_pointer, %ebx
    movl $193, %ecx
    movl $0600, %edx
    int $0x80
    testl %eax, %eax
    js dirty_filesystem
    movl %eax, %ebx
    movl $4, %eax
    movl $marker_byte, %ecx
    movl $1, %edx
    int $0x80
    cmpl $1, %eax
    jne child_failed
    movl $6, %eax
    int $0x80
.if ENABLE_FAULTS
    cmpb $67, buffer
    jne check_segv
    ud2
check_segv:
    cmpb $83, buffer
    jne check_abort
    xorl %eax, %eax
    movl $1, (%eax)
check_abort:
    cmpb $66, buffer
    jne check_hang
    movl $20, %eax
    int $0x80
    movl %eax, %ebx
    movl $6, %ecx
    movl $37, %eax
    int $0x80
    jmp child_failed
check_hang:
    cmpb $72, buffer
    jne check_exit
hang:
    jmp hang
check_exit:
    cmpb $69, buffer
    jne parse
    movl $86, %ebx
    jmp emit
.endif
parse:
.if RECORD_PARSER
    movl $20, %ebx
    cmpl $2, %ebp
    jl emit
    movzbl buffer+1, %edx
    addl $2, %edx
    movl $21, %ebx
    cmpl %ebp, %edx
    jne emit
    cmpb $1, buffer
    je sum_record
    cmpb $2, buffer
    je text_record
    movl $22, %ebx
    jmp emit
sum_record:
    xorl %eax, %eax
    movl $2, %ecx
sum_loop:
    cmpl %ebp, %ecx
    jge sum_done
    movzbl buffer(%ecx), %edx
    addl %edx, %eax
    incl %ecx
    jmp sum_loop
sum_done:
    andl $15, %eax
    leal 32(%eax), %ebx
    jmp emit
text_record:
    movl $48, %ebx
    cmpl $2, %ebp
    je emit
    cmpb $88, buffer+2
    jne emit
    incl %ebx
.else
    xorl %ebx, %ebx
    cmpb $65, buffer
    jne emit
    incl %ebx
    cmpl $2, %ebp
    jl emit
    cmpb $70, buffer+1
    jne emit
    incl %ebx
    cmpl $3, %ebp
    jl emit
    cmpb $76, buffer+2
    jne emit
    incl %ebx
    cmpl $4, %ebp
    jl emit
    cmpb $33, buffer+3
    jne emit
    incl %ebx
.endif
emit:
    movb %bl, output_byte
    movl %ebx, %edi
    movl $4, %eax
    movl $1, %ebx
    movl $output_byte, %ecx
    movl $1, %edx
    int $0x80
    cmpl $1, %eax
    jne child_failed
    movl %edi, %ebx
    jmp child_exit
dirty_memory:
    movl $98, %ebx
    jmp child_exit
dirty_filesystem:
    movl $99, %ebx
    jmp child_exit
child_failed:
    movl $97, %ebx
child_exit:
    movl $1, %eax
    int $0x80
payload_end:
.section .payload,"aw",@progbits
.balign 4096
payload_page: .space 4096
.section .bss
.balign 4
input_pointer: .space 4
marker_pointer: .space 4
prepared_pointer: .space 4
mutation_counter: .space 4
output_byte: .space 1
buffer: .space 4096
.section .note.GNU-stack,"",@progbits
