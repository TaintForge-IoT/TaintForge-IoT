/* Benign unpacking i386 fixture. Every input path exits normally.
 * Production: /etc/afl-input and /tmp/afl-marker; optional argv paths are
 * used only by component tests, which never claim M4 retirement.
 */
.section .text
.global _start
_start:
    movl $input_name, input_pointer
    movl $marker_name, marker_pointer
    cmpl $2, (%esp)
    jl 1f
    movl 8(%esp), %eax
    movl %eax, input_pointer
    cmpl $3, (%esp)
    jl 1f
    movl 12(%esp), %eax
    movl %eax, marker_pointer
    cmpl $4, (%esp)
    jl 1f
    /* Component oracle: one append for the original preparation, never for
     * each post-checkpoint child. No open descriptor survives this operation. */
    movl 16(%esp), %ebx
    movl $5, %eax
    movl $1089, %ecx /* O_WRONLY | O_CREAT | O_APPEND */
    movl $0600, %edx
    int $0x80
    testl %eax, %eax
    js failed
    movl %eax, %ebx
    movl $4, %eax
    movl $prepared_byte, %ecx
    movl $1, %edx
    int $0x80
    movl $6, %eax
    int $0x80
1:  movl $125, %eax
    movl $payload_page, %ebx
    movl $4096, %ecx
    movl $3, %edx
    int $0x80
    testl %eax, %eax
    jne failed
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
    jne failed
    movl $payload_page, %eax
    call *%eax
    xorl %ebx, %ebx
    jmp quit
failed:
    movl $77, %ebx
quit:
    movl $1, %eax
    int $0x80

.section .rodata
input_name: .asciz "/etc/afl-input"
marker_name: .asciz "/tmp/afl-marker"
prepared_byte: .byte 80
payload_source:
    movl $WORK_LOOPS, %ecx
1:  testl $1, %ecx
    jz 2f
    nop
2:  loop 1b
    movl $5, %eax
    movl input_pointer, %ebx
    xorl %ecx, %ecx
    int $0x80
    testl %eax, %eax
    js 9f
    movl %eax, %ebx
    movl $3, %eax
    movl $buffer, %ecx
    movl $4096, %edx
    int $0x80
    testl %eax, %eax
    jle 9f
    incl mutation_counter
    cmpl $1, mutation_counter
    jne 9f
    pushl %ebx
    /* An existing marker makes a dirty environment observable to the test. */
    movl $5, %eax
    movl marker_pointer, %ebx
    movl $193, %ecx /* O_WRONLY | O_CREAT | O_EXCL */
    movl $0600, %edx
    int $0x80
    testl %eax, %eax
    js 9f
    movl %eax, %ebx
    movl $6, %eax
    int $0x80
    popl %ebx

.if !CONSTANT_PATH
    cmpb $65, buffer
    jne 3f
    movl $1, %edi
    cmpb $70, buffer+1
    jne 5f
    movl $2, %edi
    cmpb $76, buffer+2
    jne 5f
    movl $3, %edi
    cmpb $33, buffer+3
    jne 5f
    movl $4, %edi
    jmp 5f
3:  cmpb $66, buffer
    jne 4f
    movl $5, %edi
    jmp 5f
4:  movl $6, %edi
5:
.endif
    movl $6, %eax
    int $0x80
    ret
9:  movl $78, %ebx
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
mutation_counter: .space 4
buffer: .space 4096
.section .note.GNU-stack,"",@progbits
