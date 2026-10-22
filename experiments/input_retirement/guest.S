/* Benign static i386 input for M3. Finite work, no controller handshake.
 * No production controller knows its labels or expected OEP address.
 * NEED_DIRECTORY=1 exercises a missing parent for O_CREAT after retirement.
 * NO_VERDICT=1 runs without unpacking; FORK_AFTER=1 tests the permanent guard.
 */
.section .text
.global _start
_start:
.if NO_VERDICT
    movl $20000000, %ecx
1:  loop 1b
.else
    movl $125, %eax
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
.endif
.if FORK_AFTER
    movl $2, %eax
    int $0x80
    jmp failed
.endif
.if NEED_DIRECTORY
    movl $5, %eax
    movl $filename, %ebx
    movl $65, %ecx               /* O_WRONLY | O_CREAT */
    movl $0600, %edx
    int $0x80
    testl %eax, %eax
    js missing
    movl %eax, %ebx
    movl $6, %eax
    int $0x80
.endif
    movl $4, %eax
    movl $1, %ebx
    movl $ok, %ecx
    movl $12, %edx
    int $0x80
    cmpl $12, %eax
    jne failed
    xorl %ebx, %ebx
    jmp quit
missing:
    movl $42, %ebx
    jmp quit
failed:
    movl $77, %ebx
quit:
    movl $1, %eax
    int $0x80
.section .rodata
filename: .asciz "/var/lib/taintforge-m3/output"
ok: .ascii "M3_INPUT_OK\n"
payload_source:
    pushl %ebp
    movl %esp, %ebp
    movl $20000000, %ecx
1:  testl $1, %ecx
    jz 2f
    nop
2:  loop 1b
    popl %ebp
    ret
payload_end:
.section .payload,"aw",@progbits
.balign 4096
payload_page: .space 4096
.section .note.GNU-stack,"",@progbits
