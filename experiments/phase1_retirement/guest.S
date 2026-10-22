/* SPDX-License-Identifier: GPL-2.0-or-later
 * Benign Linux i386 ET_EXEC, no libc, no threads, no network.
 * Observation NOPs are branch targets after completed syscalls.
 */
.section .text
.global _start, capsule_point_one, capsule_point_two
.macro check_stack
    cmpl $0x11223344, 0(%esp)
    jne failed
    cmpl $0x55667788, 4(%esp)
    jne failed
    cmpl $0x99aabbcc, 8(%esp)
    jne failed
    cmpl %edi, 12(%esp)
    jne failed
    cmpl %esi, 16(%esp)
    jne failed
    cmpl %esp, 20(%esp)
    jne failed
    cmpl $0xdeadbeef, 24(%esp)
    jne failed
    cmpl $0xcafebabe, 28(%esp)
    jne failed
    cmpl %esp, %ebp
    jne failed
.endm
_start:
    /* A small benign unpacker: copy an actual function into a separate page,
     * make it executable and enter by an indirect call. Phase 1 must detect
     * and select the candidate itself; there is no forced OEP option. */
    movl $125, %eax
    movl $phase1_payload_entry, %ebx
    movl $4096, %ecx
    movl $3, %edx
    int $0x80
    testl %eax, %eax
    jne failed
    movl $payload_source, %esi
    movl $phase1_payload_entry, %edi
    movl $payload_end-payload_source, %ecx
    cld
    rep movsb
    movl $125, %eax
    movl $phase1_payload_entry, %ebx
    movl $4096, %ecx
    movl $5, %edx
    int $0x80
    testl %eax, %eax
    jne failed
    movl $phase1_payload_entry, %eax
    call *%eax
    call exercise
    movl $4, %eax
    movl $1, %ebx
    movl $ok, %ecx
    movl $11, %edx
    int $0x80
    cmpl $11, %eax
    jne failed
    xorl %ebx, %ebx
    jmp quit
exercise:
    subl $32, %esp
    movl %esp, %ebp
    movl $5, %eax                 /* open, exclusively in fresh case cwd */
    movl $filename, %ebx
    movl $194, %ecx               /* O_RDWR | O_CREAT | O_EXCL */
    movl $0600, %edx
    int $0x80
    testl %eax, %eax
    js failed
    movl %eax, %edi
    movl $20, %eax                /* getpid */
    int $0x80
    movl %eax, %esi
    movl $0x11223344, 0(%esp)
    movl $0x55667788, 4(%esp)
    movl $0x99aabbcc, 8(%esp)
    movl %edi, 12(%esp)
    movl %esi, 16(%esp)
    movl %esp, 20(%esp)
    movl $0xdeadbeef, 24(%esp)
    movl $0xcafebabe, 28(%esp)
    movl $4, %eax
    movl %edi, %ebx
    movl $before, %ecx
    movl $7, %edx
    int $0x80
    cmpl $7, %eax
    jne failed
    movl $0x11111111, %eax
    movl $capsule_buffer, %ecx
    movl $16, %edx
    jmp capsule_point_one
capsule_point_one:
    nop
.global phase1_retire_boundary
phase1_retire_boundary:
    nop
    cmpl $0x11111111, %eax
    jne failed
    check_stack
    movl $20, %eax
    int $0x80
    cmpl %esi, %eax
    jne failed
    movl $19, %eax                /* lseek(fd, 0, SEEK_CUR) */
    movl %edi, %ebx
    xorl %ecx, %ecx
    movl $1, %edx
    int $0x80
    cmpl $7, %eax
    jne failed
    movl $4, %eax
    movl $between, %ecx
    movl $8, %edx
    int $0x80
    cmpl $8, %eax
    jne failed
    movl $0x63646566, capsule_buffer
    movl $0x38396162, capsule_buffer+4
    movl $0x34353637, capsule_buffer+8
    movl $0x30313233, capsule_buffer+12
    movl $20, %eax                /* completed syscall before next TB */
    int $0x80
    cmpl %esi, %eax
    jne failed
    movl $0x22222222, %eax
    movl $capsule_buffer, %ecx
    movl $16, %edx
    jmp capsule_point_two
capsule_point_two:
    nop
    cmpl $0x22222222, %eax
    jne failed
    check_stack
    movl $19, %eax
    movl %edi, %ebx
    xorl %ecx, %ecx
    movl $1, %edx
    int $0x80
    cmpl $15, %eax
    jne failed
    movl $4, %eax
    movl $after, %ecx
    movl $6, %edx
    int $0x80
    cmpl $6, %eax
    jne failed
    movl $19, %eax
    xorl %ecx, %ecx
    xorl %edx, %edx
    int $0x80
    testl %eax, %eax
    jne failed
    movl $3, %eax
    movl $readback, %ecx
    movl $21, %edx
    int $0x80
    cmpl $21, %eax
    jne failed
    check_stack
    movl $readback, %esi
    movl $expected_file, %edi
    movl $21, %ecx
    cld
    repe cmpsb
    jne failed
    movl 12(%esp), %ebx
    movl $6, %eax
    int $0x80
    testl %eax, %eax
    jne failed
    addl $32, %esp
    ret
failed:
    movl $77, %ebx
quit:
    movl $1, %eax
    int $0x80
.section .rodata
filename: .asciz "capsule-fd.txt"
before: .ascii "before\n"
between: .ascii "between\n"
after: .ascii "after\n"
expected_file: .ascii "before\nbetween\nafter\n"
ok: .ascii "CAPSULE_OK\n"
.section .data
.global capsule_buffer
capsule_buffer: .ascii "0123456789ABCDEF"
.section .bss
readback: .skip 21
.section .note.GNU-stack,"",@progbits

.section .rodata
payload_source:
    pushl %ebp
    movl %esp, %ebp
    movl $64, %ecx
1:  nop
    loop 1b
    popl %ebp
    ret
payload_end:
.section .phase1_payload,"aw",@progbits
.balign 4096
.global phase1_payload_entry
phase1_payload_entry: .space 4096
