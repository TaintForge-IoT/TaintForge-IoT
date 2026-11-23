/* Static i386 fixture. All branches are ordinary Linux processes. */
.macro payload
    mov $4, %eax
    mov $1, %ebx
    mov $message, %ecx
    mov $(message_end-message), %edx
    int $0x80
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
.endm

.section .text
.global _start
_start:
.ifdef MEMFD_SHARED
    mov $356, %eax
    mov $memfd_name, %ebx
    xor %ecx, %ecx
    int $0x80
    test %eax, %eax
    js failed
    mov %eax, %edi
    mov $93, %eax
    mov %edi, %ebx
    mov $4096, %ecx
    int $0x80
    test %eax, %eax
    jne failed
    mov $192, %eax
    xor %ebx, %ebx
    mov $4096, %ecx
    mov $3, %edx
    mov $1, %esi
    xor %ebp, %ebp
    int $0x80
    cmp $-4095, %eax
    jae failed
.ifdef RELEASE_SHARED
    mov %eax, %ebx
    mov $91, %eax
    mov $4096, %ecx
    int $0x80
    test %eax, %eax
    jne failed
.endif
    mov $6, %eax
    mov %edi, %ebx
    int $0x80
.endif
.ifdef SHARED_PAGE
    mov $192, %eax
    xor %ebx, %ebx
    mov $4096, %ecx
    mov $3, %edx
    mov $0x21, %esi
    mov $-1, %edi
    xor %ebp, %ebp
    int $0x80
.endif
    mov $125, %eax
    mov $payload_entry, %ebx
    mov $4096, %ecx
    mov $7, %edx
    int $0x80
    test %eax, %eax
    jne failed
.ifdef LATE_FORK
    movb $0xc3, prior_entry
    call prior_entry
.endif
.ifndef AFTER_ONLY
.ifndef CHILD_BUILD
    mov $template, %esi
    mov $payload_entry, %edi
    mov $(template_end-template), %ecx
    cld
    rep movsb
.endif
.endif
.ifdef NO_FORK
    jmp payload_entry
.endif
    mov $42, %eax
    mov $pipe_fds, %ebx
    int $0x80
    test %eax, %eax
    jne failed
.ifdef LIBC_CLONE
    mov $120, %eax
    mov $0x01200011, %ebx
    xor %ecx, %ecx
    mov $tid, %edi
.else
.ifdef VFORK
    mov $190, %eax
.else
    mov $2, %eax
.endif
.endif
    int $0x80
    test %eax, %eax
    js failed
    jz child
    mov %eax, %edi
    /* Corrupt the parent's private copy. The child waits for EOF, so it
     * always executes after this store, independently of scheduling. */
    movb $0xcc, payload_entry
.ifdef ROOT_FIRST
    /* Leave the last pipe writer open until the kernel tears down the parent. */
    xor %ebx, %ebx
    jmp exit
.endif
    mov $6, %eax
    mov pipe_fds+4, %ebx
    int $0x80
    mov $7, %eax
    mov %edi, %ebx
    mov $status, %ecx
    xor %edx, %edx
    int $0x80
    cmp %edi, %eax
    jne failed
.ifndef REPLAY_STATUS
    cmpl $0, status
    jne failed
.endif
.ifdef BOTH
    movb $0xb8, payload_entry
    jmp payload_entry
.endif
    xor %ebx, %ebx
    jmp exit
child:
.ifdef CHILD_FAULT
    ud2
.endif
.ifdef LIBC_CLONE
    mov $20, %eax
    int $0x80
    cmp %eax, tid
    jne failed
.endif
.ifdef CHILD_IDLE
    xor %ebx, %ebx
    jmp exit
.endif
    mov $6, %eax
    mov pipe_fds+4, %ebx
    int $0x80
    mov $3, %eax
    mov pipe_fds, %ebx
    mov $scratch, %ecx
    mov $1, %edx
    int $0x80
    test %eax, %eax
    jne failed
.ifdef ROOT_FIRST
    mov $162, %eax
    mov $delay, %ebx
    xor %ecx, %ecx
    int $0x80
.endif
.ifdef CHILD_BUILD
    mov $template, %esi
    mov $payload_entry, %edi
    mov $(template_end-template), %ecx
    cld
    rep movsb
.endif
.ifdef REPLAY_STATUS
    /* Only the packed stub reads this byte. Keep stdout and the parent's
     * return value identical to the rebuilt payload on all three paths. */
    mov $3, %eax
    xor %ebx, %ebx
    mov $scratch, %ecx
    mov $1, %edx
    int $0x80
    test %eax, %eax
    jz replay_normal
    mov $4, %eax
    mov $1, %ebx
    mov $message, %ecx
    mov $(message_end-message), %edx
    int $0x80
    cmpb $7, scratch
    mov $7, %ebx
    je exit
    mov $20, %eax
    int $0x80
    mov %eax, %ebx
    mov $9, %ecx
    mov $37, %eax
    int $0x80
    jmp failed
replay_normal:
.endif
.ifdef READ_ENTRY_BYTE
    mov $3, %eax
    xor %ebx, %ebx
    mov $(payload_entry+1), %ecx
    mov $1, %edx
    int $0x80
    cmp $1, %eax
    jne failed
.endif
.ifdef CHILD_REWRITE
    movb $4, payload_entry+1
.endif
.ifdef SECOND_FORK
    mov $2, %eax
    int $0x80
.endif
    jmp payload_entry
failed:
    mov $77, %ebx
exit:
    mov $1, %eax
    int $0x80

.balign 4096
.global payload_entry
payload_entry:
.ifdef AFTER_ONLY
    payload
.else
    .fill template_end-template, 1, 0xcc
.endif
message:
    .ascii "fork-child-ok\n"
message_end:
prior_entry: .byte 0xcc
.section .rodata
template:
    payload
template_end:
delay: .long 0, 50000000
memfd_name: .asciz "fork-fixture"
.section .bss
.balign 4
pipe_fds: .skip 8
status: .skip 4
tid: .skip 4
scratch: .skip 1
.section .note.GNU-stack,"",@progbits
