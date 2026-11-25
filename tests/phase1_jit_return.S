/* A helper returns 6 * 7. A payload exits with the same result. In REENTER
 * mode the same entry point changes behavior on its second invocation. */
.text
.global _start
_start:
    mov $192, %eax          /* mmap2(NULL, 4096, RW, PRIVATE|ANON, -1, 0) */
    xor %ebx, %ebx
    mov $4096, %ecx
    mov $3, %edx
    mov $0x22, %esi
    mov $-1, %edi
    xor %ebp, %ebp
    int $0x80
    cmp $-4095, %eax
    jae fail
    mov %eax, %edi
    push %eax               /* Publish the guest-chosen target address. */
    mov $4, %eax
    mov $1, %ebx
    mov %esp, %ecx
    mov $4, %edx
    int $0x80
    add $4, %esp
    cmp $4, %eax
    jne fail

    movl $0x000006b8, (%edi)      /* mov $6,%eax; imul $7,%eax */
    movl $0x07c06b00, 4(%edi)
.if REENTER
    movl $0x0175f685, 8(%edi)     /* test %esi,%esi; jnz payload */
    movb $0xc3, 12(%edi)
    .set payload_offset, 13
.elseif RETURNS
    movb $0xc3, 8(%edi)           /* ret */
.else
    .set payload_offset, 8
.endif
.if REENTER || !RETURNS
    movl $0x01b8c389, payload_offset(%edi)    /* mov %eax,%ebx; mov $1,%eax; int $0x80 */
    movl $0xcd000000, payload_offset+4(%edi)
    movb $0x80, payload_offset+8(%edi)
.endif
    mov $125, %eax          /* mprotect(page, 4096, RX) */
    mov %edi, %ebx
    mov $4096, %ecx
    mov $5, %edx
    int $0x80
    test %eax, %eax
    jne fail
    xor %esi, %esi
invoke:
.if TAIL
    call dispatch
.else
    call *%edi
.endif
.if REENTER
    cmp $42, %eax
    jne fail
    test %esi, %esi
    jnz fail
    inc %esi
    jmp invoke
.endif
    mov %eax, %ebx
    jmp exit
dispatch:
    jmp *%edi
fail:
    mov $99, %ebx
exit:
    mov $1, %eax
    int $0x80
.section .note.GNU-stack,"",@progbits
