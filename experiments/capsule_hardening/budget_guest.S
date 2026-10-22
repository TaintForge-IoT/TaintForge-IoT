.equ PAYLOAD_BYTES, (1+511*LARGE_EXPORT)*4096
.section .text
.global _start
_start:
    mov $125,%eax
    mov $payload_page,%ebx
    mov $PAYLOAD_BYTES,%ecx
    mov $3,%edx
    int $0x80
    test %eax,%eax
    jne failed
.if LARGE_EXPORT
    mov $payload_page,%edi
    mov $512,%ecx
fill:
    movb $0,(%edi)
    add $4096,%edi
    loop fill
.endif
    mov $payload_source,%esi
    mov $payload_page,%edi
    mov $payload_end-payload_source,%ecx
    cld
    rep movsb
    mov $125,%eax
    mov $payload_page,%ebx
    mov $PAYLOAD_BYTES,%ecx
    mov $5,%edx
    int $0x80
    test %eax,%eax
    jne failed
    mov $payload_page,%eax
    call *%eax
.if LARGE_JOURNAL
    mov $4,%eax
    mov $1,%ebx
    mov $journal_data,%ecx
    mov $2097152,%edx
    int $0x80
    cmp $2097152,%eax
    jne failed
.endif
    mov $4,%eax
    mov $1,%ebx
    mov $ok,%ecx
    mov $12,%edx
    int $0x80
    cmp $12,%eax
    jne failed
    xor %ebx,%ebx
    jmp quit
failed:
    mov $77,%ebx
quit:
    mov $1,%eax
    int $0x80
.section .rodata
ok: .ascii "M3_INPUT_OK\n"
payload_source:
    push %ebp
    mov %esp,%ebp
    mov $20000000,%ecx
1:  test $1,%ecx
    jz 2f
    nop
2:  loop 1b
    pop %ebp
    ret
payload_end:
.section .payload,"aw",@nobits
.balign 4096
payload_page: .space PAYLOAD_BYTES
.if LARGE_JOURNAL
.section .journal,"aw",@nobits
.balign 4096
journal_data: .space 2097152
.endif
.section .note.GNU-stack,"",@progbits
