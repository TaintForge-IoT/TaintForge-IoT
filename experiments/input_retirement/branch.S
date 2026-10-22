.section .text
.global _start
_start:
    movl $125, %eax
    movl $payload_page, %ebx
    movl $4096, %ecx
    movl $3, %edx
    int $0x80
    testl %eax, %eax
    jne failed
    movl $payload_source, %esi
    movl $payload_entry, %edi
    movl $payload_end-payload_source, %ecx
copy:
    movb (%esi), %al
    movb %al, (%edi)
    incl %esi
    incl %edi
    decl %ecx
    jnz copy
    movl $125, %eax
    movl $5, %edx
    movl $4096, %ecx
    int $0x80
    testl %eax, %eax
    jne failed
    movl $payload_entry, %eax
    call *%eax
    cmpl $10000000, %edx
    jne failed
    movl $4, %eax
    movl $1, %ebx
    movl $ok, %ecx
    movl $ok_end-ok, %edx
    int $0x80
    cmpl $ok_end-ok, %eax
    jne failed
    xorl %ebx, %ebx
quit:
    movl $1, %eax
    int $0x80
failed:
    movl $77, %ebx
    jmp quit
.section .rodata
ok: .ascii "M3_BRANCH_OK\n"
ok_end:
payload_source:
    movl $20000000, %ecx
    xorl %edx, %edx
1:  testl $1, %ecx
    jz 2f
    incl %edx
2:  decl %ecx
    jnz 1b
    ret
payload_end:
.section .payload,"aw",@progbits
.balign 4096
payload_page:
payload_entry: .space 4096
.section .note.GNU-stack,"",@progbits
