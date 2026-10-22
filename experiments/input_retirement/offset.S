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
    movl $payload_end-1, %esi
    movl $payload_entry+(payload_end-payload_source)-1, %edi
    movl $payload_end-payload_source, %ecx
copy:
    movb (%esi), %al
    movb %al, (%edi)
    decl %esi
    decl %edi
    decl %ecx
    jnz copy
    movl $125, %eax
    movl $4096, %ecx
    movl $5, %edx
    int $0x80
    testl %eax, %eax
    jne failed
    movl $payload_entry, %eax
    call *%eax
    cmpl $40000000, %eax
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
ok: .ascii "M3_OFFSET_OK\n"
ok_end:
payload_source:
    xorl %eax, %eax
    movl $20000000, %ecx
1:  call 2f
    decl %ecx
    jnz 1b
    ret
2:  addl $2, %eax
    ret
payload_end:
.section .payload,"aw",@progbits
.balign 4096
payload_page: .space 256
payload_entry: .space 3840
.section .note.GNU-stack,"",@progbits
