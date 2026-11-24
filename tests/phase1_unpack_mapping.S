/* Single-process i386 workload with a private mapping outside the selected image. */
.equ data_base, 0x24000000
.equ data_length, 0x2345
.section .text
.global _start
_start:
    mov $192, %eax
    mov $data_base, %ebx
    mov $data_length, %ecx
    mov $3, %edx
    mov $0x32, %esi
    mov $-1, %edi
    xor %ebp, %ebp
    int $0x80
    cmp $data_base, %eax
    jne failed
.ifdef SEEDED
    mov $3, %eax
    xor %ebx, %ebx
    mov $(data_base+0x2008), %ecx
    mov $1, %edx
    int $0x80
.endif
    mov $125, %eax
    mov $entry, %ebx
    mov $4096, %ecx
    mov $7, %edx
    int $0x80
    test %eax, %eax
    jne failed
    mov $template, %esi
    mov $entry, %edi
    mov $(template_end-template), %ecx
    cld
    rep movsb
    jmp entry
failed:
    mov $77, %ebx
    mov $1, %eax
    int $0x80

.balign 4096
entry:
    .fill template_end-template, 1, 0xcc
.section .rodata
template:
    mov $4, %eax
    mov $1, %ebx
    mov $entry, %ecx
    xor %edx, %edx
    int $0x80
    xor %ebx, %ebx
.ifndef HEALTHY
    mov $(data_base+0x2000), %edi
    mov 8(%edi), %ebx
.endif
.ifdef STACK_IO
    push %ebx
    sub $4, %esp
    mov $3, %eax
    xor %ebx, %ebx
    mov %esp, %ecx
    mov $1, %edx
    int $0x80
    add $4, %esp
    pop %ebx
.endif
    mov $1, %eax
    int $0x80
template_end:
