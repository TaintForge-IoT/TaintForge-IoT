.section .text
.global _start
_start:
    cmpl $2, (%esp)
    jne fail
    movl 8(%esp), %esi
    movzbl (%esi), %esi
    cmpl $'s', %esi
    je shift_setup
    cmpl $'r', %esi
    je read_regular
    cmpl $'l', %esi
    je read_large
    cmpl $'c', %esi
    je close_setup
    cmpl $'m', %esi
    je mmap_setup
    cmpl $'x', %esi
    je xmm_start
    jmp fail

shift_setup:
    movl $0x76543211, %edi
    movl $0x1fedcba9, %ebp
    xorl %ecx, %ecx
    stc
shift_start:
    shrdl $32, %ebp, %edi
    jnc fail
    jnz fail
    cmpl $0x76543211, %edi
    jne fail
    shrdl $1, %ebp, %edi
    jnc fail
    jno fail
    cmpl $0xbb2a1908, %edi
    jne fail
    movl $0x87654321, %edi
    shrdl $12, %ebp, %edi
    cmpl $0xba987654, %edi
    jne fail
shift_done:
    jmp success

read_regular:
    movl $20, %edi
    jmp read_setup
read_large:
    movl $257, %edi
read_setup:
    movl $3, %eax
    xorl %ebx, %ebx
    movl $buffer, %ecx
    movl $8192, %edx
read_start:
    int $0x80
    cmpl %edi, %eax
    jne fail
    cmpl $20, %edi
    jne read_done
    cmpl $0x03020100, buffer
    jne fail
    cmpl $0x07060504, buffer+4
    jne fail
    cmpl $0x0b0a0908, buffer+8
    jne fail
    cmpl $0x0f0e0d0c, buffer+12
    jne fail
    cmpl $0x13121110, buffer+16
    jne fail
    cmpb $0x5a, buffer+20
    jne fail
    movl $3, %eax
    int $0x80
    testl %eax, %eax
    jne fail
read_done:
    jmp success

close_setup:
    movl $6, %eax
    movl $1, %ebx
close_start:
    int $0x80
    testl %eax, %eax
    jne fail
close_done:
    movl $6, %eax
close_again:
    int $0x80
    cmpl $-9, %eax
    jne fail
close_again_done:
    jmp success

mmap_setup:
    movl $192, %eax
    xorl %ebx, %ebx
    movl $4097, %ecx
    movl $3, %edx
    movl $0x22, %esi
    movl $-1, %edi
    xorl %ebp, %ebp
mmap_start:
    int $0x80
    cmpl $-4095, %eax
    jae fail
    testl $4095, %eax
    jnz fail
    cmpl $0, (%eax)
    jne fail
    cmpb $0, 8191(%eax)
    jne fail
    movl $0xa9876543, 4096(%eax)
    cmpl $0xa9876543, 4096(%eax)
    jne fail
mmap_done:
    jmp success

xmm_start:
    movd first_dword, %xmm1
    movl $0x11223344, %eax
    movd %eax, %xmm2
xmm_unpack:
    punpckldq %xmm2, %xmm1
    movq %xmm1, output
    cmpl $0xcafebabe, output
    jne fail
    cmpl $0x11223344, output+4
    jne fail
    movq two_dwords, %xmm3
    punpckldq %xmm3, %xmm3
    movq %xmm3, output
    cmpl $0x44332211, output
    jne fail
    cmpl $0x44332211, output+4
    jne fail
xmm_done:
    jmp success

fail:
    movl $1, %ebx
    jmp exit
success:
    xorl %ebx, %ebx
exit:
    movl $1, %eax
    int $0x80

.section .rodata
first_dword:
    .long 0xcafebabe
two_dwords:
    .long 0x44332211, 0x88776655

.section .data
.balign 8
output:
    .quad 0
buffer:
    .fill 8192, 1, 0x5a
