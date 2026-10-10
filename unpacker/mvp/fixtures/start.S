.section .text.start,"ax"
.global _start
.type _start,@function
_start:
    xorl %ebp, %ebp
    movl (%esp), %eax
    leal 4(%esp), %edx
    andl $-16, %esp
    subl $8, %esp
    pushl %edx
    pushl %eax
    call fixture_entry
    ud2
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
