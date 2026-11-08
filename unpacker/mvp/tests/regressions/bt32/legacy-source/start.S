.section .text.start,"ax",@progbits
.global _start
.type _start,@function
_start:
    xorl %ebp, %ebp
    andl $-16, %esp
    call target_main
    ud2
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
