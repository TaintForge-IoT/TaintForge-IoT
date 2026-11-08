.section .text
.globl _start
.type _start, @function
_start:
    cld
    movl (%esp), %eax
    movl $input_path, %ebx
    cmpl $2, %eax
    jb 1f
    movl 8(%esp), %ebx
1:  andl $-16, %esp
    movl $5, %eax
    xorl %ecx, %ecx
    xorl %edx, %edx
    int $0x80
    testl %eax, %eax
    js .Lerror
    movl %eax, %ebx
    movl $3, %eax
    movl $input_buffer, %ecx
    movl $16, %edx
    int $0x80
    testl %eax, %eax
    jle .Lerror
    subl $8, %esp
    pushl %eax
    pushl $input_buffer
    call tf_kernel
    addl $16, %esp
    cmpl $TF_COMPARE, %eax
.globl tf_probe_jcc
tf_probe_jcc:
    jne tf_probe_taken
.globl tf_probe_fallthrough
tf_probe_fallthrough:
    movl $token_false, %ecx
    jmp .Lwrite
.globl tf_probe_taken
tf_probe_taken:
    movl $token_true, %ecx
.Lwrite:
    movl $4, %eax
    movl $1, %ebx
    movl $2, %edx
    int $0x80
    xorl %ebx, %ebx
    jmp .Lexit
.Lerror:
    movl $80, %ebx
.Lexit:
    movl $1, %eax
    int $0x80
.size _start, .-_start
.section .rodata
input_path: .asciz "/etc/dta-input"
token_false: .ascii "F\n"
token_true: .ascii "T\n"
.section .bss
.balign 16
input_buffer: .skip 16
.section .note.GNU-stack,"",@progbits
