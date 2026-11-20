.section .text
.global _start
_start:
    mov $results, %edi
    cld
    movl $0, %eax
    addl $0, %eax
.global flag_boundary_0
flag_boundary_0:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $2147483647, %eax
    addl $1, %eax
.global flag_boundary_1
flag_boundary_1:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $4294967295, %eax
    addl $1, %eax
.global flag_boundary_2
flag_boundary_2:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $2147483648, %eax
    addl $2147483648, %eax
.global flag_boundary_3
flag_boundary_3:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $15, %eax
    addl $1, %eax
.global flag_boundary_4
flag_boundary_4:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $16, %eax
    addl $1, %eax
.global flag_boundary_5
flag_boundary_5:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $127, %eax
    addl $1, %eax
.global flag_boundary_6
flag_boundary_6:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $255, %eax
    addl $1, %eax
.global flag_boundary_7
flag_boundary_7:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $0, %eax
    addl $0, %eax
.global flag_boundary_8
flag_boundary_8:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $2147483647, %eax
    addl $1, %eax
.global flag_boundary_9
flag_boundary_9:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $4294967295, %eax
    addl $1, %eax
.global flag_boundary_10
flag_boundary_10:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $2147483648, %eax
    addl $2147483648, %eax
.global flag_boundary_11
flag_boundary_11:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $15, %eax
    addl $1, %eax
.global flag_boundary_12
flag_boundary_12:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $16, %eax
    addl $1, %eax
.global flag_boundary_13
flag_boundary_13:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $127, %eax
    addl $1, %eax
.global flag_boundary_14
flag_boundary_14:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $255, %eax
    addl $1, %eax
.global flag_boundary_15
flag_boundary_15:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $0, %eax
    subl $0, %eax
.global flag_boundary_16
flag_boundary_16:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $2147483647, %eax
    subl $1, %eax
.global flag_boundary_17
flag_boundary_17:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $4294967295, %eax
    subl $1, %eax
.global flag_boundary_18
flag_boundary_18:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $2147483648, %eax
    subl $2147483648, %eax
.global flag_boundary_19
flag_boundary_19:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $15, %eax
    subl $1, %eax
.global flag_boundary_20
flag_boundary_20:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $16, %eax
    subl $1, %eax
.global flag_boundary_21
flag_boundary_21:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $127, %eax
    subl $1, %eax
.global flag_boundary_22
flag_boundary_22:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    movl $255, %eax
    subl $1, %eax
.global flag_boundary_23
flag_boundary_23:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $0, %eax
    subl $0, %eax
.global flag_boundary_24
flag_boundary_24:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $2147483647, %eax
    subl $1, %eax
.global flag_boundary_25
flag_boundary_25:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $4294967295, %eax
    subl $1, %eax
.global flag_boundary_26
flag_boundary_26:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $2147483648, %eax
    subl $2147483648, %eax
.global flag_boundary_27
flag_boundary_27:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $15, %eax
    subl $1, %eax
.global flag_boundary_28
flag_boundary_28:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $16, %eax
    subl $1, %eax
.global flag_boundary_29
flag_boundary_29:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $127, %eax
    subl $1, %eax
.global flag_boundary_30
flag_boundary_30:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    std
    movl $255, %eax
    subl $1, %eax
.global flag_boundary_31
flag_boundary_31:
    pushfl
    popl %eax
    movl %eax, (%edi)
    leal 4(%edi), %edi
    cld
    mov $4, %eax
    mov $1, %ebx
    mov $results, %ecx
    mov $128, %edx
    int $0x80
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
.section .bss
results: .skip 128
.section .note.GNU-stack,"",@progbits
.section .rodata
.byte 0
