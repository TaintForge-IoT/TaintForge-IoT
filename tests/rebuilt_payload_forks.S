/* Benign static i386 ELF. No argument takes the capture/rebuild path. With
 * a file argument, bits select an extra leaf edge (1), UD2 in the leaf (2),
 * early root exit (4), UD2 in the root's other child (8), normal leaf
 * exit 132 (16), eight direct children (32), or seven (32|64). */
.section .text
.global _start, payload_entry, sibling_choice, leaf_choice_block, leaf_choice, leaf_extra, leaf_fault, sibling_fault
_start:
    mov $125, %eax
    mov $payload_entry, %ebx
    mov $4096, %ecx
    mov $7, %edx
    int $0x80
    test %eax, %eax
    jnz failed
    mov $template, %esi
    mov $payload_entry, %edi
    mov $5, %ecx
    cld
    rep movsb
    jmp payload_entry
template:
    mov $0, %eax
.balign 4096
payload_entry:
    .fill 5,1,0xcc
    cmpl $1, (%esp)
    je success
    mov %esp, %edi
    sub $16, %esp
    mov %esp, %ebp
    /* A second argument delegates the input read to a worker. */
    cmpl $3, (%edi)
    jne read_input
    mov $2, %eax
    int $0x80
    test %eax, %eax
    js failed
    jz read_input
    call wait_one
    jmp success
read_input:
    mov 8(%edi), %ebx
    mov $5, %eax
    xor %ecx, %ecx
    int $0x80
    test %eax, %eax
    js failed
    mov %eax, %ebx
    mov $3, %eax
    lea 12(%ebp), %ecx
    mov $1, %edx
    int $0x80
    cmp $1, %eax
    jne failed
    mov $6, %eax
    int $0x80
    testb $32, 12(%ebp)
    jnz too_many
    mov $42, %eax
    mov %ebp, %ebx
    int $0x80
    test %eax, %eax
    jnz failed
    mov $2, %eax
    int $0x80
    test %eax, %eax
    js failed
    jz sibling
    mov $2, %eax
    int $0x80
    test %eax, %eax
    js failed
    jz middle
    testb $4, 12(%ebp)
    jnz success
    call close_writer
    call wait_one
    call wait_one
    jmp success
sibling:
    call close_writer
    testb $8, 12(%ebp)
sibling_choice:
    jz success
sibling_fault:
    ud2
middle:
    call close_writer
    mov $2, %eax
    int $0x80
    test %eax, %eax
    js failed
    jz leaf
    call wait_one
    jmp success
leaf:
    /* EOF is possible only after the root closes its writer or exits. */
    mov $3, %eax
    mov (%ebp), %ebx
    lea 13(%ebp), %ecx
    mov $1, %edx
    int $0x80
    test %eax, %eax
    jne failed
leaf_choice_block:
    testb $1, 12(%ebp)
leaf_choice:
    jnz leaf_extra
    jmp leaf_end
.balign 32
leaf_extra:
    nop
leaf_end:
    testb $16, 12(%ebp)
    jz check_fault
    mov $132, %ebx
    jmp exit
check_fault:
    testb $2, 12(%ebp)
    jz success
leaf_fault:
    ud2
too_many:
    mov $7, %esi
    testb $64, 12(%ebp)
    jnz next_sibling
    inc %esi
next_sibling:
    mov $2, %eax
    int $0x80
    test %eax, %eax
    js failed
    jz success
    dec %esi
    jnz next_sibling
    jmp success
close_writer:
    mov $6, %eax
    mov 4(%ebp), %ebx
    int $0x80
    test %eax, %eax
    jne failed
    ret
wait_one:
    mov $7, %eax
    mov $-1, %ebx
    lea 8(%ebp), %ecx
    xor %edx, %edx
    int $0x80
    cmp $-4, %eax
    je wait_one
    test %eax, %eax
    js failed
    ret
success:
    xor %ebx, %ebx
    jmp exit
failed:
    mov $73, %ebx
exit:
    mov $1, %eax
    int $0x80
.section .note.GNU-stack,"",@progbits
