.section .text
.global _start
_start:
    mov $4, %eax
    mov $PROBE_FD, %ebx
    mov $message, %ecx
    mov $message_end-message, %edx
    int $0x80
    cmp $message_end-message, %eax
    jne failed
    xor %ebx, %ebx
    jmp exit
failed:
    mov $1, %ebx
exit:
    mov $1, %eax
    int $0x80
.section .rodata
message:
    .ascii "M4_FD_PROBE\n"
message_end:
.section .note.GNU-stack,"",@progbits
