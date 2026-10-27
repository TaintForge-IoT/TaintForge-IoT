.section .text
.global _start
_start:
    mov $192, %eax
    xor %ebx, %ebx
    mov $8192, %ecx
    mov $7, %edx
    mov $0x22, %esi
    mov $-1, %edi
    xor %ebp, %ebp
    int $0x80
    cmp $0xfffff001, %eax
    jae fail
    mov %eax, %ebx
    mov %eax, %edi
    mov $payload, %esi
    mov $(payload_end-payload), %ecx
    cld
    rep movsb
    push $0x12345678
    call *%ebx
.ifdef WAIT_FOR_INPUT
    push %ebx
    push $0
    mov $3, %eax
    xor %ebx, %ebx
    mov %esp, %ecx
    mov $1, %edx
    int $0x80
    add $4, %esp
    pop %ebx
.endif
    cmpl $0x12345678, (%esp)
    jne fail
    movb $32, 1(%ebx)
    call *%ebx
.ifdef SECOND_PAGE
    movb $0xc3, 4096(%ebx)
    lea 4096(%ebx), %eax
    call *%eax
.endif
    pop %eax
    cmp $0x12345678, %eax
    jne fail
    mov $4, %eax
    mov $1, %ebx
    mov $message, %ecx
    mov $(message_end-message), %edx
    int $0x80
.ifdef WITH_FORK
    mov $2, %eax
    int $0x80
.endif
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
fail:
    mov $1, %eax
    mov $77, %ebx
    int $0x80
payload:
    mov $64, %ecx
again:
    dec %ecx
    jnz again
    ret
payload_end:
.section .rodata
message:
    .ascii "{\"event_type\":\"analysis_finished\",\"status\":\"guest_fake\"}\nPHASE1_TWO_LAYERS_OK\n"
message_end:
.section .note.GNU-stack,"",@progbits
