.macro protect permissions
    mov $125, %eax
    mov $image, %ebx
    mov $4096, %ecx
    mov $\permissions, %edx
    int $0x80
    test %eax, %eax
    jne fail
.endm

.macro payload
    mov $4, %eax
    mov $1, %ebx
    mov $message, %ecx
    mov $(message_end-message), %edx
    int $0x80
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
.endm

.section .text
.global _start
_start:
    protect 7
.if SCENARIO == 3
    /* Only one byte of the first instruction has a guest write. */
    orb $0, payload_entry
.else
    mov $template, %esi
.if SCENARIO == 2
    mov $handoff, %edi
.else
    mov $payload_entry, %edi
.endif
    mov $(template_end-template), %ecx
    cld
    rep movsb
.endif
    protect 5
.if SCENARIO == 1 || SCENARIO == 4 || SCENARIO == 5
    call helper
.if SCENARIO == 5
    call helper
    payload
.else
    jmp payload_entry
.endif
.else
    jmp handoff
.endif
fail:
    mov $1, %eax
    mov $77, %ebx
    int $0x80

.balign 4096
image:
handoff:
.if SCENARIO == 2
    .byte 0xcc
.else
    nop
.endif
payload_entry:
.if SCENARIO == 3
    payload
.else
    .fill helper_template-payload_template, 1, 0xcc
.endif
helper:
    .fill template_end-helper_template, 1, 0xcc
message:
    .ascii "PHASE1_OEP_HANDOFF_OK\n"
message_end:

.section .rodata
template:
.if SCENARIO == 2
    nop
.endif
payload_template:
    payload
helper_template:
.if SCENARIO == 4
    mov $payload_entry, %eax
    jmp *%eax
.else
    ret
.endif
template_end:

.section .note.GNU-stack,"",@progbits
