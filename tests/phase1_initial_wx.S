/* The loader supplies executable permissions. No mprotect of the target. */
.section .text
.global _start
_start:
.if SCENARIO == 3
    mov $91, %eax
    mov $hole_page, %ebx
    mov $4096, %ecx
    int $0x80
    test %eax, %eax
    jne fail
    mov $125, %eax
    mov $changed_page, %ebx
    mov $1, %edx
    int $0x80
    test %eax, %eax
    jne fail
.endif
.if SCENARIO == 0 || SCENARIO == 3 || SCENARIO == 4
    movb $0x90, payload_entry
.elseif SCENARIO == 2
    movb $1, unused_byte
.endif
.if SCENARIO == 4
    /* The earlier store belongs to the page that mremap replaces. */
    mov $163, %eax
    mov $replacement, %ebx
    mov $4096, %ecx
    mov %ecx, %edx
    mov $3, %esi
    mov $payload_entry, %edi
    int $0x80
    cmp %edi, %eax
    jne fail
.endif
    jmp payload_entry
fail:
    mov $1, %eax
    mov $77, %ebx
    int $0x80
print_message:
    mov $4, %eax
    mov $1, %ebx
    mov $message, %ecx
    mov $(message_end-message), %edx
    int $0x80
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80

.section .inplace,"awx",@progbits
.balign 4096
payload_entry:
.if SCENARIO == 0 || SCENARIO == 3
    int3
.else
    nop
.endif
    cmpl $0, state
    jne fail
    incl state
    jmp print_message
unused_byte:
    .byte 0
.if SCENARIO == 4
.balign 4096
replacement:
    mov $print_message, %eax
    jmp *%eax
.endif

.section .rodata
message:
    .ascii "PHASE1_OEP_HANDOFF_OK\n"
message_end:

.section .bss
.balign 4096
state:
    .skip 4096
changed_page:
    .skip 4096
hole_page:
    .skip 4096

.section .note.GNU-stack,"",@progbits
