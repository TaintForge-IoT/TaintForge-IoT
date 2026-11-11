.macro protect page, permissions
    mov $125, %eax
    mov $\page, %ebx
    mov $4096, %ecx
    mov $\permissions, %edx
    int $0x80
    test %eax, %eax
    jne fail
.endm

.macro restore_payload
    protect payload_page, 7
    mov $body, %esi
    mov $payload_entry, %edi
    mov $(body_end-body), %ecx
    cld
    rep movsb
    protect payload_page, 5
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

.set EXECUTABLE_REMAP, SCENARIO >= 4 && SCENARIO <= 6

.section .text
.global _start
_start:
.if SCENARIO < 2 || SCENARIO >= 9
    protect stage, 7
    mov $stage, %esi
    mov %esi, %edi
    mov $(stage_end-stage), %ecx
    cld
    rep movsb
    protect stage, 5
.endif
.if SCENARIO >= 9
    /* Both regions are written before the first stage starts executing. */
    restore_payload
.endif
    jmp stage
fail:
    mov $1, %eax
    mov $77, %ebx
    int $0x80

.balign 4096
stage:
.if EXECUTABLE_REMAP
    /* MAP_FIXED supplies executable bytes without a guest store to this page. */
    mov $192, %eax
    mov $payload_page, %ebx
    mov $4096, %ecx
    mov $5, %edx
    mov $0x32, %esi
    mov $-1, %edi
    xor %ebp, %ebp
    int $0x80
    cmp $payload_page, %eax
    jne fail
    mov $scratch, %eax
.elseif SCENARIO < 9
    restore_payload
.endif
.if SCENARIO == 0 || SCENARIO == 4 || SCENARIO == 7 || SCENARIO == 9
    call payload_entry
.elseif SCENARIO == 1 || SCENARIO == 5 || SCENARIO == 8 || SCENARIO == 10
    cmp %eax, %eax
    je payload_entry
.elseif SCENARIO == 6
    jmp payload_entry
.else
    jmp handoff
.endif
    jmp fail
stage_end:

.balign 4096
payload_page:
.if SCENARIO == 2
handoff:
    mov $1, %eax
    test %eax, %eax
    je fail
.elseif SCENARIO == 3
handoff:
    xor %eax, %eax
    je payload_entry
.endif
payload_entry:
.if EXECUTABLE_REMAP
    /* Zero bytes decode as addb %al,(%eax) up to the next mapped page. */
    .zero 4096
    payload
.else
    .fill body_end-body, 1, 0xcc
.endif

.section .rodata
body:
    payload
body_end:
message:
    .ascii "PHASE1_OEP_HANDOFF_OK\n"
message_end:

.section .bss
scratch:
    .skip 4

.section .note.GNU-stack,"",@progbits
