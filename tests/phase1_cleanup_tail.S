/* S37 synthetic i386 Linux fixture. Each variant reaches the same payload. */
.ifndef SCENARIO
.error "set SCENARIO to an integer between 0 and 7"
.endif

.section .text
.globl _start
.macro anon_page slot
    movl $192, %eax
    xorl %ebx, %ebx
    movl $4096, %ecx
    movl $3, %edx
    movl $0x22, %esi
    movl $-1, %edi
    xorl %ebp, %ebp
    int $0x80
    cmpl $-4095, %eax
    jae .Lfail
    movl %eax, \slot
.endm

.macro protect_page prot
    movl $125, %eax
    movl $4096, %ecx
    movl $\prot, %edx
    int $0x80
    testl %eax, %eax
    jnz .Lfail
.endm

_start:
    anon_page scratch
    anon_page unrelated
    movl scratch, %ebx
    movw $0xe2ff, (%ebx)            /* jmp *%edx, from the scratch mapping */
    protect_page 5
    movl unrelated, %ebx
    movb $0xc3, (%ebx)
    protect_page 5
    call *unrelated                /* make the unrelated page an observed candidate */

    movl $payload_page, %ebx
    protect_page 3
    cld
    movl $tail_template, %esi
    movl $cleanup, %edi
    movl $(tail_template_end-tail_template), %ecx
    rep movsb
    movl $target, %edi
.if SCENARIO == 4 || SCENARIO == 7
    /* Remaining bytes are file-backed in case 4 and cleanup bytes in case 7. */
    movb $0xb8, (%edi)
.else
    movl $target_template, %esi
    movl $(target_template_end-target_template), %ecx
    rep movsb
.endif
    movl $payload_page, %ebx
    protect_page 5

    movl $target, %edx
    pushl %edx
    pushal
    movl $cleanup, %edx
    movl scratch, %esi
.if SCENARIO == 2
    movl unrelated, %ebx
.else
    movl %esi, %ebx
.endif
.if SCENARIO == 1
    incl %ebx                      /* munmap fails with EINVAL */
.endif
    movl $4096, %ecx
    movl $91, %eax
    jmp *%esi

.Lfail:
    movl $1, %eax
    movl $77, %ebx
    int $0x80

.macro target_code
    movl $4, %eax
    movl $1, %ebx
    movl $marker, %ecx
    movl $(marker_end-marker), %edx
    int $0x80
    movl $1, %eax
    xorl %ebx, %ebx
    int $0x80
.endm

target_template:
    target_code
target_template_end:
tail_template:
    int $0x80
    popal
.if SCENARIO == 3
    jmp *%edx                      /* lacks a POP-bound target */
.elseif SCENARIO == 5
    popl %eax
    .byte 0x3e, 0xff, 0xe0         /* jmp ds:%eax, as emitted by UPX 5.2.1 */
.else
.if SCENARIO == 6
    nop                            /* interrupts the recognized return tail */
.endif
    ret
.endif
tail_template_end:

.p2align 12
payload_page:
.org payload_page+0x100, 0x90
.globl target
.if SCENARIO == 7
.Lbody:
.else
target:
.endif
    target_code
.if SCENARIO == 7
.org payload_page+0x1ff, 0x90
target:
    .byte 0xb8                     /* MOV EAX, imm32 consumes the four tail bytes. */
.endif
.org payload_page+0x200, 0x90
.globl cleanup
cleanup:
    .fill tail_template_end-tail_template, 1, 0xcc
.if SCENARIO == 7
    jmp .Lbody
.endif
.org payload_page+0x1000, 0x90

.section .rodata
marker:
    .ascii "S37_SYNTHETIC_TARGET_REACHED\n"
marker_end:

.section .bss
.balign 4
scratch:   .skip 4
unrelated: .skip 4

.section .note.GNU-stack,"",@progbits
