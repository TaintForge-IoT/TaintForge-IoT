/* Branch-free bounded REP diagnostic fixture.  Both buffers are original ELF
 * bytes.  No syscall occurs until after the selected computed transfer. */
.code32
.section .text
.globl _start, rep_instruction, after_rep, transfer
_start:
    mov $0x13579bdf, %ebp
    mov $0x2468ace0, %ebx
    mov $0, %edx
    mov $0x9a5c317e, %eax
    mov $SOURCE_START, %esi
    mov $DESTINATION_START, %edi
    mov $REPEAT_COUNT, %ecx
.if BACKWARD
    std
.else
    cld
.endif
rep_instruction:
.if STORE_KIND
.if ELEMENT_BYTES == 1
    rep stosb
.elseif ELEMENT_BYTES == 2
    rep stosw
.else
    rep stosl
.endif
.else
.if ELEMENT_BYTES == 1
    rep movsb
.elseif ELEMENT_BYTES == 2
    rep movsw
.else
    rep movsl
.endif
.endif
after_rep:
    mov %ecx, observed_count
    mov %esi, observed_source
    mov %edi, observed_destination
    cld
    mov $payload, %eax
transfer:
    jmp *%eax

.section .payload, "ax"
.globl payload
payload:
    mov $4, %eax
    mov $1, %ebx
    mov $destination_buffer, %ecx
    mov $4108, %edx
    int $0x80
    mov $1, %eax
    mov $0, %ebx
    int $0x80
    ud2

.section .testdata, "aw"
.globl source_buffer, destination_buffer, observed_count, observed_source, observed_destination
source_buffer:
    .incbin "source.bin"
destination_buffer:
    .incbin "destination.bin"
observed_count:
    .long 0
observed_source:
    .long 0
observed_destination:
    .long 0
