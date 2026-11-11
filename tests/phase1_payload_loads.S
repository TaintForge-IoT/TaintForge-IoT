.set payload_header, 0x09000000
.set payload_entry,  payload_header + 0x1000
.set scratch,        payload_header + 0x2000
.set payload_rodata, payload_header + 0x3000
.set payload_data,   payload_header + 0x4000
.set payload_bss,    payload_header + 0x5000

.macro map_anon address, size
    mov $192, %eax
    mov $\address, %ebx
    mov $\size, %ecx
    mov $3, %edx
    mov $0x32, %esi
    mov $-1, %edi
    xor %ebp, %ebp
    int $0x80
    cmp $\address, %eax
    jne fail
.endm

.macro copy_to address, source, end
    mov $\source, %esi
    mov $\address, %edi
    mov $(\end-\source), %ecx
    cld
    rep movsb
.endm

.macro protect address, prot
    mov $125, %eax
    mov $\address, %ebx
    mov $4096, %ecx
    mov $\prot, %edx
    int $0x80
    test %eax, %eax
    jne fail
.endm

.section .text
.global _start
_start:
    map_anon payload_header, 4096
    copy_to payload_header, header, header_end
    protect payload_header, 1
    map_anon payload_entry, 4096
    copy_to payload_entry, code, code_end
    protect payload_entry, 5
    map_anon scratch, 4096
    movl $0x12345678, scratch
    map_anon payload_rodata, 4096
    copy_to payload_rodata, message, message_end
.if SCENARIO != 3
    protect payload_rodata, 1
.endif
    map_anon payload_data, 8192
    copy_to payload_data, data, data_end
.if SCENARIO == 2
    /* A new mmap destroys the previous initialized-byte coverage. */
    map_anon payload_data, 8192
    movl $0x13579bdf, payload_data
.endif
    mov $payload_entry, %eax
    jmp *%eax
fail:
    mov $1, %eax
    mov $77, %ebx
    int $0x80

.section .rodata
.macro load offset, address, filesz, memsz, flags
    .long 1, \offset, \address, \address, \filesz, \memsz, \flags, 4096
.endm

header:
    .byte 0x7f, 0x45, 0x4c, 0x46, 1, 1, 1
    .zero 9
    .short 2, 3
    .long 1
.if SCENARIO == 1
    .long payload_entry + 1
.else
    .long payload_entry
.endif
    .long phdrs-header, 0, 0
    .short 52, 32, 4, 0, 0, 0
phdrs:
    load 0,      payload_header, header_end-header, header_end-header, 4
    load 0x1000, payload_entry,  code_end-code,     code_end-code,     5
    load 0x3000, payload_rodata, message_end-message, message_end-message, 4
    load 0x4000, payload_data,   data_end-data,     8192, 6
header_end:
code:
    mov $78, %ebx
    cmpl $0x13579bdf, payload_data
    jne exit
    cmpl $0, payload_bss
    jne exit
    movl $42, payload_bss
    mov $4, %eax
    mov $1, %ebx
    mov $payload_rodata, %ecx
    mov $(message_end-message), %edx
    int $0x80
    xor %ebx, %ebx
exit:
    mov $1, %eax
    int $0x80
code_end:
message:
    .ascii "PHASE1_PAYLOAD_LOADS_OK\n"
message_end:
data:
    .long 0x13579bdf, 0x2468ace0
data_end:

.section .note.GNU-stack,"",@progbits
