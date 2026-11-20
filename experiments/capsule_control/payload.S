.section .text
.global control_probe
control_probe:
.if CASE_ID == 0
    mov $4, %eax
    mov $PROBE_FD, %ebx
    mov $probe_message, %ecx
    mov $probe_message_end-probe_message, %edx
.elseif CASE_ID == 1
    mov $3, %eax
    mov $PROBE_FD, %ebx
    mov $probe_buffer, %ecx
    mov $16, %edx
.elseif CASE_ID == 2
    mov $6, %eax
    mov $PROBE_FD, %ebx
.elseif CASE_ID == 3
    mov $41, %eax
    mov $PROBE_FD, %ebx
.elseif CASE_ID == 4
    mov $63, %eax
    mov $1, %ebx
    mov $PROBE_FD, %ecx
.elseif CASE_ID == 5
    mov $55, %eax
    mov $PROBE_FD, %ebx
    mov $1, %ecx
.elseif CASE_ID == 6
    mov $221, %eax
    mov $PROBE_FD, %ebx
    xor %ecx, %ecx
    mov $240, %edx
.elseif CASE_ID == 7
    mov $192, %eax
    xor %ebx, %ebx
    mov $4096, %ecx
    mov $1, %edx
    mov $2, %esi
    mov $PROBE_FD, %edi
    xor %ebp, %ebp
.elseif CASE_ID == 8
    mov $90, %eax
    mov $probe_mmap, %ebx
.elseif CASE_ID == 9
    mov $146, %eax
    mov $PROBE_FD, %ebx
    mov $probe_iov, %ecx
    mov $1, %edx
.elseif CASE_ID == 10
    mov $181, %eax
    mov $PROBE_FD, %ebx
    mov $probe_message, %ecx
    mov $probe_message_end-probe_message, %edx
    xor %esi, %esi
    xor %edi, %edi
.elseif CASE_ID == 11
    mov $187, %eax
    mov $PROBE_FD, %ebx
    xor %ecx, %ecx
    xor %edx, %edx
    mov $16, %esi
.elseif CASE_ID == 12
    mov $102, %eax
    mov $9, %ebx
    mov $probe_socket_args, %ecx
.elseif CASE_ID == 13
    mov $436, %eax
    mov $3, %ebx
    mov $0xffffffff, %ecx
    xor %edx, %edx
.elseif CASE_ID == 14
    mov $5, %eax
    mov $proc_path, %ebx
    xor %ecx, %ecx
.elseif CASE_ID == 15
    mov $5, %eax
    mov $reserved_path, %ebx
    xor %ecx, %ecx
.elseif CASE_ID == 16
    mov $5, %eax
    mov $private_path, %ebx
    mov $2, %ecx
.elseif CASE_ID == 17
    mov $5, %eax
    mov $symlink_path, %ebx
    mov $2, %ecx
.elseif CASE_ID == 18
    mov $5, %eax
    mov $traversal_path, %ebx
    mov $2, %ecx
.elseif CASE_ID == 19
    mov $5, %eax
    mov $relative_path, %ebx
    mov $2, %ecx
.elseif CASE_ID == 20
    mov $999, %eax
.elseif CASE_ID == 21 || CASE_ID == 22 || CASE_ID == 23 || CASE_ID == 24 || CASE_ID == 28 || CASE_ID == 33
    mov $5, %eax
    mov $public_path, %ebx
    mov $66, %ecx
    mov $0600, %edx
.if CASE_ID == 28
    mov $295, %eax
    mov $-100, %ebx
    mov $public_path, %ecx
    mov $66, %edx
    mov $0600, %esi
.endif
    int $0x80
    test %eax, %eax
    js probe_failed
    mov %eax, %ebx
.if CASE_ID == 22
    mov $6, %eax
    int $0x80
.elseif CASE_ID == 23
    mov $41, %eax
    int $0x80
    test %eax, %eax
    js probe_failed
    mov %eax, %ebx
.elseif CASE_ID == 24
    mov %ebx, %ecx
    mov $1, %ebx
    mov $63, %eax
    int $0x80
    test %eax, %eax
    js probe_failed
    mov %eax, %ebx
.elseif CASE_ID == 33
    mov %ebx, %edi
    mov $192, %eax
    xor %ebx, %ebx
    mov $4096, %ecx
    mov $1, %edx
    mov $2, %esi
    xor %ebp, %ebp
    int $0x80
    cmp $-4095, %eax
    jae probe_failed
    jmp probe_ok
.endif
    mov $4, %eax
    mov $probe_message, %ecx
    mov $probe_message_end-probe_message, %edx
.elseif CASE_ID == 25
    mov $5, %eax
    xor %ebx, %ebx
    xor %ecx, %ecx
.elseif CASE_ID == 26
    mov $5, %eax
    mov $long_path, %ebx
    xor %ecx, %ecx
.elseif CASE_ID == 27
    mov $5, %eax
    mov $hardlink_path, %ebx
    mov $2, %ecx
.elseif CASE_ID == 29
    mov $295, %eax
    mov $PROBE_FD, %ebx
    mov $relative_path, %ecx
    xor %edx, %edx
.elseif CASE_ID == 30
    mov $private_path, %esi
    mov $mutable_path, %edi
    mov $4096, %ecx
1:  lodsb
    stosb
    test %al, %al
    loopne 1b
    mov $5, %eax
    mov $mutable_path, %ebx
    mov $2, %ecx
.elseif CASE_ID == 31
    jmp probe_ok
.elseif CASE_ID == 32
    mov $192, %eax
    xor %ebx, %ebx
    mov $4096, %ecx
    mov $3, %edx
    mov $34, %esi
    mov $-1, %edi
    xor %ebp, %ebp
.else
    .error "unsupported CASE_ID"
.endif
    int $0x80
.if CASE_ID == 32
    cmp $-4095, %eax
    jae probe_failed
.endif
probe_ok:
    mov $4, %eax
    mov $1, %ebx
    mov $probe_ok_message, %ecx
    mov $probe_ok_end-probe_ok_message, %edx
    int $0x80
    xor %ebx, %ebx
    jmp probe_exit
probe_failed:
    mov $77, %ebx
probe_exit:
    mov $1, %eax
    int $0x80
.section .rodata
probe_message: .ascii "CONTROL_FD_WRITE\n"
probe_message_end:
probe_ok_message: .ascii "CONTROL_GUEST_OK\n"
probe_ok_end:
probe_iov: .long probe_message, probe_message_end-probe_message
probe_socket_args: .long PROBE_FD, probe_message, probe_message_end-probe_message, 0
probe_mmap: .long 0, 4096, 1, 2, PROBE_FD, 0
proc_path: .asciz "/proc/self/fd/200"
reserved_path: .asciz "/__taintforge_capsule/observer.sock"
relative_path: .asciz "input"
long_path: .fill 4096, 1, 65
    .byte 0
.include "paths.inc"
.section .bss
probe_buffer: .space 64
mutable_path: .space 4096
.section .note.GNU-stack,"",@progbits
