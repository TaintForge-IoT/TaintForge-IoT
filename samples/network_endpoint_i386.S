.global _start
.text
_start:
    /* Direct TCP syscall: -strace prints only the sockaddr pointer. */
    mov $359, %eax
    mov $2, %ebx
    mov $1, %ecx
    xor %edx, %edx
    int $0x80
    mov %eax, %esi
    mov %esi, %ebx
    mov $362, %eax
    mov $tcp_address, %ecx
    mov $16, %edx
    int $0x80
    /* Reuse the same pointer after changing its contents. */
    movb $2, tcp_address+7
    mov $362, %eax
    int $0x80
    mov $6, %eax
    mov %esi, %ebx
    int $0x80

    /* Legacy socketcall, CLOEXEC flags, and a duplicated UDP descriptor. */
    mov $102, %eax
    mov $1, %ebx
    mov $socket_args, %ecx
    int $0x80
    mov %eax, %edi
    mov %edi, %ebx
    mov $41, %eax
    int $0x80
    mov %eax, %esi
    mov %esi, connect_args
    mov $102, %eax
    mov $3, %ebx
    mov $connect_args, %ecx
    int $0x80

    /* The original fd shares the peer selected through its dup alias. */
    mov $369, %eax
    mov %edi, %ebx
    mov $payload, %ecx
    mov $4, %edx
    push %esi
    xor %esi, %esi
    push %edi
    xor %edi, %edi
    xor %ebp, %ebp
    int $0x80
    pop %edi
    pop %esi

    mov $370, %eax
    mov $message, %ecx
    xor %edx, %edx
    int $0x80

    mov %edi, sendto_args
    mov $102, %eax
    mov $11, %ebx
    mov $sendto_args, %ecx
    int $0x80
    mov %esi, send_args
    mov $102, %eax
    mov $9, %ebx
    mov $send_args, %ecx
    int $0x80

    /* Reuse the original fd for TCP; its UDP peer must not survive. */
    mov $6, %eax
    mov %edi, %ebx
    int $0x80
    mov $359, %eax
    mov $2, %ebx
    mov $1, %ecx
    xor %edx, %edx
    int $0x80
    mov %eax, %ebx
    mov $362, %eax
    mov $1, %ecx
    mov $16, %edx
    int $0x80
    mov $6, %eax
    int $0x80

    /* The remaining UDP alias still refers to the original connected socket. */
    mov $102, %eax
    mov $9, %ebx
    mov $send_args, %ecx
    int $0x80
    mov $6, %eax
    mov %esi, %ebx
    int $0x80

    /* AF_UNIX is explicitly outside the IPv4 observer profile. */
    mov $359, %eax
    mov $1, %ebx
    mov $1, %ecx
    xor %edx, %edx
    int $0x80
    mov %eax, %ebx
    mov $362, %eax
    mov $unix_address, %ecx
    mov $16, %edx
    int $0x80
    mov $6, %eax
    int $0x80
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80

.data
.align 4
tcp_address:
    .short 2, TCP_PORT_NET
    .byte 127,0,0,1
    .zero 8
udp_address:
    .short 2, UDP_PORT_NET
    .byte 127,0,0,1
    .zero 8
unix_address:
    .short 1
    .asciz "/net2-missing"
socket_args:
    .long 2, 524290, 17
connect_args:
    .long 0, udp_address, 16
sendto_args:
    .long 0, payload, 4, 0, udp_address, 16
send_args:
    .long 0, payload, 4, 0
payload:
    .ascii "ping"
vector:
    .long payload, 4
message:
    .long udp_address, 16, vector, 1, 0, 0, 0
.section .note.GNU-stack,"",@progbits
