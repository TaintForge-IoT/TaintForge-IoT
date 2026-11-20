.global _start
.text
_start:
    cmpl $3, (%esp)
    jne bad_arguments
    mov 8(%esp), %eax
    movb (%eax), %al
    cmp $'t', %al
    je parse_port
    movl $1, mode
    cmp $'u', %al
    je parse_port
    cmp $'d', %al
    jne bad_arguments
    movl $2, mode
parse_port:
    mov 12(%esp), %ecx
    xor %eax, %eax
port_digit:
    movzbl (%ecx), %edx
    test %edx, %edx
    jz port_ready
    sub $'0', %edx
    cmp $9, %edx
    ja bad_arguments
    imul $10, %eax
    add %edx, %eax
    cmp $65535, %eax
    ja bad_arguments
    inc %ecx
    jmp port_digit
port_ready:
    test %eax, %eax
    jz bad_arguments
    xchg %al, %ah
    movw %ax, address+2
    mov $359, %eax
    mov $2, %ebx
    mov $1, %ecx
    cmpl $0, mode
    je create_socket
    mov $2, %ecx
create_socket:
    xor %edx, %edx
    int $0x80
    test %eax, %eax
    js socket_failed
    mov %eax, socket_fd
    mov $366, %eax
    mov socket_fd, %ebx
    mov $1, %ecx
    mov $20, %edx
    mov $timeout, %esi
    mov $8, %edi
    int $0x80
    mov $362, %eax
    mov socket_fd, %ebx
    mov $address, %ecx
    mov $16, %edx
    int $0x80
    test %eax, %eax
    js connect_failed
    movl $tcp_request, request
    movl $6, request_length
    cmpl $0, mode
    je first_send
    movl $udp_request, request
    movl $4, request_length
    cmpl $1, mode
    je first_send
    movl $dns_query, request
    movl $30, request_length
first_send:
    call send_request
    test %eax, %eax
    js send_failed
    cmpl $0, mode
    je receive_reply
    /* A second UDP send observes pending loopback ICMP refusal without a provider. */
    mov $162, %eax
    mov $pause, %ebx
    xor %ecx, %ecx
    int $0x80
    call send_request
    test %eax, %eax
    js send_failed
receive_reply:
    mov $371, %eax
    mov socket_fd, %ebx
    mov $reply, %ecx
    mov $1024, %edx
    xor %esi, %esi
    xor %edi, %edi
    xor %ebp, %ebp
    int $0x80
    cmpl $2, mode
    je check_dns
    cmpl $1, mode
    je check_udp
    cmp $3, %eax
    jne wrong_reply
    cmpw $0x4b4f, reply
    jne wrong_reply
    cmpb $10, reply+2
    jne wrong_reply
    jmp success
check_udp:
    cmp $4, %eax
    jne wrong_reply
    cmpl $0x676e6f70, reply
    jne wrong_reply
    jmp success
check_dns:
    cmp $16, %eax
    jl wrong_reply
    cmpb $0, reply
    jne wrong_reply
    cmpb $1, reply+1
    jne wrong_reply
    testb $128, reply+2
    jz wrong_reply
    testb $15, reply+3
    jnz wrong_reply
    cmpb $1, reply+7
    jne wrong_reply
    cmpl $0x070200c0, reply-4(%eax)
    jne wrong_reply
success:
    mov $6, %eax
    mov socket_fd, %ebx
    int $0x80
    mov $4, %eax
    mov $1, %ebx
    mov $marker, %ecx
    mov $8, %edx
    int $0x80
    xor %ebx, %ebx
    jmp exit
send_request:
    mov $369, %eax
    mov socket_fd, %ebx
    mov request, %ecx
    mov request_length, %edx
    xor %esi, %esi
    xor %edi, %edi
    xor %ebp, %ebp
    int $0x80
    ret
bad_arguments:
    mov $2, %ebx
    jmp exit
socket_failed:
    mov $3, %ebx
    jmp exit
connect_failed:
    mov $10, %ebx
    jmp exit
send_failed:
    mov $11, %ebx
    jmp exit
wrong_reply:
    mov $14, %ebx
exit:
    mov $1, %eax
    int $0x80
.data
.align 4
mode: .long 0
socket_fd: .long 0
request: .long 0
request_length: .long 0
address: .short 2,0
    .byte 127,0,0,1
    .zero 8
timeout: .long 1,0
pause: .long 0,100000000
tcp_request: .ascii "HELLO\n"
udp_request: .ascii "ping"
dns_query: .byte 0,1,1,0,0,1,0,0,0,0,0,0,4,'n','e','t','3',7,'e','x','a','m','p','l','e',0,0,1,0,1
marker: .ascii "NET3_OK\n"
.bss
.align 4
reply: .skip 1024
