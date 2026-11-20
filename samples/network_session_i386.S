.global _start
.section .text
_start:
    cmpl $3, (%esp)
    jne bad_arguments
    mov 8(%esp), %ecx
    call decimal
    cmp $10, %eax
    ja bad_arguments
    mov %eax, mode
    mov 12(%esp), %ecx
    call decimal
    test %eax, %eax
    jz bad_arguments
    xchg %al, %ah
    movw %ax, address+2
    call connect_socket
    cmpl $3, mode
    je wrong_order
    cmpl $4, mode
    je unknown_step
    cmpl $5, mode
    je partial_eof
    cmpl $6, mode
    je idle
    cmpl $7, mode
    je trailing
    cmpl $8, mode
    je oversized
    cmpl $10, mode
    je interleaved
    call dialogue
    call close_socket
    cmpl $9, mode
    jne success
    call connect_socket
    call dialogue
    call close_socket
    jmp success

decimal:
    xor %eax, %eax
1:
    movzbl (%ecx), %edx
    test %edx, %edx
    jz 2f
    sub $'0', %edx
    cmp $9, %edx
    ja bad_arguments
    imul $10, %eax
    add %edx, %eax
    cmp $65535, %eax
    ja bad_arguments
    inc %ecx
    jmp 1b
2:
    ret

connect_socket:
    mov $359, %eax
    mov $2, %ebx
    mov $1, %ecx
    xor %edx, %edx
    int $0x80
    test %eax, %eax
    js io_failure
    mov %eax, socket_fd
    mov $362, %eax
    mov socket_fd, %ebx
    mov $address, %ecx
    mov $16, %edx
    int $0x80
    test %eax, %eax
    js connect_failure
    ret

close_socket:
    mov $6, %eax
    mov socket_fd, %ebx
    int $0x80
    ret

send_all:
    mov %ecx, cursor
    mov %edx, remaining
1:
    mov $369, %eax
    mov socket_fd, %ebx
    mov cursor, %ecx
    mov remaining, %edx
    mov $0x4000, %esi
    xor %edi, %edi
    xor %ebp, %ebp
    int $0x80
    test %eax, %eax
    jle io_failure
    add %eax, cursor
    sub %eax, remaining
    jnz 1b
    ret

expect:
    mov %ecx, expected
    mov %edx, remaining
    movl $reply, cursor
1:
    mov $371, %eax
    mov socket_fd, %ebx
    mov cursor, %ecx
    mov remaining, %edx
    xor %esi, %esi
    xor %edi, %edi
    xor %ebp, %ebp
    int $0x80
    test %eax, %eax
    jle wrong_reply
    mov %eax, received
    mov cursor, %esi
    mov expected, %edi
    mov %eax, %ecx
    cld
    repe cmpsb
    jne wrong_reply
    mov received, %eax
    add %eax, cursor
    add %eax, expected
    sub %eax, remaining
    jnz 1b
    ret

hello:
    mov $hello_request, %ecx
    mov $6, %edx
    call send_all
    mov $ready_response, %ecx
    mov $6, %edx
    call expect
    ret

finish_dialogue:
    mov $auth_request, %ecx
    mov $10, %edx
    call send_all
    mov $ok_response, %ecx
    mov $3, %edx
    call expect
    mov $config_request, %ecx
    mov $11, %edx
    call send_all
    mov $config_response, %ecx
    mov $12, %edx
    call expect
    ret

dialogue:
    cmpl $1, mode
    je fragmented
    cmpl $2, mode
    je coalesced
    call hello
    call finish_dialogue
    ret
fragmented:
    mov $hello_request, %ecx
    mov $2, %edx
    call send_all
    mov $162, %eax
    mov $short_pause, %ebx
    xor %ecx, %ecx
    int $0x80
    mov $hello_request+2, %ecx
    mov $4, %edx
    call send_all
    mov $ready_response, %ecx
    mov $6, %edx
    call expect
    call finish_dialogue
    ret
coalesced:
    mov $hello_request, %ecx
    mov $27, %edx
    call send_all
    mov $ready_response, %ecx
    mov $21, %edx
    call expect
    ret

interleaved:
    mov socket_fd, %eax
    mov %eax, first_fd
    call hello
    call connect_socket
    call hello
    call finish_dialogue
    call close_socket
    mov first_fd, %eax
    mov %eax, socket_fd
    call finish_dialogue
    call close_socket
    jmp success

wrong_order:
    mov $config_request, %ecx
    mov $11, %edx
    call send_all
    jmp require_closed
unknown_step:
    call hello
    mov $hello_request, %ecx
    mov $6, %edx
    call send_all
    jmp require_closed
partial_eof:
    mov $hello_request, %ecx
    mov $3, %edx
    call send_all
    call close_socket
    jmp negative_result
idle:
    mov $162, %eax
    mov $long_pause, %ebx
    xor %ecx, %ecx
    int $0x80
    jmp require_closed
trailing:
    mov $hello_request, %ecx
    mov $28, %edx
    call send_all
    mov $ready_response, %ecx
    mov $9, %edx
    call expect
    jmp require_closed
oversized:
    mov $hello_request, %ecx
    mov $28, %edx
    call send_all
    jmp require_closed
require_closed:
    mov $371, %eax
    mov socket_fd, %ebx
    mov $reply, %ecx
    mov $1024, %edx
    xor %esi, %esi
    xor %edi, %edi
    xor %ebp, %ebp
    int $0x80
    test %eax, %eax
    jne wrong_reply
negative_result:
    mov $20, %ebx
    jmp exit
success:
    mov $4, %eax
    mov $1, %ebx
    mov $marker, %ecx
    mov $8, %edx
    int $0x80
    xor %ebx, %ebx
    jmp exit
bad_arguments:
    mov $2, %ebx
    jmp exit
connect_failure:
    mov $10, %ebx
    jmp exit
io_failure:
    mov $11, %ebx
    jmp exit
wrong_reply:
    mov $14, %ebx
exit:
    mov $1, %eax
    int $0x80

.section .data
.align 4
mode: .long 0
socket_fd: .long 0
first_fd: .long 0
cursor: .long 0
remaining: .long 0
expected: .long 0
received: .long 0
address: .short 2,0
    .byte 127,0,0,1
    .zero 8
short_pause: .long 0,20000000
long_pause: .long 0,300000000
hello_request: .ascii "HELLO\n"
auth_request: .ascii "AUTH test\n"
config_request: .ascii "GET CONFIG\n"
extra: .byte 'X'
ready_response: .ascii "READY\n"
ok_response: .ascii "OK\n"
config_response: .ascii "interval=30\n"
marker: .ascii "NET4_OK\n"

.section .bss
.align 4
reply: .skip 1024

.section .note.GNU-stack,"",@progbits
