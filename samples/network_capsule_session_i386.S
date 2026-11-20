/* Benign i386 session fixture with the same written-code entry as NET-6. */
.ifndef NET8_PORT
.set NET8_PORT,4444
.endif
.ifndef NET8_MODE
.set NET8_MODE,0
.endif
.ifndef NET8_WORK
.set NET8_WORK,20000000
.endif
.ifndef NET8_EXIT_GRACE_MS
.set NET8_EXIT_GRACE_MS,0
.endif
.if NET8_EXIT_GRACE_MS < 0 || NET8_EXIT_GRACE_MS > 10000 || NET8_EXIT_GRACE_MS % 10 != 0
.error "NET8_EXIT_GRACE_MS must be 0..10000 in 10 ms steps"
.endif
.global _start
.section .text
_start:
    mov $125,%eax
    mov $payload_page,%ebx
    mov $4096,%ecx
    mov $3,%edx
    int $0x80
    test %eax,%eax
    jnz io_failure
    mov $payload_source,%esi
    mov $payload_page,%edi
    mov $payload_end-payload_source,%ecx
    cld
    rep movsb
    mov $125,%eax
    mov $payload_page,%ebx
    mov $4096,%ecx
    mov $5,%edx
    int $0x80
    test %eax,%eax
    jnz io_failure
    /* Phase 1 discovers the written page through an indirect transfer. */
    mov $payload_page,%eax
    call *%eax
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
    mov $373, %eax
    mov socket_fd, %ebx
    mov $1, %ecx
    int $0x80
    test %eax, %eax
    js io_failure
    jmp require_closed
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
    cmp $8, %eax
    jne io_failure
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
.if NET8_EXIT_GRACE_MS
    /* Observation time for the fixed fixture, preserving its application
     * outcome. A fast network dialogue must not decide controller timing.
     */
    mov %ebx,%ebp
    mov $(NET8_EXIT_GRACE_MS / 10),%edi
1:
    mov $162,%eax
    mov $observation_pause,%ebx
    xor %ecx,%ecx
    int $0x80
    dec %edi
    jnz 1b
    mov %ebp,%ebx
.endif
    mov $1, %eax
    int $0x80

payload_source:
    push %ebp
    mov %esp,%ebp
    mov $NET8_WORK,%ecx
1:
    test $1,%ecx
    jz 2f
    nop
2:
    loop 1b
    pop %ebp
    ret
payload_end:

.section .data
.align 4
mode: .long NET8_MODE
socket_fd: .long 0
first_fd: .long 0
cursor: .long 0
remaining: .long 0
expected: .long 0
received: .long 0
address: .short 2
    .byte (NET8_PORT >> 8) & 255, NET8_PORT & 255
    .byte 127,0,0,1
    .zero 8
short_pause: .long 0,20000000
long_pause: .long 0,300000000
.if NET8_EXIT_GRACE_MS
observation_pause: .long 0,10000000
.endif
hello_request: .ascii "HELLO\n"
auth_request: .ascii "AUTH test\n"
config_request: .ascii "GET CONFIG\n"
extra: .byte 'X'
ready_response: .ascii "READY\n"
ok_response: .ascii "OK\n"
config_response: .ascii "interval=30\n"
marker: .ascii "NET8_OK\n"

.section .payload,"aw",@progbits
.balign 4096
payload_page: .space 4096
.section .bss
.align 4
reply: .skip 1024

.section .note.GNU-stack,"",@progbits
