/* Benign static i386 input: unpack a finite loop, then validate a network reply.
 * NET6_TRANSPORT: 0=ordered TCP, 1=UDP, 2=DNS/UDP, 3=DNS/TCP.
 * NET6_STALL leaves the client alive after its first validated TCP reply.
 * NET6_FAILURE_GRACE_MS keeps a failed repair probe alive for observer evidence.
 * NET6_SUCCESS_GRACE_MS reserves observation time after a validated dialogue.
 */
.ifndef NET6_PORT
.set NET6_PORT,4444
.endif
.ifndef NET6_TRANSPORT
.set NET6_TRANSPORT,0
.endif
.ifndef NET6_STALL
.set NET6_STALL,0
.endif
.ifndef NET6_IP0
.set NET6_IP0,127
.set NET6_IP1,0
.set NET6_IP2,0
.set NET6_IP3,1
.endif
.ifndef NET6_WORK
.set NET6_WORK,20000000
.endif
.ifndef NET6_FAILURE_GRACE_MS
.set NET6_FAILURE_GRACE_MS,0
.endif
.if NET6_FAILURE_GRACE_MS < 0 || NET6_FAILURE_GRACE_MS > 10000 || NET6_FAILURE_GRACE_MS % 10 != 0
.error "NET6_FAILURE_GRACE_MS must be 0..10000 in 10 ms steps"
.endif
.ifndef NET6_SUCCESS_GRACE_MS
.set NET6_SUCCESS_GRACE_MS,0
.endif
.if NET6_SUCCESS_GRACE_MS < 0 || NET6_SUCCESS_GRACE_MS > 10000 || NET6_SUCCESS_GRACE_MS % 10 != 0
.error "NET6_SUCCESS_GRACE_MS must be 0..10000 in 10 ms steps"
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
    jnz failed
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
    jnz failed
    /* Phase 1 discovers the written page through an indirect transfer. */
    mov $payload_page,%eax
    call *%eax
    mov $359,%eax
    mov $2,%ebx
.if NET6_TRANSPORT == 1 || NET6_TRANSPORT == 2
    mov $2,%ecx
.else
    mov $1,%ecx
.endif
    xor %edx,%edx
    int $0x80
    test %eax,%eax
    js failed
    mov %eax,fd
    mov $362,%eax
    mov fd,%ebx
    mov $address,%ecx
    mov $16,%edx
    int $0x80
    test %eax,%eax
    js failed
.if NET6_TRANSPORT == 0
    mov $hello,%ecx
    mov $6,%edx
    call send_all
    mov $ready,%edi
    mov $6,%edx
    call receive_exact
.if NET6_STALL
1:  jmp 1b
.endif
    mov $auth,%ecx
    mov $10,%edx
    call send_all
    mov $accepted,%edi
    mov $3,%edx
    call receive_exact
    mov $request,%ecx
    mov $11,%edx
    call send_all
    mov $configuration,%edi
    mov $12,%edx
    call receive_exact
.elseif NET6_TRANSPORT == 1
    mov $ping,%ecx
    mov $4,%edx
    call send_all
    mov $pong,%edi
    mov $4,%edx
    call receive_exact
.else
.if NET6_TRANSPORT == 3
    mov $query_frame,%ecx
    mov $32,%edx
.else
    mov $query,%ecx
    mov $30,%edx
.endif
    call send_all
.if NET6_TRANSPORT == 3
    mov $answer_frame,%edi
    mov $48,%edx
.else
    mov $answer,%edi
    mov $46,%edx
.endif
    call receive_exact
.endif
    mov $6,%eax
    mov fd,%ebx
    int $0x80
    mov $4,%eax
    mov $1,%ebx
    mov $marker,%ecx
    mov $8,%edx
    int $0x80
    cmp $8,%eax
    jne failed
success_wait:
.if NET6_SUCCESS_GRACE_MS
    /* Keep this fixed test input alive while the independent controller
     * checks unmapping and performs its post-unmap hold. The marker was
     * emitted only after validating every reply byte.
     */
    mov $(NET6_SUCCESS_GRACE_MS / 10),%edi
1:
    mov $162,%eax
    mov $observation_pause,%ebx
    xor %ecx,%ecx
    int $0x80
    dec %edi
    jnz 1b
.endif
    xor %ebx,%ebx
    jmp quit
failed:
.if NET6_FAILURE_GRACE_MS
    /* A missing service is expected in the first repair attempt. Yield in
     * bounded 10 ms slices so the independent observer can hold and resume
     * the live vCPU after checking that Phase 1 was actually unmapped.
     * The failure code and absence of NET6_OK remain the application result.
     */
    mov $(NET6_FAILURE_GRACE_MS / 10),%edi
1:
    mov $162,%eax
    mov $failure_pause,%ebx
    xor %ecx,%ecx
    int $0x80
    dec %edi
    jnz 1b
.endif
    mov $14,%ebx
quit:
    mov $1,%eax
    int $0x80

send_all:
    mov %ecx,cursor
    mov %edx,remaining
1:
    mov $4,%eax
    mov fd,%ebx
    mov cursor,%ecx
    mov remaining,%edx
    int $0x80
    test %eax,%eax
    jle failed
    add %eax,cursor
    sub %eax,remaining
    jne 1b
    ret

receive_exact:
    mov %edi,expected
    mov %edx,remaining
    mov $reply,cursor
1:
    mov $3,%eax
    mov fd,%ebx
    mov cursor,%ecx
    mov remaining,%edx
    int $0x80
    test %eax,%eax
    jle failed
    mov %eax,%ecx
    mov cursor,%esi
    mov expected,%edi
    cld
    repe cmpsb
    jne failed
    mov %edi,expected
    add %eax,cursor
    sub %eax,remaining
    jne 1b
    ret

.section .rodata
hello: .ascii "HELLO\n"
ready: .ascii "READY\n"
auth: .ascii "AUTH test\n"
accepted: .ascii "OK\n"
request: .ascii "GET CONFIG\n"
configuration: .ascii "interval=30\n"
ping: .ascii "ping"
pong: .ascii "pong"
marker: .ascii "NET6_OK\n"
.if NET6_FAILURE_GRACE_MS
failure_pause: .long 0,10000000
.endif
.if NET6_SUCCESS_GRACE_MS
observation_pause: .long 0,10000000
.endif
query_frame: .byte 0,30
query:
    .byte 0x12,0x34,0x01,0,0,1,0,0,0,0,0,0
    .byte 4
    .ascii "net6"
    .byte 7
    .ascii "invalid"
    .byte 0,0,1,0,1
answer_frame: .byte 0,46
answer:
    .byte 0x12,0x34,0x81,0x80,0,1,0,1,0,0,0,0
    .byte 4
    .ascii "net6"
    .byte 7
    .ascii "invalid"
    .byte 0,0,1,0,1
    .byte 0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,192,0,2,7
payload_source:
    push %ebp
    mov %esp,%ebp
    mov $NET6_WORK,%ecx
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
fd: .long -1
cursor: .long 0
remaining: .long 0
expected: .long 0
address:
    .short 2
    .byte (NET6_PORT >> 8) & 255, NET6_PORT & 255
    .byte NET6_IP0,NET6_IP1,NET6_IP2,NET6_IP3
    .zero 8
.section .payload,"aw",@progbits
.balign 4096
payload_page: .space 4096
.section .bss
reply: .skip 1024
.section .note.GNU-stack,"",@progbits
