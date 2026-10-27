/* SPDX-License-Identifier: GPL-2.0-or-later
 * M2: QEMU 11.0.1/API 6, benign single-process i386 experiment.
 * No guest addresses/options, no borrowed Phase-1 pointers. The host thread
 * only reads commands and atomics. All guest reads are on the vCPU thread.
 * Bootstrap hold precedes any guest execution. HOLD 2 is controller-gated
 * after live module disappearance, never by an uninstall/flush callback.
 */
#define _GNU_SOURCE
#include <qemu-plugin.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include "../afl_file/coverage.h"

_Static_assert(QEMU_PLUGIN_VERSION == 6, "pinned API 6 required");
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
static const char *const names[] = {"eax","ebx","ecx","edx","esi","edi","ebp","esp","eip"};
enum { NREG=9, SP=7, PC=8 };
static struct qemu_plugin_register *handles[NREG];
static bool found[NREG]; /* A valid opaque EAX handle can be NULL. */
enum State { BOOT, HELD1, CHECK1, CHECKED1, RESUME1, RUNNING,
             REQUEST2, HELD2, CHECK2, CHECKED2, RESUME2, FINAL_RUN };
static enum State state = BOOT;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t send_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed;
static atomic_bool hold_requested = true, finished;
static atomic_uint vcpus;
static _Atomic uint64_t sequence;
static uint64_t pause_ms, total_ms, total_deadline;
static bool stamped;
static int channel = -1;
static pthread_t host_thread;
static bool warm_mode, warm_detached, warm_child;
extern int qemu_plugin_tf_warm_configure(const char *, const char *, uint64_t, int,
                                        void (*)(void), void (*)(void)) __attribute__((weak));
extern void qemu_plugin_tf_warm_arm(void) __attribute__((weak));

static void warm_prepare(void);
static void warm_child_start(void)
{
    warm_child = true;
    close(channel);
    channel = -1;
    tf_afl_previous = 0;
}


static uint64_t now_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) _exit(126);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}

static _Noreturn void abort_run(int code, const char *reason)
{
    char line[160];
    int n = snprintf(line, sizeof(line), "OBSERVER_ABORT code=%d reason=%s\n", code, reason);
    if (n > 0 && (size_t)n < sizeof(line)) {
        ssize_t ignored = write(STDERR_FILENO, line, (size_t)n);
        (void)ignored;
    }
    _exit(code);
}

static void send_frame(const char *frame)
{
    pthread_mutex_lock(&send_lock);
    size_t off = 0, len = strlen(frame);
    uint64_t deadline = now_ms() + 1000;
    if (deadline > total_deadline) deadline = total_deadline;
    while (off < len) {
        if (now_ms() >= deadline) abort_run(124, "send_timeout");
        ssize_t n = send(channel, frame + off, len - off, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
            struct pollfd p = {.fd=channel, .events=POLLOUT};
            (void)poll(&p, 1, 10);
            continue;
        }
        abort_run(125, "controller_lost");
    }
    pthread_mutex_unlock(&send_lock);
}

static void dispatch(const char *cmd)
{
    pthread_mutex_lock(&lock);
    if (!strcmp(cmd, "STAMP") && state == RUNNING && !stamped) {
        stamped = true;
        char line[192];
        snprintf(line, sizeof(line), "{\"event\":\"stamp\",\"protocol\":3,\"host_pid\":%ld,"
                 "\"seq\":%llu,\"monotonic_ms\":%llu}\n", (long)getpid(),
                 (unsigned long long)atomic_load(&sequence), (unsigned long long)now_ms());
        send_frame(line);
    } else if (!strcmp(cmd, "HOLD 2") && state == RUNNING && stamped) {
        state = REQUEST2;
        atomic_store(&hold_requested, true);
    } else if (!strcmp(cmd, "CHECK 1") && state == HELD1) state = CHECK1;
    else if (!strcmp(cmd, "RESUME 1") && state == CHECKED1) state = RESUME1;
    else if (!strcmp(cmd, "CHECK 2") && state == HELD2) state = CHECK2;
    else if (!strcmp(cmd, "RESUME 2") && state == CHECKED2) state = RESUME2;
    else abort_run(126, "command_order");
    pthread_cond_broadcast(&changed);
    pthread_mutex_unlock(&lock);
}

static void *control_host(void *unused)
{
    (void)unused;
    char cmd[32];
    size_t used = 0;
    while (!atomic_load(&finished)) {
        if (now_ms() >= total_deadline) abort_run(124, "total_timeout");
        struct pollfd p = {.fd=channel, .events=POLLIN | POLLRDHUP};
        int n = poll(&p, 1, 20);
        if (atomic_load(&finished)) break;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) abort_run(126, "poll_failed");
        if (p.revents & (POLLHUP | POLLRDHUP | POLLERR | POLLNVAL)) abort_run(125, "controller_lost");
        if (!(p.revents & POLLIN)) continue;
        char c;
        n = (int)recv(channel, &c, 1, MSG_DONTWAIT);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) abort_run(125, "controller_lost");
        if (c == '\n') { cmd[used] = 0; dispatch(cmd); used = 0; }
        else {
            if (c < 32 || c > 126 || used + 1 >= sizeof(cmd)) abort_run(126, "invalid_command");
            cmd[used++] = c;
        }
    }
    return NULL;
}

static void format_snapshot(char *line, size_t size, unsigned point, unsigned sample,
                            uint64_t seq, uint64_t pc)
{
    if (!pc || pc > UINT32_MAX) abort_run(126, "callback_pc_range");
    uint32_t regs[NREG];
    GByteArray *bytes = g_byte_array_new();
    for (unsigned i=0; i<NREG; ++i) {
        g_byte_array_set_size(bytes, 0);
        if (!found[i] || !qemu_plugin_read_register(handles[i], bytes) || bytes->len != 4)
            abort_run(126, "register_read");
        regs[i] = (uint32_t)bytes->data[0] | (uint32_t)bytes->data[1]<<8 |
                  (uint32_t)bytes->data[2]<<16 | (uint32_t)bytes->data[3]<<24;
    }
    /* Raw EIP may lag within a TB; callback vaddr is the instruction PC. */
    g_byte_array_set_size(bytes, 0);
    bool stack_ok = qemu_plugin_read_memory_vaddr(regs[SP], bytes, 32) && bytes->len == 32;
    char stack[65] = "";
    if (stack_ok) {
        const char *hex = "0123456789abcdef";
        for (unsigned i=0; i<32; ++i) {
            stack[2*i] = hex[bytes->data[i]>>4]; stack[2*i+1] = hex[bytes->data[i]&15];
        }
    }
    g_byte_array_free(bytes, true);
    int n = snprintf(line, size, "{\"event\":\"snapshot\",\"protocol\":3,\"host_pid\":%ld,"
        "\"point\":%u,\"sample\":%u,\"seq\":%llu,\"pc\":%llu,\"monotonic_ms\":%llu,"
        "\"pc_source\":\"qemu_plugin_insn_vaddr\",\"qemu_eip\":%u,"
        "\"regs\":[%u,%u,%u,%u,%u,%u,%u,%u],\"stack_readable\":%s,\"stack_hex\":\"%s\"}\n",
        (long)getpid(), point, sample, (unsigned long long)seq, (unsigned long long)pc,
        (unsigned long long)now_ms(), regs[PC], regs[0],regs[1],regs[2],regs[3],regs[4],regs[5],regs[6],regs[7],
        stack_ok ? "true" : "false", stack);
    if (n < 0 || (size_t)n >= size) abort_run(126, "snapshot_size");
}

static void snapshot(unsigned point, unsigned sample, uint64_t seq, uint64_t pc)
{
    char line[1024];
    format_snapshot(line, sizeof(line), point, sample, seq, pc);
    send_frame(line);
}

static void observe(unsigned vcpu, void *userdata)
{
    if (vcpu != 0) abort_run(126, "multiple_vcpu");
    uint64_t seq = atomic_fetch_add(&sequence, 1) + 1;
    if (!seq) abort_run(126, "sequence_overflow");
    if (!atomic_load(&hold_requested)) return;
    pthread_mutex_lock(&lock);
    unsigned point = state == BOOT ? 1 : state == REQUEST2 ? 2 : 0;
    if (!point) abort_run(126, "hold_state");
    state = point == 1 ? HELD1 : HELD2;
    uint64_t deadline = now_ms() + pause_ms;
    if (deadline > total_deadline) deadline = total_deadline;
    snapshot(point, 1, seq, (uintptr_t)userdata);
    for (;;) {
        if (now_ms() >= deadline) abort_run(124, "hold_timeout");
        if (state == CHECK1 || state == CHECK2) {
            snapshot(point, 2, seq, (uintptr_t)userdata);
            state = point == 1 ? CHECKED1 : CHECKED2;
        } else if (state == RESUME1 || state == RESUME2) {
            state = point == 1 ? RUNNING : FINAL_RUN;
            if (point == 2) {
                tf_afl_arm();
                if (warm_mode) qemu_plugin_tf_warm_arm();
            }
            atomic_store(&hold_requested, false);
            char line[128];
            snprintf(line, sizeof(line), "{\"event\":\"resumed\",\"protocol\":3,\"point\":%u,\"seq\":%llu}\n",
                     point, (unsigned long long)seq);
            send_frame(line);
            break;
        }
        struct timespec t = {.tv_sec=(time_t)(deadline/1000), .tv_nsec=(long)(deadline%1000)*1000000};
        int rc = pthread_cond_timedwait(&changed, &lock, &t);
        if (rc && rc != ETIMEDOUT) abort_run(126, "condition_wait");
    }
    pthread_mutex_unlock(&lock);
}

static void init_vcpu(qemu_plugin_id_t id, unsigned vcpu)
{
    (void)id;
    if (vcpu || atomic_fetch_add(&vcpus, 1)) abort_run(126, "multiple_vcpu");
    GArray *regs = qemu_plugin_get_registers();
    if (!regs) abort_run(126, "no_registers");
    for (unsigned i=0; i<regs->len; ++i) {
        qemu_plugin_reg_descriptor *r = &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        for (unsigned k=0; k<NREG; ++k) {
            if (r->name && !strcmp(r->name, names[k])) { handles[k]=r->handle; found[k]=true; }
        }
    }
    g_array_free(regs, true);
    for (unsigned k=0; k<NREG; ++k) if (!found[k]) abort_run(126, "missing_register");
}

static void translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    if (tf_afl_record)
        qemu_plugin_register_vcpu_tb_exec_cb(tb, tf_afl_block, QEMU_PLUGIN_CB_NO_REGS,
            (void *)(uintptr_t)qemu_plugin_tb_vaddr(tb));
    for (size_t i=0; i<qemu_plugin_tb_n_insns(tb); ++i) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, observe, QEMU_PLUGIN_CB_R_REGS,
                                             (void *)(uintptr_t)qemu_plugin_insn_vaddr(insn));
    }
}

static void syscall_guard(qemu_plugin_id_t id, unsigned vcpu, int64_t num,
                          uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                          uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8)
{
    (void)id; (void)vcpu; (void)a1; (void)a2; (void)a3; (void)a4;
    (void)a5; (void)a6; (void)a7; (void)a8;
    /* No inherited guest IPC/timers in the file-only checkpoint profile. */
    if (warm_mode && !warm_detached &&
        (num == 27 || num == 104 || num == 102 || num == 42 || num == 331 ||
         num == 254 || num == 329 || num == 321 || num == 327 || num == 322 ||
         num == 323 || num == 328 || num == 259 || num == 260 ||
         (num >= 359 && num <= 373)))
        abort_run(126, "unsupported_precheckpoint_resource");
    tf_afl_syscall(num, a1, a2);
    /* i386 fork, execve, clone, vfork, execveat, clone3. Remains after retire. */
    if (num == 2 || num == 11 || num == 120 || num == 190 || num == 358 || num == 435)
        abort_run(126, "unsupported_process_transition");
}

static void warm_prepare(void)
{
    atomic_store(&finished, true);
    pthread_join(host_thread, NULL);
    warm_detached = true;
    char line[192];
    snprintf(line, sizeof(line), "{\"event\":\"warm_checkpoint\",\"protocol\":3,"
        "\"host_pid\":%ld,\"seq\":%llu}\n", (long)getpid(),
        (unsigned long long)atomic_load(&sequence));
    send_frame(line);
}

static void observer_exit(qemu_plugin_id_t id, void *unused)
{
    (void)id; (void)unused;
    if (warm_child) { tf_afl_finish(); return; }
    pthread_mutex_lock(&lock);
    bool complete = state == FINAL_RUN;
    atomic_store(&finished, true);
    pthread_mutex_unlock(&lock);
    if (!warm_detached) pthread_join(host_thread, NULL);
    tf_afl_finish();
    char line[192];
    snprintf(line, sizeof(line), "{\"event\":\"%s\",\"protocol\":3,\"host_pid\":%ld,\"seq\":%llu}\n",
             complete ? "done" : "early_exit", (long)getpid(), (unsigned long long)atomic_load(&sequence));
    send_frame(line);
    close(channel);
    if (!complete) abort_run(123, "exit_before_observation");
}

static bool number(const char *s, uint64_t *value)
{
    char *end; errno=0;
    if (!*s || *s=='-' || *s=='+') return false;
    unsigned long long n=strtoull(s, &end, 10);
    if (errno || *end) return false;
    *value=n; return true;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
    if (info->system_emulation || strcmp(info->target_name,"i386") ||
        info->version.cur != 6 || info->version.min > 6 || argc < 4 || argc > 9) return -1;
    const char *path=NULL;
    const char *coverage=NULL, *afl_input=NULL, *warm_endpoint=NULL;
    uint64_t warm_rss=2048;
    uint64_t controller=0, controller_uid=getuid();
    unsigned seen=0;
    const char *keys[]={"pause-ms=","total-ms=","controller="};
    uint64_t *values[]={&pause_ms,&total_ms,&controller};
    for (int i=0; i<argc; ++i) {
        unsigned bit=0;
        if (!strncmp(argv[i],"socket=",7)) { path=argv[i]+7; bit=8; }
        else if (!strncmp(argv[i],"controller-uid=",15) && number(argv[i]+15,&controller_uid)) bit=16;
        else if (!strncmp(argv[i],"afl-coverage=",13)) { coverage=argv[i]+13; bit=32; }
        else if (!strncmp(argv[i],"afl-input=",10)) { afl_input=argv[i]+10; bit=64; }
        else if (!strncmp(argv[i],"afl-warm=",9)) { warm_endpoint=argv[i]+9; bit=128; }
        else if (!strncmp(argv[i],"afl-warm-rss=",13) && number(argv[i]+13,&warm_rss)) bit=256;
        else for (unsigned k=0;k<3;++k) {
            size_t n=strlen(keys[k]);
            if (!strncmp(argv[i],keys[k],n) && number(argv[i]+n,values[k])) {bit=1U<<k;break;}
        }
        if (!bit || (seen&bit)) return -1;
        seen|=bit;
    }
    struct sockaddr_un addr={.sun_family=AF_UNIX};
    unsigned required = 15U | (seen & 16U) | ((coverage || afl_input) ? 96U : 0U) | (warm_endpoint ? 384U : 0U);
    if (seen!=required || controller_uid>INT_MAX || !path || !*path || strlen(path)>=sizeof(addr.sun_path) ||
        pause_ms<100 || pause_ms>60000 || total_ms<100 || total_ms>86400000 ||
        !controller || controller>INT_MAX) return -1;
    if (tf_afl_open_map(coverage, afl_input)) return -1;
    total_deadline=now_ms()+total_ms;
    channel=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if (channel<0) return -1;
    strcpy(addr.sun_path,path);
    struct ucred peer;
    socklen_t len=sizeof(peer);
    if (connect(channel,(struct sockaddr *)&addr,sizeof(addr)) ||
        getsockopt(channel,SOL_SOCKET,SO_PEERCRED,&peer,&len) ||
        len!=sizeof(peer) || peer.uid!=(uid_t)controller_uid || peer.pid!=(pid_t)controller) {close(channel);return -1;}
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr) || pthread_condattr_setclock(&attr,CLOCK_MONOTONIC) ||
        pthread_cond_init(&changed,&attr)) {close(channel);return -1;}
    pthread_condattr_destroy(&attr);
    if (pthread_create(&host_thread,NULL,control_host,NULL)) {close(channel);return -1;}
    if (warm_endpoint) {
        if (!coverage || !warm_rss || !qemu_plugin_tf_warm_configure || !qemu_plugin_tf_warm_arm ||
            qemu_plugin_tf_warm_configure(afl_input, warm_endpoint, warm_rss, channel,
                                         warm_prepare, warm_child_start)) return -1;
        warm_mode = true;
    }
    qemu_plugin_register_vcpu_init_cb(id,init_vcpu);
    qemu_plugin_register_vcpu_tb_trans_cb(id,translate);
    qemu_plugin_register_vcpu_syscall_cb(id,syscall_guard);
    if (tf_afl_record) qemu_plugin_register_vcpu_syscall_ret_cb(id,tf_afl_sysret);
    qemu_plugin_register_atexit_cb(id,observer_exit,NULL);
    return 0;
}
