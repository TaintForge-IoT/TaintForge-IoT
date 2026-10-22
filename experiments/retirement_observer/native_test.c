/* Native protocol harness, NOT a QEMU run. Socketpair supplied by Python.
 * Uses the real observer state machine; guest register/memory APIs are mocks.
 * A host-thread guest API call aborts so the STAMP path is tested explicitly.
 */
#include "observer.c"
static pthread_t cpu_thread;
static uint32_t mock_pc = 0x8048000;
static uint32_t mock_eip_lag;

bool qemu_plugin_read_register(struct qemu_plugin_register *handle, GByteArray *buf)
{
    if (!pthread_equal(cpu_thread, pthread_self())) _exit(91);
    uintptr_t index = (uintptr_t)handle;
    uint32_t value = index == PC ? mock_pc - mock_eip_lag :
                     index == SP ? 0x12345000 : (uint32_t)index;
    unsigned char bytes[4] = {value, value>>8, value>>16, value>>24};
    g_byte_array_append(buf, bytes, 4);
    return true;
}

bool qemu_plugin_read_memory_vaddr(uint64_t address, GByteArray *buf, size_t len)
{
    if (!pthread_equal(cpu_thread, pthread_self()) || address != 0x12345000 || len != 32) _exit(92);
    unsigned char data[32] = {0};
    g_byte_array_append(buf, data, 32);
    return true;
}

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    channel = atoi(argv[1]);
    const char *mode = argv[2];
    mock_eip_lag = !strcmp(mode, "lazy-eip") ? 4 : 0;
    cpu_thread = pthread_self();
    pause_ms = 400;
    total_ms = !strcmp(mode,"total-timeout") ? 550 : 4000;
    total_deadline = now_ms() + total_ms;
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr,CLOCK_MONOTONIC);
    pthread_cond_init(&changed,&attr);
    pthread_condattr_destroy(&attr);
    for (unsigned i=0;i<NREG;++i) {found[i]=true;handles[i]=(void *)(uintptr_t)i;}
    if (pthread_create(&host_thread,NULL,control_host,NULL)) return 3;
    observe(0,(void *)(uintptr_t)mock_pc);
    if (!strcmp(mode,"early")) observer_exit(0,NULL);
    if (!strcmp(mode,"second-vcpu")) observe(1,(void *)(uintptr_t)mock_pc);
    if (!strcmp(mode,"fork")) syscall_guard(0,0,2,0,0,0,0,0,0,0,0);
    /* Simulate a Phase-1 permit wait: CPU does not service observer commands.
     * STAMP must still reply from the host thread during these 150 ms. */
    usleep(150000);
    for (;;) {
        ++mock_pc;
        observe(0,(void *)(uintptr_t)mock_pc);
        pthread_mutex_lock(&lock);
        bool done = state == FINAL_RUN;
        pthread_mutex_unlock(&lock);
        if (done) break;
        usleep(100);
    }
    if (!strcmp(mode,"fork-after")) syscall_guard(0,0,120,0,0,0,0,0,0,0,0);
    ++mock_pc;
    observe(0,(void *)(uintptr_t)mock_pc);
    observer_exit(0,NULL);
    return 0;
}
