#define _GNU_SOURCE
#include "qemu_loaded_image.h"

__attribute__((noinline)) void anchor(void) {
    __asm__ volatile("" ::: "memory");
}

int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    struct stat expected, actual, proc;
    int fd = tf_qemu_loaded_image_fd((const void *)anchor);
    if (fd < 0 || stat(argv[1], &expected) || fstat(fd, &actual))
        return 3;
    bool same = expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino;
    bool proc_same = !stat("/proc/self/exe", &proc) && proc.st_dev == actual.st_dev && proc.st_ino == actual.st_ino;
    close(fd);
    printf("{\"image_matches\":%s,\"proc_exe_matches\":%s}\n",
           same ? "true" : "false", proc_same ? "true" : "false");
    return same ? 0 : 4;
}
