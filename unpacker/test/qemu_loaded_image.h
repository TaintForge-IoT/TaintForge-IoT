#ifndef TF_QEMU_LOADED_IMAGE_H
#define TF_QEMU_LOADED_IMAGE_H

#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int tf_qemu_loaded_image_fd(const void *symbol) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps)
        return -1;
    unsigned long long start, end, offset, inode = 0;
    unsigned device_major = 0, device_minor = 0;
    char line[8192], permissions[5];
    bool found = false;
    while (fgets(line, sizeof(line), maps)) {
        if (sscanf(line, "%llx-%llx %4s %llx %x:%x %llu", &start, &end, permissions,
                   &offset, &device_major, &device_minor, &inode) == 7 &&
            (uintptr_t)symbol >= start && (uintptr_t)symbol < end &&
            permissions[2] == 'x' && inode != 0) {
            found = true;
            break;
        }
    }
    fclose(maps);
    if (!found)
        return -1;
    Dl_info image = {0};
    const char *paths[2] = {"/proc/self/exe", NULL};
    if (dladdr(symbol, &image))
        paths[1] = image.dli_fname;
    for (unsigned i = 0; i < 2; ++i) {
        if (!paths[i])
            continue;
        int fd = open(paths[i], O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0)
            continue;
        struct stat info;
        if (!fstat(fd, &info) && S_ISREG(info.st_mode) && info.st_ino == inode &&
            major(info.st_dev) == device_major && minor(info.st_dev) == device_minor)
            return fd;
        close(fd);
    }
    return -1;
}

#endif
