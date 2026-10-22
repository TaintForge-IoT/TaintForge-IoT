#define _GNU_SOURCE
#include "phase1_io.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static ssize_t fail_write(void *cookie, const char *data, size_t size) {
    (void)cookie; (void)data; (void)size;
    errno = ENOSPC;
    return -1;
}
static FILE *close_failure_stream;
int __real_fclose(FILE *stream);
int __wrap_fclose(FILE *stream) {
    bool fail = stream == close_failure_stream;
    int result = __real_fclose(stream);
    if (fail) { close_failure_stream = NULL; errno = EIO; return EOF; }
    return result;
}

int main(void) {
    char *quoted = tf_json_string("quote\" slash\\ newline\n");
    assert(!strcmp(quoted, "\"quote\\\" slash\\\\ newline\\u000a\""));
    g_free(quoted);
    char invalid[] = {'/', (char)0xff, 0};
    quoted = tf_json_bytes_field("path", invalid);
    assert(!strcmp(quoted, "\"path\":null,\"path_bytes_base64\":\"L/8=\""));
    g_free(quoted);

    char temporary[] = "/tmp/tf-phase1-io-XXXXXX";
    char *directory = mkdtemp(temporary);
    assert(directory);
    char *path = g_build_filename(directory, "artifact", NULL);
    TfAtomicFile file;
    assert(tf_atomic_open(&file, path));
    assert(tf_write_all(file.stream, "abcdef", 6));
    assert(tf_atomic_commit(&file));
    char hash[65]; uint64_t size;
    assert(tf_file_digest(path, hash, &size) && size == 6);
    assert(!strcmp(hash, "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"));
    assert(!tf_atomic_open(&file, path));
    unlink(path);
    assert(symlink("/dev/null", path) == 0);
    assert(!tf_atomic_open(&file, path));
    unlink(path);

    /* Fault injection at the stream boundary exercises write and close errors
     * without depending on root privileges or a particular filesystem. */
    cookie_io_functions_t operations = {.write = fail_write};
    FILE *stream = fopencookie(NULL, "w", operations);
    assert(stream);
    setbuf(stream, NULL);
    assert(!tf_write_all(stream, "x", 1));
    fclose(stream);

    assert(tf_atomic_open(&file, path));
    assert(tf_write_all(file.stream, "valid data", 10));
    close_failure_stream = file.stream;
    assert(!tf_atomic_commit(&file));
    assert(access(path, F_OK) != 0);

    assert(tf_atomic_open(&file, path));
    struct rlimit previous, limit;
    assert(getrlimit(RLIMIT_FSIZE, &previous) == 0);
    limit = previous;
    limit.rlim_cur = 1;
    signal(SIGXFSZ, SIG_IGN);
    assert(setrlimit(RLIMIT_FSIZE, &limit) == 0);
    fwrite("too long", 1, 8, file.stream);
    assert(!tf_atomic_commit(&file));
    assert(setrlimit(RLIMIT_FSIZE, &previous) == 0);
    assert(access(path, F_OK) != 0);

    char *missing = g_build_filename(directory, "absent", "artifact", NULL);
    assert(!tf_atomic_open(&file, missing));
    g_free(missing); g_free(path);
    assert(rmdir(directory) == 0);
    puts("PASS: JSON bytes; exact writes; immutable publication; missing paths; symlinks; ENOSPC and close failures");
    return 0;
}
