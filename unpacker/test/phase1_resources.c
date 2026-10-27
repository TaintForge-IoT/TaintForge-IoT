#define _GNU_SOURCE
#undef malloc
#undef calloc
#undef realloc
#undef free
#include "phase1_resources.h"
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef TF_RESOURCE_SLOTS
#define TF_RESOURCE_SLOTS 65536U
#endif
#define SLOTS TF_RESOURCE_SLOTS
#define OWNERS 64U
#define DELETED ((void *)(uintptr_t)1)

typedef struct { void *data; size_t size; unsigned owner; } Allocation;
typedef struct { const char *name; uint64_t live, bytes, peak, acquired, released; } Owner;
static Allocation slots[SLOTS];
static Owner owners[OWNERS];
static unsigned owner_count;
static uint64_t limit, live, bytes, peak, acquired, released, wiped;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static _Noreturn void fail(const char *reason) {
    dprintf(2, "CAPSULE_PHASE1_ABORT code=92 reason=%s\n", reason);
    _exit(92);
}

size_t tf_resources_reserved(void) {
    return sizeof(slots) + sizeof(owners) + sizeof(lock) + sizeof(owner_count) +
           sizeof(limit) + sizeof(live) + sizeof(bytes) + sizeof(peak) +
           sizeof(acquired) + sizeof(released) + sizeof(wiped);
}
bool tf_resources_enabled(void) { return limit != 0; }

bool tf_resources_configure(int argc, char **argv) {
    bool seen = false;
    uint64_t value = 0;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "m4-", 3)) continue;
        const char *prefix = "m4-memory-bytes=";
        if (seen || strncmp(argv[i], prefix, strlen(prefix))) return false;
        const char *text = argv[i] + strlen(prefix);
        if (*text < '0' || *text > '9') return false;
        char *end; errno = 0;
        value = strtoull(text, &end, 10);
        if (errno || *end || value < tf_resources_reserved() || value > UINT64_C(137438953472)) return false;
        seen = true;
    }
    if (live) return false;
    memset(slots, 0, sizeof(slots));
    memset(owners, 0, sizeof(owners));
    owner_count = 0;
    live = bytes = peak = acquired = released = wiped = 0;
    limit = value;
    return true;
}

static size_t position(void *data, bool insert) {
    size_t index = ((uintptr_t)data >> 4) % SLOTS, tombstone = SLOTS;
    for (size_t n = 0; n < SLOTS; n++, index = (index + 1) % SLOTS) {
        if (slots[index].data == data) return index;
        if (slots[index].data == DELETED && tombstone == SLOTS) tombstone = index;
        if (!slots[index].data) return insert ? (tombstone == SLOTS ? index : tombstone) : SLOTS;
    }
    return insert ? tombstone : SLOTS;
}

static unsigned owner_id(const char *path) {
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    if (strlen(name) > 120 || strpbrk(name, "\"\\\n\r\t")) fail("invalid_allocation_owner");
    for (unsigned i = 0; i < owner_count; i++)
        if (!strcmp(owners[i].name, name)) return i;
    if (owner_count == OWNERS) fail("allocation_owner_capacity");
    owners[owner_count].name = name;
    return owner_count++;
}

static void reserve(size_t size) {
    uint64_t available = limit - tf_resources_reserved();
    if (bytes > available || size > available - bytes) fail("analysis_memory_budget");
}

static void add(void *data, size_t size, const char *path) {
    size_t index = position(data, true);
    if (index == SLOTS) fail("allocation_ledger_capacity");
    unsigned id = owner_id(path);
    slots[index] = (Allocation){data, size, id};
    ++live; ++acquired; bytes += size;
    if (bytes > peak) peak = bytes;
    Owner *owner = &owners[id];
    ++owner->live; ++owner->acquired; owner->bytes += size;
    if (owner->bytes > owner->peak) owner->peak = owner->bytes;
}

void *tf_alloc_malloc(size_t size, const char *owner) {
    if (!limit) return malloc(size);
    if (!size) size = 1;
    pthread_mutex_lock(&lock);
    reserve(size);
    void *data = malloc(size ? size : 1);
    if (!data) fail("analysis_allocation_failed");
    add(data, size, owner);
    pthread_mutex_unlock(&lock);
    return data;
}

void *tf_alloc_calloc(size_t count, size_t size, const char *owner) {
    if (count && size > SIZE_MAX / count) {
        if (limit) fail("analysis_allocation_overflow");
        errno = ENOMEM; return NULL;
    }
    size_t total = count * size;
    void *data = tf_alloc_malloc(total, owner);
    if (data) memset(data, 0, total);
    return data;
}

void *tf_alloc_malloc_array(size_t count, size_t size, const char *owner) {
    if (count && size > SIZE_MAX / count) {
        if (limit) fail("analysis_allocation_overflow");
        errno = ENOMEM; return NULL;
    }
    return tf_alloc_malloc(count * size, owner);
}

void *tf_alloc_realloc_array(void *data, size_t count, size_t size, const char *owner) {
    if (count && size > SIZE_MAX / count) {
        if (limit) fail("analysis_allocation_overflow");
        errno = ENOMEM; return NULL;
    }
    return tf_alloc_realloc(data, count * size, owner);
}

static void remove_allocation(size_t index) {
    Allocation *a = &slots[index];
    volatile unsigned char *p = a->data;
    for (size_t n = 0; n < a->size; n++) p[n] = 0;
    wiped += a->size;
    --live; ++released; bytes -= a->size;
    Owner *owner = &owners[a->owner];
    --owner->live; ++owner->released; owner->bytes -= a->size;
    a->data = DELETED; a->size = 0; a->owner = 0;
}

void tf_alloc_free(void *data) {
    if (!data) return;
    if (!limit) { free(data); return; }
    pthread_mutex_lock(&lock);
    size_t index = position(data, false);
    if (index != SLOTS) remove_allocation(index);
    free(data);
    pthread_mutex_unlock(&lock);
}

void *tf_alloc_realloc(void *data, size_t size, const char *owner) {
    if (!limit) return realloc(data, size);
    if (!data) return tf_alloc_malloc(size, owner);
    if (!size) { tf_alloc_free(data); return NULL; }
    pthread_mutex_lock(&lock);
    size_t index = position(data, false);
    reserve(size);
    if (bytes + size > peak) peak = bytes + size;
    unsigned id = owner_id(owner);
    if (owners[id].bytes + size > owners[id].peak) owners[id].peak = owners[id].bytes + size;
    void *next;
    if (index == SLOTS) next = realloc(data, size);
    else {
        next = malloc(size);
        if (next) {
            memcpy(next, data, slots[index].size < size ? slots[index].size : size);
            remove_allocation(index);
            free(data);
        }
    }
    if (!next) fail("analysis_allocation_failed");
    add(next, size, owner);
    pthread_mutex_unlock(&lock);
    return next;
}

char *tf_alloc_strndup(const char *text, size_t size, const char *owner) {
    if (!text) return NULL;
    size_t length = strnlen(text, size);
    char *out = tf_alloc_malloc(length + 1, owner);
    if (out) { memcpy(out, text, length); out[length] = 0; }
    return out;
}

char *tf_alloc_strdup(const char *text, const char *owner) {
    return text ? tf_alloc_strndup(text, strlen(text), owner) : NULL;
}

char *tf_alloc_printf(const char *owner, const char *format, ...) {
    va_list args, copy;
    va_start(args, format); va_copy(copy, args);
    int length = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    char *out = length < 0 ? NULL : tf_alloc_malloc((size_t)length + 1, owner);
    if (out) vsnprintf(out, (size_t)length + 1, format, args);
    va_end(args);
    return out;
}

uint64_t tf_resources_remaining(void) {
    pthread_mutex_lock(&lock);
    uint64_t result = live;
    pthread_mutex_unlock(&lock);
    return result;
}

static int summary(char *output, size_t size) {
    return snprintf(output, size, "{\"schema\":1,\"scope\":\"explicit_project_allocations\","
        "\"limit_bytes\":%" PRIu64 ",\"ledger_reserved_bytes\":%zu,\"live_allocations\":%" PRIu64
        ",\"live_bytes\":%" PRIu64 ",\"peak_bytes\":%" PRIu64 ",\"allocations\":%" PRIu64
        ",\"releases\":%" PRIu64 ",\"wiped_bytes\":%" PRIu64 ",\"external_allocations_tracked\":false}",
        limit, tf_resources_reserved(), live, bytes, peak, acquired, released, wiped);
}

int tf_resources_summary(char *output, size_t size) {
    pthread_mutex_lock(&lock);
    int length = summary(output, size);
    pthread_mutex_unlock(&lock);
    return length;
}

void tf_resources_json(FILE *stream, bool detail) {
    pthread_mutex_lock(&lock);
    char text[768];
    int length = summary(text, sizeof(text));
    if (length < 1 || (size_t)length >= sizeof(text)) fail("resource_summary_failed");
    fwrite(text, 1, (size_t)length - 1, stream);
    if (detail) {
        fputs(",\"owners\":[", stream);
        for (unsigned i = 0; i < owner_count; i++) {
            Owner *o = &owners[i];
            fprintf(stream, "%s{\"source\":\"%s\",\"live_allocations\":%" PRIu64
                ",\"live_bytes\":%" PRIu64 ",\"peak_bytes\":%" PRIu64
                ",\"allocations\":%" PRIu64 ",\"releases\":%" PRIu64 "}",
                i ? "," : "", o->name, o->live, o->bytes, o->peak, o->acquired, o->released);
        }
        fputc(']', stream);
    }
    fputc('}', stream);
    pthread_mutex_unlock(&lock);
}
