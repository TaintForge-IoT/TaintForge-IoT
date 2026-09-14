#include "qemu_flags_contract.h"
#include <glib.h>
#include <string.h>

static bool failure(FILE *errors, const char *message) {
    if (errors)
        fprintf(errors, "[REG] EFLAGS receipt rejected: %s\n", message);
    return false;
}

bool tf_qemu_flags_options(int argc, char **argv, const char **receipt, FILE *errors) {
    if (!receipt || argc < 0 || (argc && !argv))
        return failure(errors, "invalid arguments");
    const char *path = NULL;
    for (int i = 0; i < argc; ++i) {
        if (!argv[i])
            return failure(errors, "missing option");
        const char *eq = strchr(argv[i], '=');
        size_t length = eq ? (size_t)(eq - argv[i]) : strlen(argv[i]);
        if (length != sizeof("x86-flags-receipt") - 1 ||
            memcmp(argv[i], "x86-flags-receipt", length))
            continue;
        if (!eq || !eq[1] || path)
            return failure(errors, "x86-flags-receipt requires one nonempty path");
        path = eq + 1;
    }
    *receipt = path;
    return true;
}

bool tf_qemu_flags_receipt_check(const char *receipt, const char *executable, FILE *errors) {
    if (!receipt || !executable)
        return failure(errors, "missing receipt or executable");
    char text[sizeof(TF_QEMU_FLAGS_RECEIPT_PREFIX) - 1 + 64 + sizeof(TF_QEMU_FLAGS_RECEIPT_SUFFIX) -
              1];
    FILE *f = fopen(receipt, "rb");
    if (!f)
        return failure(errors, "cannot open receipt");
    size_t n = fread(text, 1, sizeof(text), f);
    bool exact = n == sizeof(text) && fgetc(f) == EOF && !ferror(f);
    fclose(f);
    size_t prefix = sizeof(TF_QEMU_FLAGS_RECEIPT_PREFIX) - 1;
    if (!exact || memcmp(text, TF_QEMU_FLAGS_RECEIPT_PREFIX, prefix) ||
        memcmp(text + prefix + 64, TF_QEMU_FLAGS_RECEIPT_SUFFIX,
               sizeof(TF_QEMU_FLAGS_RECEIPT_SUFFIX) - 1))
        return failure(errors, "invalid version, incomplete probe or malformed receipt");
    for (size_t i = 0; i < 64; ++i)
        if (!((text[prefix + i] >= '0' && text[prefix + i] <= '9') ||
              (text[prefix + i] >= 'a' && text[prefix + i] <= 'f')))
            return failure(errors, "invalid executable digest");
    f = fopen(executable, "rb");
    if (!f)
        return failure(errors, "cannot read running QEMU executable");
    GChecksum *hash = g_checksum_new(G_CHECKSUM_SHA256);
    if (!hash) {
        fclose(f);
        return failure(errors, "cannot allocate checksum");
    }
    unsigned char data[65536];
    while ((n = fread(data, 1, sizeof(data), f)) != 0)
        g_checksum_update(hash, data, n);
    bool ok = !ferror(f) && !memcmp(text + prefix, g_checksum_get_string(hash), 64);
    fclose(f);
    g_checksum_free(hash);
    return ok || failure(errors, "receipt does not match the running QEMU executable");
}
