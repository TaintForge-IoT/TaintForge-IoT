#include "qemu_flags_contract.h"
#include <glib.h>
#include <string.h>

static bool failure(FILE *errors, const char *kind, const char *message) {
    if (errors)
        fprintf(errors, "[REG] %s receipt rejected: %s\n", kind, message);
    return false;
}

static bool receipt_options(int argc, char **argv, const char **receipt, FILE *errors,
                            const char *option, const char *kind) {
    if (!receipt || argc < 0 || (argc && !argv))
        return failure(errors, kind, "invalid arguments");
    const char *path = NULL;
    for (int i = 0; i < argc; ++i) {
        if (!argv[i])
            return failure(errors, kind, "missing option");
        const char *eq = strchr(argv[i], '=');
        size_t length = eq ? (size_t)(eq - argv[i]) : strlen(argv[i]);
        if (length != strlen(option) || memcmp(argv[i], option, length))
            continue;
        if (!eq || !eq[1] || path)
            return failure(errors, kind, "receipt option requires one nonempty path");
        path = eq + 1;
    }
    *receipt = path;
    return true;
}

static bool receipt_check(const char *receipt, const char *executable, FILE *errors,
                          const char *prefix_text, const char *suffix_text, const char *kind) {
    if (!receipt || !executable)
        return failure(errors, kind, "missing receipt or executable");
    char text[512];
    size_t prefix = strlen(prefix_text), suffix = strlen(suffix_text);
    size_t size = prefix + 64 + suffix;
    if (size > sizeof(text))
        return failure(errors, kind, "invalid receipt contract");
    FILE *f = fopen(receipt, "rb");
    if (!f)
        return failure(errors, kind, "cannot open receipt");
    size_t n = fread(text, 1, size, f);
    bool exact = n == size && fgetc(f) == EOF && !ferror(f);
    fclose(f);
    if (!exact || memcmp(text, prefix_text, prefix) ||
        memcmp(text + prefix + 64, suffix_text, suffix))
        return failure(errors, kind, "invalid version, incomplete probe or malformed receipt");
    for (size_t i = 0; i < 64; ++i)
        if (!((text[prefix + i] >= '0' && text[prefix + i] <= '9') ||
              (text[prefix + i] >= 'a' && text[prefix + i] <= 'f')))
            return failure(errors, kind, "invalid executable digest");
    f = fopen(executable, "rb");
    if (!f)
        return failure(errors, kind, "cannot read running QEMU executable");
    GChecksum *hash = g_checksum_new(G_CHECKSUM_SHA256);
    if (!hash) {
        fclose(f);
        return failure(errors, kind, "cannot allocate checksum");
    }
    unsigned char data[65536];
    while ((n = fread(data, 1, sizeof(data), f)) != 0)
        g_checksum_update(hash, data, n);
    bool ok = !ferror(f) && !memcmp(text + prefix, g_checksum_get_string(hash), 64);
    fclose(f);
    g_checksum_free(hash);
    return ok || failure(errors, kind, "receipt does not match the running QEMU executable");
}

bool tf_qemu_flags_options(int argc, char **argv, const char **receipt, FILE *errors) {
    return receipt_options(argc, argv, receipt, errors, "x86-flags-receipt", "EFLAGS");
}
bool tf_qemu_flags_receipt_check(const char *receipt, const char *executable, FILE *errors) {
    return receipt_check(receipt, executable, errors, TF_QEMU_FLAGS_RECEIPT_PREFIX,
                         TF_QEMU_FLAGS_RECEIPT_SUFFIX, "EFLAGS");
}
bool tf_qemu_es_options(int argc, char **argv, const char **receipt, FILE *errors) {
    return receipt_options(argc, argv, receipt, errors, "x86-es-receipt", "ES");
}
bool tf_qemu_es_receipt_check(const char *receipt, const char *executable, FILE *errors) {
    return receipt_check(receipt, executable, errors, TF_QEMU_ES_RECEIPT_PREFIX,
                         TF_QEMU_ES_RECEIPT_SUFFIX, "ES");
}
