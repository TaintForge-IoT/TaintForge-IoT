#ifndef TAINTFORGE_QEMU_FLAGS_CONTRACT_H
#define TAINTFORGE_QEMU_FLAGS_CONTRACT_H

#include <stdbool.h>
#include <stdio.h>

/* A local validation receipt binds the PUSHF boundary probe results to one
 * QEMU executable. It is a validation record, not a signed certificate. */
#define TF_QEMU_FLAGS_RECEIPT_PREFIX "TAINTFORGE_X86_FLAGS_V1\nqemu_sha256="
#define TF_QEMU_FLAGS_RECEIPT_SUFFIX                                                               \
    "\nprobe=pushf-boundary-v1\ntarget=i386-linux-user\nnormal_checked=32\n"                       \
    "single_checked=32\nmismatches=0\n"

bool tf_qemu_flags_options(int argc, char **argv, const char **receipt, FILE *errors);
bool tf_qemu_flags_receipt_check(const char *receipt, const char *executable, FILE *errors);

#endif
