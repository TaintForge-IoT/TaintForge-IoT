/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TF_AFL_NO_CORE_H
#define TF_AFL_NO_CORE_H

#include <sys/prctl.h>
#include <sys/resource.h>

/* RLIMIT_CORE alone does not disable a piped kernel core handler. Apply this
 * after exec/fork, and again before a guest fatal signal is relayed by QEMU. */
static inline int tf_afl_disable_core_dumps(void)
{
    const struct rlimit limit = {0, 0};
    return setrlimit(RLIMIT_CORE, &limit) ||
           prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L) ||
           prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L) != 0;
}

#endif
