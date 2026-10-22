#ifndef TF_PHASE1_ALLOC_H
#define TF_PHASE1_ALLOC_H

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include "phase1_resources.h"

#undef g_free
#undef g_strdup

#define malloc(n) tf_alloc_malloc((n), __FILE__)
#define calloc(n, s) tf_alloc_calloc((n), (s), __FILE__)
#define realloc(p, n) tf_alloc_realloc((p), (n), __FILE__)
#define free tf_alloc_free
#define g_malloc(n) (tf_resources_enabled() ? tf_alloc_malloc((n), __FILE__) : (g_malloc)(n))
#define g_malloc0(n) (tf_resources_enabled() ? tf_alloc_calloc(1, (n), __FILE__) : (g_malloc0)(n))
#define g_malloc_n(n, s) (tf_resources_enabled() ? tf_alloc_malloc_array((n), (s), __FILE__) : (g_malloc_n)((n), (s)))
#define g_malloc0_n(n, s) (tf_resources_enabled() ? tf_alloc_calloc((n), (s), __FILE__) : (g_malloc0_n)((n), (s)))
#define g_try_malloc(n) (tf_resources_enabled() ? tf_alloc_malloc((n), __FILE__) : (g_try_malloc)(n))
#define g_try_malloc0(n) (tf_resources_enabled() ? tf_alloc_calloc(1, (n), __FILE__) : (g_try_malloc0)(n))
#define g_try_malloc_n(n, s) (tf_resources_enabled() ? tf_alloc_malloc_array((n), (s), __FILE__) : (g_try_malloc_n)((n), (s)))
#define g_try_malloc0_n(n, s) (tf_resources_enabled() ? tf_alloc_calloc((n), (s), __FILE__) : (g_try_malloc0_n)((n), (s)))
#define g_realloc(p, n) (tf_resources_enabled() ? tf_alloc_realloc((p), (n), __FILE__) : (g_realloc)((p), (n)))
#define g_try_realloc(p, n) (tf_resources_enabled() ? tf_alloc_realloc((p), (n), __FILE__) : (g_try_realloc)((p), (n)))
#define g_realloc_n(p, n, s) (tf_resources_enabled() ? tf_alloc_realloc_array((p), (n), (s), __FILE__) : (g_realloc_n)((p), (n), (s)))
#define g_free tf_alloc_free
#define g_strdup(s) (tf_resources_enabled() ? tf_alloc_strdup((s), __FILE__) : (g_strdup)(s))
#define g_strndup(s, n) (tf_resources_enabled() ? tf_alloc_strndup((s), (n), __FILE__) : (g_strndup)((s), (n)))
#define g_strdup_printf(...) (tf_resources_enabled() ? tf_alloc_printf(__FILE__, __VA_ARGS__) : (g_strdup_printf)(__VA_ARGS__))

#endif
