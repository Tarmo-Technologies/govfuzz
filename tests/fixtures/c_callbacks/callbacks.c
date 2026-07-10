// SPDX-License-Identifier: Apache-2.0
// Fixture: C function-pointer / callback harness-generation coverage.
//   §26.5  a typedef'd function-pointer PARAMETER (run_visitor)
//   §27.3  a callback ARRAY struct field (run_dispatch) + a VARIADIC callback
//          parameter (run_logger)
//   §27.9  an INLINE (non-typedef) function-pointer PARAMETER (run_inline) and an
//          INLINE function-pointer struct FIELD (run_ops)
// Each target must build (no placeholder/skip): the callback is satisfied with a
// generated no-op trampoline (or a filled array of them), not left unsatisfiable.
#include <stddef.h>

typedef int (*visit_cb)(void *opaque, const char *name);
typedef void (*log_fn)(int level, ...);

struct dispatch {
    void (*handlers[4])(int);
    int n;
};

struct ops {
    int (*cmp)(const void *, const void *);
    int x;
};

/* §26.5: a typedef'd function-pointer parameter. */
int run_visitor(visit_cb cb, const unsigned char *data, unsigned len) {
    int acc = 0;
    unsigned i;
    if (cb) {
        acc = cb((void *)data, "x");
    }
    for (i = 0; i < len; i++) {
        acc += data[i];
    }
    return acc;
}

/* §27.3: a struct carrying a callback ARRAY field. */
int run_dispatch(const struct dispatch *d) {
    if (!d) {
        return 0;
    }
    if (d->handlers[0]) {
        d->handlers[0](d->n);
    }
    return d->n;
}

/* §27.3: a VARIADIC function-pointer parameter. */
int run_logger(log_fn fn, const unsigned char *data, unsigned len) {
    if (fn) {
        fn(1);
    }
    return (data && len) ? data[0] : 0;
}

/* §27.9: an INLINE (non-typedef) function-pointer parameter. */
int run_inline(int (*cb)(int, int), const unsigned char *data, unsigned len) {
    int acc = cb ? cb((int)len, 0) : 0;
    unsigned i;
    for (i = 0; i < len; i++) {
        acc ^= data[i];
    }
    return acc;
}

/* §27.9: a struct carrying an INLINE function-pointer field. */
int run_ops(const struct ops *o) {
    if (!o) {
        return 0;
    }
    return o->cmp ? o->cmp(o, o) + o->x : o->x;
}
