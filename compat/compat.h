#ifndef COMPAT_H
#define COMPAT_H

#include "config-compat.h"

#include <stdlib.h>

#ifndef HAVE_STRTONUM
long long strtonum(
    const char *nptr,
    long long minval,
    long long maxval,
    const char **errstr
);
#endif

#include <stddef.h>
#include <stdint.h>

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(void);
#endif

#ifndef HAVE_ARC4RANDOM_BUF
void arc4random_buf(void *, size_t);
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#include <strings.h>

#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void *p, size_t n);
#endif

void dtnc_setprogname(const char *name);
const char *dtnc_getprogname(void);

#ifdef HAVE_ERR_H
#include <err.h>
#endif
#include <stdarg.h>

#ifndef HAVE_VWARN
void vwarn(const char *fmt, va_list ap);
#endif

#ifndef HAVE_VWARNC
void vwarnc(int code, const char *fmt, va_list ap);
#endif

#ifndef HAVE_VWARNX
void vwarnx(const char *fmt, va_list ap);
#endif

#ifndef HAVE_VERR
_Noreturn void verr(int eval, const char *fmt, va_list ap);
#endif

#ifndef HAVE_VERRC
_Noreturn void verrc(int eval, int code, const char *fmt, va_list ap);
#endif

#ifndef HAVE_VERRX
_Noreturn void verrx(int eval, const char *fmt, va_list ap);
#endif

#ifndef HAVE_ERR
_Noreturn void err(int eval, const char *fmt, ...);
#endif

#ifndef HAVE_ERRC
_Noreturn void errc(int eval, int code, const char *fmt, ...);
#endif

#ifndef HAVE_ERRX
_Noreturn void errx(int eval, const char *fmt, ...);
#endif

#ifndef HAVE_WARN
void warn(const char *fmt, ...);
#endif

#ifndef HAVE_WARNC
void warnc(int code, const char *fmt, ...);
#endif

#ifndef HAVE_WARNX
void warnx(const char *fmt, ...);
#endif

#endif // COMPAT_H
