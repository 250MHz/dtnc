/*	$OpenBSD: arc4random.c,v 1.58 2022/07/31 13:41:45 tb Exp $	*/

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2014, Theo de Raadt <deraadt@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * ChaCha based random number generator for OpenBSD.
 */

/* OPENBSD ORIGINAL: lib/libc/crypt/arc4random.c */

#include "compat.h"

#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>

#define fatal(...) errx(1, __VA_ARGS__)

/*
 * Always use the getentropy implementation from bsd-getentropy.c, which
 * will call a native getentropy if available then fall back as required.
 * We use a different name so that OpenSSL cannot call the wrong getentropy.
 */
int compat_getentropy(void *, size_t);

// Compat getentropy from openssh-portable/openbsd-compat/bsd-getentropy.c
// Removed OpenSSL and egd/prngd stuff

#ifndef HAVE_ARC4RANDOM

#ifndef DTNC_RANDOM_DEV
# define DTNC_RANDOM_DEV "/dev/urandom"
#endif

#include <sys/types.h>
#ifdef HAVE_SYS_RANDOM_H
# include <sys/random.h>
#endif

#include <errno.h>

typedef unsigned char u_char;

int
compat_getentropy(void *s, size_t len)
{
	int fd, save_errno;
	ssize_t r;
	size_t o = 0;

#ifdef HAVE_GETENTROPY
	if ((r = getentropy(s, len)) == 0)
		return 0;
#endif
#ifdef HAVE_GETRANDOM
	if ((r = getrandom(s, len, 0)) > 0 && (size_t)r == len)
		return 0;
#endif

	if ((fd = open(DTNC_RANDOM_DEV, O_RDONLY)) == -1) {
		save_errno = errno;
		fatal("Couldn't open %s: %s", DTNC_RANDOM_DEV,
		    strerror(save_errno));
	}
	while (o < len) {
		r = read(fd, (u_char *)s + o, len - o);
		if (r < 0) {
			if (errno == EAGAIN || errno == EINTR ||
			    errno == EWOULDBLOCK)
				continue;
			fatal("read %s: %s", DTNC_RANDOM_DEV, strerror(errno));
		}
		o += (size_t)r;
	}
	close(fd);
	return 0;
}
// End bsd-getentropy.c

#ifdef getentropy
# undef getentropy
#endif
#define getentropy(x, y) (compat_getentropy((x), (y)))

#define KEYSTREAM_ONLY

/* OPENBSD ORIGINAL: lib/libc/crypt/chacha_private.h */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

/* $OpenBSD: chacha_private.h,v 1.3 2022/02/28 21:56:29 dtucker Exp $ */

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned int u_int;

typedef struct
{
  u32 input[16]; /* could be compressed */
} chacha_ctx;

#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((u8)(v) & U8C(0xFF))
#define U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define U8TO32_LITTLE(p) \
  (((u32)((p)[0])      ) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))

#define U32TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } while (0)

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

static void
chacha_keysetup(chacha_ctx *x,const u8 *k,u32 kbits)
{
  const char *constants;

  x->input[4] = U8TO32_LITTLE(k + 0);
  x->input[5] = U8TO32_LITTLE(k + 4);
  x->input[6] = U8TO32_LITTLE(k + 8);
  x->input[7] = U8TO32_LITTLE(k + 12);
  if (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  x->input[8] = U8TO32_LITTLE(k + 0);
  x->input[9] = U8TO32_LITTLE(k + 4);
  x->input[10] = U8TO32_LITTLE(k + 8);
  x->input[11] = U8TO32_LITTLE(k + 12);
  x->input[0] = U8TO32_LITTLE(constants + 0);
  x->input[1] = U8TO32_LITTLE(constants + 4);
  x->input[2] = U8TO32_LITTLE(constants + 8);
  x->input[3] = U8TO32_LITTLE(constants + 12);
}

static void
chacha_ivsetup(chacha_ctx *x,const u8 *iv)
{
  x->input[12] = 0;
  x->input[13] = 0;
  x->input[14] = U8TO32_LITTLE(iv + 0);
  x->input[15] = U8TO32_LITTLE(iv + 4);
}

static void
chacha_encrypt_bytes(chacha_ctx *x,const u8 *m,u8 *c,u32 bytes)
{
  u32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  u32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  u8 *ctarget = NULL;
  u8 tmp[64];
  u_int i;

  if (!bytes) return;

  j0 = x->input[0];
  j1 = x->input[1];
  j2 = x->input[2];
  j3 = x->input[3];
  j4 = x->input[4];
  j5 = x->input[5];
  j6 = x->input[6];
  j7 = x->input[7];
  j8 = x->input[8];
  j9 = x->input[9];
  j10 = x->input[10];
  j11 = x->input[11];
  j12 = x->input[12];
  j13 = x->input[13];
  j14 = x->input[14];
  j15 = x->input[15];

  for (;;) {
    if (bytes < 64) {
      for (i = 0;i < bytes;++i) tmp[i] = m[i];
      m = tmp;
      ctarget = c;
      c = tmp;
    }
    x0 = j0;
    x1 = j1;
    x2 = j2;
    x3 = j3;
    x4 = j4;
    x5 = j5;
    x6 = j6;
    x7 = j7;
    x8 = j8;
    x9 = j9;
    x10 = j10;
    x11 = j11;
    x12 = j12;
    x13 = j13;
    x14 = j14;
    x15 = j15;
    for (i = 20;i > 0;i -= 2) {
      QUARTERROUND( x0, x4, x8,x12)
      QUARTERROUND( x1, x5, x9,x13)
      QUARTERROUND( x2, x6,x10,x14)
      QUARTERROUND( x3, x7,x11,x15)
      QUARTERROUND( x0, x5,x10,x15)
      QUARTERROUND( x1, x6,x11,x12)
      QUARTERROUND( x2, x7, x8,x13)
      QUARTERROUND( x3, x4, x9,x14)
    }
    x0 = PLUS(x0,j0);
    x1 = PLUS(x1,j1);
    x2 = PLUS(x2,j2);
    x3 = PLUS(x3,j3);
    x4 = PLUS(x4,j4);
    x5 = PLUS(x5,j5);
    x6 = PLUS(x6,j6);
    x7 = PLUS(x7,j7);
    x8 = PLUS(x8,j8);
    x9 = PLUS(x9,j9);
    x10 = PLUS(x10,j10);
    x11 = PLUS(x11,j11);
    x12 = PLUS(x12,j12);
    x13 = PLUS(x13,j13);
    x14 = PLUS(x14,j14);
    x15 = PLUS(x15,j15);

#ifndef KEYSTREAM_ONLY
    x0 = XOR(x0,U8TO32_LITTLE(m + 0));
    x1 = XOR(x1,U8TO32_LITTLE(m + 4));
    x2 = XOR(x2,U8TO32_LITTLE(m + 8));
    x3 = XOR(x3,U8TO32_LITTLE(m + 12));
    x4 = XOR(x4,U8TO32_LITTLE(m + 16));
    x5 = XOR(x5,U8TO32_LITTLE(m + 20));
    x6 = XOR(x6,U8TO32_LITTLE(m + 24));
    x7 = XOR(x7,U8TO32_LITTLE(m + 28));
    x8 = XOR(x8,U8TO32_LITTLE(m + 32));
    x9 = XOR(x9,U8TO32_LITTLE(m + 36));
    x10 = XOR(x10,U8TO32_LITTLE(m + 40));
    x11 = XOR(x11,U8TO32_LITTLE(m + 44));
    x12 = XOR(x12,U8TO32_LITTLE(m + 48));
    x13 = XOR(x13,U8TO32_LITTLE(m + 52));
    x14 = XOR(x14,U8TO32_LITTLE(m + 56));
    x15 = XOR(x15,U8TO32_LITTLE(m + 60));
#endif

    j12 = PLUSONE(j12);
    if (!j12) {
      j13 = PLUSONE(j13);
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }

    U32TO8_LITTLE(c + 0,x0);
    U32TO8_LITTLE(c + 4,x1);
    U32TO8_LITTLE(c + 8,x2);
    U32TO8_LITTLE(c + 12,x3);
    U32TO8_LITTLE(c + 16,x4);
    U32TO8_LITTLE(c + 20,x5);
    U32TO8_LITTLE(c + 24,x6);
    U32TO8_LITTLE(c + 28,x7);
    U32TO8_LITTLE(c + 32,x8);
    U32TO8_LITTLE(c + 36,x9);
    U32TO8_LITTLE(c + 40,x10);
    U32TO8_LITTLE(c + 44,x11);
    U32TO8_LITTLE(c + 48,x12);
    U32TO8_LITTLE(c + 52,x13);
    U32TO8_LITTLE(c + 56,x14);
    U32TO8_LITTLE(c + 60,x15);

    if (bytes <= 64) {
      if (bytes < 64) {
        for (i = 0;i < bytes;++i) ctarget[i] = c[i];
      }
      x->input[12] = j12;
      x->input[13] = j13;
      return;
    }
    bytes -= 64;
    c += 64;
#ifndef KEYSTREAM_ONLY
    m += 64;
#endif
  }
}
// End chacha_private.h

#define minimum(a, b) ((a) < (b) ? (a) : (b))

#if defined(__GNUC__) || defined(_MSC_VER)
#define inline __inline
#else				/* __GNUC__ || _MSC_VER */
#define inline
#endif				/* !__GNUC__ && !_MSC_VER */

#define KEYSZ	32
#define IVSZ	8
#define BLOCKSZ	64
#define RSBUFSZ	(16*BLOCKSZ)

#define REKEY_BASE	(1024*1024) /* NB. should be a power of 2 */

/* Marked MAP_INHERIT_ZERO, so zero'd out in fork children. */
static struct _rs {
	size_t		rs_have;	/* valid bytes at end of rs_buf */
	size_t		rs_count;	/* bytes till reseed */
} *rs;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
static struct _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx;

static inline int _rs_allocate(struct _rs **, struct _rsx **);
static inline void _rs_forkdetect(void);

// arc4random.h from openssh-portable/openbsd-compat
/*	$OpenBSD: arc4random_linux.h,v 1.12 2019/07/11 10:37:28 inoguchi Exp $	*/

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#if !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#define MAP_ANON MAP_ANONYMOUS
#endif

#include <err.h>

/* OpenSSH isn't multithreaded */
#define _ARC4_LOCK()
#define _ARC4_UNLOCK()
#define _ARC4_ATFORK(f)

static inline void
_getentropy_fail(void)
{
	fatal("getentropy failed");
}

static volatile sig_atomic_t _rs_forked;

static inline void
_rs_forkhandler(void)
{
	_rs_forked = 1;
}

static inline void
_rs_forkdetect(void)
{
	static pid_t _rs_pid = 0;
	pid_t pid = getpid();

	if (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		if (rs)
			memset(rs, 0, sizeof(*rs));
	}
}

static inline int
_rs_allocate(struct _rs **rsp, struct _rsx **rsxp)
{
#if defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	if ((*rsp = mmap(NULL, sizeof(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		return (-1);

	if ((*rsxp = mmap(NULL, sizeof(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, sizeof(**rsp));
		*rsp = NULL;
		return (-1);
	}
#else
	if ((*rsp = calloc(1, sizeof(**rsp))) == NULL)
		return (-1);
	if ((*rsxp = calloc(1, sizeof(**rsxp))) == NULL) {
		free(*rsp);
		*rsp = NULL;
		return (-1);
	}
#endif /* HAVE_MMAP et al */

	_ARC4_ATFORK(_rs_forkhandler);
	return (0);
}
// End arc4random.h

static inline void _rs_rekey(u_char *dat, size_t datlen);

static inline void
_rs_init(u_char *buf, size_t n)
{
	if (n < KEYSZ + IVSZ)
		return;

	if (rs == NULL) {
		if (_rs_allocate(&rs, &rsx) == -1)
			_exit(1);
	}

	chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8);
	chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ);
}

static void
_rs_stir(void)
{
	u_char rnd[KEYSZ + IVSZ];
	uint32_t rekey_fuzz = 0;

	if (getentropy(rnd, sizeof rnd) == -1)
		_getentropy_fail();

	if (!rs)
		_rs_init(rnd, sizeof(rnd));
	else
		_rs_rekey(rnd, sizeof(rnd));
	explicit_bzero(rnd, sizeof(rnd));	/* discard source seed */

	/* invalidate rs_buf */
	rs->rs_have = 0;
	memset(rsx->rs_buf, 0, sizeof(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_bytes(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, sizeof(rekey_fuzz));
	rs->rs_count = REKEY_BASE + (rekey_fuzz % REKEY_BASE);
}

static inline void
_rs_stir_if_needed(size_t len)
{
	_rs_forkdetect();
	if (!rs || rs->rs_count <= len)
		_rs_stir();
	if (rs->rs_count <= len)
		rs->rs_count = 0;
	else
		rs->rs_count -= len;
}

static inline void
_rs_rekey(u_char *dat, size_t datlen)
{
#ifndef KEYSTREAM_ONLY
	memset(rsx->rs_buf, 0, sizeof(rsx->rs_buf));
#endif
	/* fill rs_buf with the keystream */
	chacha_encrypt_bytes(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, sizeof(rsx->rs_buf));
	/* mix in optional user provided data */
	if (dat) {
		size_t i, m;

		m = minimum(datlen, KEYSZ + IVSZ);
		for (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	memset(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = sizeof(rsx->rs_buf) - KEYSZ - IVSZ;
}

static inline void
_rs_random_buf(void *_buf, size_t n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	size_t m;

	_rs_stir_if_needed(n);
	while (n > 0) {
		if (rs->rs_have > 0) {
			m = minimum(n, rs->rs_have);
			keystream = rsx->rs_buf + sizeof(rsx->rs_buf)
			    - rs->rs_have;
			memcpy(buf, keystream, m);
			memset(keystream, 0, m);
			buf += m;
			n -= m;
			rs->rs_have -= m;
		}
		if (rs->rs_have == 0)
			_rs_rekey(NULL, 0);
	}
}

static inline void
_rs_random_u32(uint32_t *val)
{
	u_char *keystream;

	_rs_stir_if_needed(sizeof(*val));
	if (rs->rs_have < sizeof(*val))
		_rs_rekey(NULL, 0);
	keystream = rsx->rs_buf + sizeof(rsx->rs_buf) - rs->rs_have;
	memcpy(val, keystream, sizeof(*val));
	memset(keystream, 0, sizeof(*val));
	rs->rs_have -= sizeof(*val);
}

uint32_t
arc4random(void)
{
	uint32_t val;

	_ARC4_LOCK();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	return val;
}

/*
 * If we are providing arc4random, then we can provide a more efficient
 * arc4random_buf().
 */
# ifndef HAVE_ARC4RANDOM_BUF
void
arc4random_buf(void *buf, size_t n)
{
	_ARC4_LOCK();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
# endif /* !HAVE_ARC4RANDOM_BUF */
#endif /* !HAVE_ARC4RANDOM */

/* arc4random_buf() that uses platform arc4random() */
#if !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
void
arc4random_buf(void *_buf, size_t n)
{
	size_t i;
	u_int32_t r = 0;
	char *buf = (char *)_buf;

	for (i = 0; i < n; i++) {
		if (i % 4 == 0)
			r = arc4random();
		buf[i] = r & 0xff;
		r >>= 8;
	}
	explicit_bzero(&r, sizeof(r));
}
#endif /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */

/*	$OpenBSD: arc4random_uniform.c,v 1.3 2019/01/20 02:59:07 bcook Exp $	*/

/* OPENBSD ORIGINAL: lib/libc/crypto/arc4random_uniform.c */

#ifndef HAVE_ARC4RANDOM_UNIFORM
/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**32 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
uint32_t
arc4random_uniform(uint32_t upper_bound)
{
	uint32_t r, min;

	if (upper_bound < 2)
		return 0;

	/* 2**32 % x == (2**32 - x) % x */
	min = -upper_bound % upper_bound;

	/*
	 * This could theoretically loop forever but each retry has
	 * p > 0.5 (worst case, usually far better) of selecting a
	 * number inside the range we need, so it should rarely need
	 * to re-roll.
	 */
	for (;;) {
		r = arc4random();
		if (r >= min)
			break;
	}

	return r % upper_bound;
}
#endif /* !HAVE_ARC4RANDOM_UNIFORM */
