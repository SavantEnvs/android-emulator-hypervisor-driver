/* GCC-builtin versions of the MSVC bit intrinsics aehd_types.h uses (64-bit only). */
#pragma once

static inline unsigned char _BitScanForward(unsigned long *i, unsigned int m)
{ if (!m) return 0; *i = __builtin_ctz(m); return 1; }
static inline unsigned char _BitScanReverse(unsigned long *i, unsigned int m)
{ if (!m) return 0; *i = 31 - __builtin_clz(m); return 1; }
static inline unsigned char _BitScanForward64(unsigned long *i, unsigned long long m)
{ if (!m) return 0; *i = __builtin_ctzll(m); return 1; }
static inline unsigned char _BitScanReverse64(unsigned long *i, unsigned long long m)
{ if (!m) return 0; *i = 63 - __builtin_clzll(m); return 1; }

static inline unsigned char _bittest64(const long long *a, long long b)
{ return (a[b >> 6] >> (b & 63)) & 1; }
static inline unsigned char _bittestandset64(long long *a, long long b)
{ unsigned char o = _bittest64(a, b); a[b >> 6] |= 1LL << (b & 63); return o; }
static inline unsigned char _bittestandreset64(long long *a, long long b)
{ unsigned char o = _bittest64(a, b); a[b >> 6] &= ~(1LL << (b & 63)); return o; }
#define _interlockedbittestandset64 _bittestandset64
#define _interlockedbittestandreset64 _bittestandreset64
static inline void _ReadWriteBarrier(void) { __asm__ __volatile__("" ::: "memory"); }
