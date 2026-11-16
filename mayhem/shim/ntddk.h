/* Minimal Linux stand-in for the Windows kernel headers aehd_types.h expects. */
#pragma once
#include <stddef.h>
void *memset(void *, int, size_t);
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

typedef long intptr_t;
typedef unsigned long uintptr_t;

typedef int LONG;
typedef unsigned int ULONG;
typedef long long LONG64;
typedef unsigned long long ULONG64;
typedef unsigned int UINT32;
typedef int INT32;
typedef unsigned char BOOLEAN;
typedef void VOID;
typedef void *PVOID;

#define ULONG_MAX (~0UL)
#define __forceinline inline __attribute__((always_inline))
#define _forceinline __forceinline
#define _In_
#define _Out_
#define _Inout_
#define _In_opt_
#define DbgPrint(...) ((void)0)

/* MSVC SEH stand-in: a body runs once; the handler runs only if the glue flagged a host fault (e.g. #DE) */
extern int aehd_fault;
#define __try aehd_fault = 0; do
#define __except(x) while (0); if (aehd_fault)
