/* Linux stand-in for the driver's Windows-kernel glue header: just what the instruction emulator path needs. */
#pragma once
#include <ntddk.h>
#include <intrin.h>
#include <aehd_types.h>
#include <linux/list.h>
#include <uapi/asm/processor-flags.h>

/* ---- minimal Linux stand-ins for the Windows kernel glue ---- */
#define PAGE_SHIFT 12
#define PAGE_SIZE 4096
#define BIT(nr) ((size_t)(1) << (nr))
#define GFP_KERNEL BIT(0)
#define GFP_ATOMIC BIT(1)
#define __GFP_ZERO BIT(3)
#define GFP_UNALLOC BIT(5)
#define BAD_APICID 0xFFFFu
#define _CRT_UNUSED(x) ((void)(x))

typedef long atomic_t;
typedef unsigned long long hfn_t_shim;
typedef u64 pfn_t;
typedef struct page { void *hva; void *kmap_hva; size_t __private; u64 hpa; pfn_t pfn; size_t gfp_mask; void *proc; } page;
#define page_private(page) ((page)->__private)
#define set_page_private(page, v) ((page)->__private = (v))
struct page *pfn_to_page(pfn_t pfn);

struct spin_lock { volatile LONG lock; };
typedef struct spin_lock spinlock_t;
typedef struct spin_lock raw_spinlock_t;
struct mutex { volatile LONG lock; };
struct srcu_struct { int dummy; };
typedef struct { int dummy; } KEVENT;
typedef void *PETHREAD, *PEPROCESS, *PIRP, *PMDL, *PDEVICE_OBJECT, *HANDLE;
typedef struct { int dummy; } KAPC, KTIMER, KDPC;

#define smp_mb() __sync_synchronize()
#define smp_rmb() __sync_synchronize()
#define smp_wmb() __sync_synchronize()
#define cmpxchg(a, b, c) __sync_val_compare_and_swap((a), (b), (c))
#define xchg(a, b) __sync_lock_test_and_set((a), (b))
void *kzalloc(size_t size, size_t flags);
void kfree(void *p);
#define rdmsrl(a, b) ((b) = 0)
void KeBugCheck(unsigned int code);
size_t __readcr4(void); void __writecr4(size_t v);
void _sgdt(void *p); void __sidt(void *p);
#define smp_mb__after_atomic() __sync_synchronize()
#define RtlUshortByteSwap(x) __builtin_bswap16(x)
#define RtlUlongByteSwap(x) __builtin_bswap32(x)
#define RtlUlonglongByteSwap(x) __builtin_bswap64(x)
