/*
 * libFuzzer harness for the AEHD x86 instruction emulator (arch/x86/kvm/emulate.c).
 *
 * Input: [mode][opts][eflags:2][seed:4][instruction bytes...]
 *   mode  % 5 selects the X86EMUL_MODE_* value
 *   opts  bit0: also run x86_emulate_insn after a successful decode
 *         bit1: hand the bytes to x86_decode_insn directly (<=15) instead of through ops->fetch
 *         bit2: set ctxt->ud
 * Guest registers, segments, control registers and memory contents come from a PRNG seeded by `seed`.
 */
#include <linux/kvm_host.h>
#include "kvm_cache_regs.h"
#include <asm/kvm_emulate.h>
#include "x86.h"

void abort(void);
#define FASTOP_SIZE 8

int aehd_fault;

/* ---- host-side stand-ins for the MASM routines that cannot be assembled on Linux ---- */

void KeBugCheck(unsigned int code) { (void)code; abort(); }

#define VEC_REGS(n) \
	void __asm_save_xmm##n(void *d) { __asm__ __volatile__("movdqu %%xmm" #n ", (%0)" : : "r"(d) : "memory"); } \
	void __asm_store_xmm##n(void *d) { __asm__ __volatile__("movdqu (%0), %%xmm" #n : : "r"(d) : "xmm" #n, "memory"); }
VEC_REGS(0) VEC_REGS(1) VEC_REGS(2) VEC_REGS(3) VEC_REGS(4) VEC_REGS(5) VEC_REGS(6) VEC_REGS(7)
VEC_REGS(8) VEC_REGS(9) VEC_REGS(10) VEC_REGS(11) VEC_REGS(12) VEC_REGS(13) VEC_REGS(14) VEC_REGS(15)

#define MM_REGS(n) \
	void __asm_save_mm##n(u64 *d) { __asm__ __volatile__("movq %%mm" #n ", (%0)" : : "r"(d) : "memory"); } \
	void __asm_store_mm##n(u64 *d) { __asm__ __volatile__("movq (%0), %%mm" #n "\n\temms" : : "r"(d) : "mm" #n, "memory"); }
MM_REGS(0) MM_REGS(1) MM_REGS(2) MM_REGS(3) MM_REGS(4) MM_REGS(5) MM_REGS(6) MM_REGS(7)

void __bswap32(u32 *p) { *p = __builtin_bswap32(*p); }
void __bswap64(u64 *p) { *p = __builtin_bswap64(*p); }
void __fninit(void) { __asm__ __volatile__("fninit"); }
void __fnstsw(u16 *p) { __asm__ __volatile__("fnstsw %0" : "=m"(*p)); }
void __fnstcw(u16 *p) { __asm__ __volatile__("fnstcw %0" : "=m"(*p)); }
void __fwait(void) { __asm__ __volatile__("fwait"); }

extern char em_div_ex[], em_idiv_ex[];

/* True if the DIV/IDIV fastop `fop` would raise #DE for the given operands (SEH catches this on Windows). */
static int div_faults(char *fop, u64 rax, u64 rdx, u64 rcx)
{
	int sgn = fop >= em_idiv_ex && fop < em_idiv_ex + 32;
	int bytes;
	unsigned __int128 n, d;

	if (!sgn && !(fop >= em_div_ex && fop < em_div_ex + 32))
		return 0;
	bytes = 1 << ((fop - (sgn ? em_idiv_ex : em_div_ex)) / FASTOP_SIZE);
	if (bytes == 1) {
		n = rax & 0xffff; d = rcx & 0xff;
	} else if (bytes == 2) {
		n = ((rdx & 0xffff) << 16) | (rax & 0xffff); d = rcx & 0xffff;
	} else if (bytes == 4) {
		n = ((rdx & 0xffffffffull) << 32) | (rax & 0xffffffffull); d = rcx & 0xffffffffull;
	} else {
		n = ((unsigned __int128)rdx << 64) | rax; d = rcx;
	}
	if (!sgn)
		return d == 0 || n / d > (bytes == 8 ? ~0ull : (1ull << (8 * bytes)) - 1);
	{
		int bits = 8 * bytes;
		__int128 sn = (__int128)(n << (128 - 2 * bits)) >> (128 - 2 * bits);
		__int128 sd = (__int128)(d << (128 - bits)) >> (128 - bits);
		__int128 lim = (__int128)1 << (bits - 1);
		__int128 q;
		if (sd == 0)
			return 1;
		q = sn / sd;
		return q < -lim || q >= lim;
	}
}

void __asm_fastop(size_t *flags, void *fop, struct x86_emulate_ctxt *ctxt)
{
	u64 a = ctxt->dst.val, d = ctxt->src.val, c = ctxt->src2.val;
	size_t fl = *flags;

	if (div_faults(fop, a, d, c)) {
		aehd_fault = 1;
		return;
	}
	__asm__ __volatile__(
		"pushfq\n\t"
		"mov %[fl], %%r10\n\t"
		"mov (%%rsp), %%r9\n\t"
		"and $0xfffff72a, %%r9d\n\t"
		"or %%r9, %%r10\n\t"
		"push %%r10\n\t"
		"popfq\n\t"
		"call *%[fop]\n\t"
		"pushfq\n\t"
		"pop %[fl]\n\t"
		"popfq\n\t"
		: "+a"(a), "+d"(d), "+c"(c), [fl] "+r"(fl)
		: [fop] "r"(fop)
		: "r9", "r10", "memory", "cc");
	*flags = fl & 0x8D5;
	ctxt->dst.val = a;
	ctxt->src.val = d;
}

u8 __asm_test_cc(void *fop, size_t flags)
{
	u64 r;

	__asm__ __volatile__(
		"pushfq\n\t"
		"push %[fl]\n\t"
		"popfq\n\t"
		"call *%[fop]\n\t"
		"popfq\n\t"
		: "=&a"(r)
		: [fop] "r"(fop), [fl] "r"(flags)
		: "memory", "cc");
	return (u8)r;
}

/* ---- deterministic guest model ---- */

static u64 rng_state;
static u64 rng(void)
{
	u64 x = rng_state;
	x ^= x << 13; x ^= x >> 7; x ^= x << 17;
	return rng_state = x;
}

static const u8 *insn_buf;
static size_t insn_len, fetch_pos;
static size_t gpr[16];

static void fill(void *val, unsigned bytes)
{
	u8 *p = val;
	unsigned i;
	for (i = 0; i < bytes; i++)
		p[i] = (u8)rng();
}

static size_t o_read_gpr(struct x86_emulate_ctxt *c, unsigned reg) { (void)c; return gpr[reg & 15]; }
static void o_write_gpr(struct x86_emulate_ctxt *c, unsigned reg, size_t v) { (void)c; gpr[reg & 15] = v; }
static int o_read(struct x86_emulate_ctxt *c, size_t a, void *v, unsigned b, struct x86_exception *f, bool s)
{ (void)c; (void)a; (void)f; (void)s; fill(v, b); return X86EMUL_CONTINUE; }
static int o_read_phys(struct x86_emulate_ctxt *c, size_t a, void *v, unsigned b)
{ (void)c; (void)a; fill(v, b); return X86EMUL_CONTINUE; }
static int o_write(struct x86_emulate_ctxt *c, size_t a, void *v, unsigned b, struct x86_exception *f, bool s)
{ (void)c; (void)a; (void)v; (void)b; (void)f; (void)s; return X86EMUL_CONTINUE; }
static int o_fetch(struct x86_emulate_ctxt *c, size_t a, void *v, unsigned b, struct x86_exception *f)
{
	unsigned i;
	(void)c; (void)a;
	if (fetch_pos >= insn_len) {
		f->vector = PF_VECTOR;
		f->error_code_valid = true;
		f->error_code = 0;
		f->nested_page_fault = false;
		f->address = a;
		return X86EMUL_PROPAGATE_FAULT;
	}
	for (i = 0; i < b; i++)
		((u8 *)v)[i] = fetch_pos + i < insn_len ? insn_buf[fetch_pos + i] : 0;
	fetch_pos += b;
	return X86EMUL_CONTINUE;
}
static int o_read_emu(struct x86_emulate_ctxt *c, size_t a, void *v, unsigned b, struct x86_exception *f)
{ (void)c; (void)a; (void)f; fill(v, b); return X86EMUL_CONTINUE; }
static int o_write_emu(struct x86_emulate_ctxt *c, size_t a, const void *v, unsigned b, struct x86_exception *f)
{ (void)c; (void)a; (void)v; (void)b; (void)f; return X86EMUL_CONTINUE; }
static int o_cmpxchg(struct x86_emulate_ctxt *c, size_t a, const void *o, const void *n, unsigned b, struct x86_exception *f)
{ (void)c; (void)a; (void)o; (void)n; (void)b; (void)f; return X86EMUL_CONTINUE; }
static void o_invlpg(struct x86_emulate_ctxt *c, ulong a) { (void)c; (void)a; }
static int o_pio_in(struct x86_emulate_ctxt *c, int size, unsigned short port, void *v, unsigned count)
{
	(void)c; (void)port;
	if (size > 0 && count > 0 && (unsigned long)size * count <= sizeof(((struct read_cache *)0)->data))
		fill(v, size * count);
	return 1;
}
static int o_pio_out(struct x86_emulate_ctxt *c, int size, unsigned short port, const void *v, unsigned count)
{ (void)c; (void)size; (void)port; (void)v; (void)count; return 1; }
static int flat;
static bool o_get_segment(struct x86_emulate_ctxt *c, u16 *sel, struct desc_struct *d, u32 *base3, int seg)
{
	u64 r = rng();
	(void)c; (void)seg;
	if (flat) {
		static const u64 flat_desc = 0x00cf9b000000ffffull;
		*sel = 0x10;
		memcpy(d, &flat_desc, 8);
		if (base3)
			*base3 = 0;
		return 1;
	}
	*sel = (u16)r;
	memcpy(d, &r, sizeof(*d) < 8 ? sizeof(*d) : 8);
	if (base3)
		*base3 = (u32)(r >> 40);
	return (r >> 33) & 7;
}
static void o_set_segment(struct x86_emulate_ctxt *c, u16 sel, struct desc_struct *d, u32 base3, int seg)
{ (void)c; (void)sel; (void)d; (void)base3; (void)seg; }
static size_t o_seg_base(struct x86_emulate_ctxt *c, int seg)
{ (void)c; (void)seg; if (flat) return 0; return (rng() & 3) ? 0 : (size_t)(rng() & 0xffffffffu); }
static void o_get_dt(struct x86_emulate_ctxt *c, struct desc_ptr *dt)
{ (void)c; dt->size = (u16)rng(); dt->address = rng(); }
static void o_set_dt(struct x86_emulate_ctxt *c, struct desc_ptr *dt) { (void)c; (void)dt; }
static ulong o_get_cr(struct x86_emulate_ctxt *c, int cr) { (void)c; (void)cr; return (ulong)rng(); }
static int o_set_cr(struct x86_emulate_ctxt *c, int cr, ulong v) { (void)c; (void)cr; (void)v; return 0; }
static int o_cpl(struct x86_emulate_ctxt *c) { (void)c; if (flat) return 0; return (int)(rng() & 3); }
static int o_get_dr(struct x86_emulate_ctxt *c, int dr, ulong *dest) { (void)c; (void)dr; *dest = (ulong)rng(); return 0; }
static int o_set_dr(struct x86_emulate_ctxt *c, int dr, ulong v) { (void)c; (void)dr; (void)v; return 0; }
static u64 o_get_smbase(struct x86_emulate_ctxt *c) { (void)c; return rng(); }
static void o_set_smbase(struct x86_emulate_ctxt *c, u64 v) { (void)c; (void)v; }
static int o_set_msr(struct x86_emulate_ctxt *c, u32 i, u64 v) { (void)c; (void)i; (void)v; return (int)(rng() & 1); }
static int o_get_msr(struct x86_emulate_ctxt *c, u32 i, u64 *p) { (void)c; (void)i; *p = rng(); return (int)(rng() & 1); }
static int o_check_pmc(struct x86_emulate_ctxt *c, u32 pmc) { (void)c; (void)pmc; return (int)(rng() & 1); }
static int o_read_pmc(struct x86_emulate_ctxt *c, u32 pmc, u64 *p) { (void)c; (void)pmc; *p = rng(); return 0; }
static void o_void(struct x86_emulate_ctxt *c) { (void)c; }
static int o_fix_hypercall(struct x86_emulate_ctxt *c) { (void)c; return X86EMUL_CONTINUE; }
static int o_intercept(struct x86_emulate_ctxt *c, struct x86_instruction_info *i, enum x86_intercept_stage s)
{ (void)c; (void)i; (void)s; return X86EMUL_CONTINUE; }
static void o_get_cpuid(struct x86_emulate_ctxt *c, u32 *a, u32 *b, u32 *cx, u32 *d)
{ (void)c; *a = (u32)rng(); *b = (u32)rng(); *cx = (u32)rng(); *d = (u32)rng(); }
static void o_set_nmi_mask(struct x86_emulate_ctxt *c, bool m) { (void)c; (void)m; }

static const struct x86_emulate_ops ops = {
	.read_gpr = o_read_gpr, .write_gpr = o_write_gpr,
	.read_std = o_read, .read_phys = o_read_phys, .write_std = o_write,
	.fetch = o_fetch, .read_emulated = o_read_emu, .write_emulated = o_write_emu,
	.cmpxchg_emulated = o_cmpxchg, .invlpg = o_invlpg,
	.pio_in_emulated = o_pio_in, .pio_out_emulated = o_pio_out,
	.get_segment = o_get_segment, .set_segment = o_set_segment,
	.get_cached_segment_base = o_seg_base,
	.get_gdt = o_get_dt, .get_idt = o_get_dt, .set_gdt = o_set_dt, .set_idt = o_set_dt,
	.get_cr = o_get_cr, .set_cr = o_set_cr, .cpl = o_cpl,
	.get_dr = o_get_dr, .set_dr = o_set_dr,
	.get_smbase = o_get_smbase, .set_smbase = o_set_smbase,
	.set_msr = o_set_msr, .get_msr = o_get_msr,
	.check_pmc = o_check_pmc, .read_pmc = o_read_pmc,
	.halt = o_void, .wbinvd = o_void,
	.fix_hypercall = o_fix_hypercall,
	.get_fpu = o_void, .put_fpu = o_void,
	.intercept = o_intercept, .get_cpuid = o_get_cpuid, .set_nmi_mask = o_set_nmi_mask,
};

static struct x86_emulate_ctxt ctxt;

/* Decode (and optionally emulate) one instruction; `regs` NULL means PRNG-derived guest registers. */
static int run_one(u8 mode, u8 opts, u32 eflags, u32 seed, const size_t *regs, const u8 *insn, size_t len)
{
	int i, rc;

	flat = regs != NULL;
	insn_buf = insn;
	insn_len = len > 15 ? 15 : len;
	fetch_pos = 0;
	rng_state = 0x9e3779b97f4a7c15ull ^ ((u64)seed << 17 | seed);
	if (!rng_state)
		rng_state = 1;
	for (i = 0; i < 16; i++)
		gpr[i] = regs ? regs[i] : (size_t)rng();

	memset(&ctxt, 0, sizeof(ctxt));
	ctxt.ops = &ops;
	ctxt.eflags = eflags | 2;
	ctxt.tf = (ctxt.eflags & X86_EFLAGS_TF) != 0;
	ctxt.eip = regs ? 0x1000 : (size_t)rng();
	ctxt.mode = (enum x86emul_mode)mode;
	ctxt.emul_flags = 0;
	init_decode_cache(&ctxt);
	ctxt.interruptibility = 0;
	ctxt.have_exception = false;
	ctxt.exception.vector = -1;
	ctxt.perm_ok = false;
	ctxt.ud = (opts >> 2) & 1;

	emulator_invalidate_register_cache(&ctxt);
	if (opts & 2)
		rc = x86_decode_insn(&ctxt, (void *)insn_buf, (int)insn_len);
	else
		rc = x86_decode_insn(&ctxt, NULL, 0);
	if (rc != EMULATION_OK)
		return rc;

	if (opts & 1) {
		for (i = 0; i < 4; i++) {
			rc = x86_emulate_insn(&ctxt);
			if (rc != EMULATION_RESTART)
				break;
		}
		emulator_writeback_register_cache(&ctxt);
	}
	return rc;
}

#ifndef KAT_MAIN
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size)
{
	if (size < 9)
		return -1;
	run_one(data[0] % 5, data[1], data[2] | data[3] << 8,
		data[4] | data[5] << 8 | data[6] << 16 | (u32)data[7] << 24,
		NULL, data + 8, size - 8);
	return 0;
}
#else
/* Known-answer probe: decode/emulate fixed instructions from fixed register state and print the results. */
int printf(const char *, ...);

/* fmask keeps only the flags the instruction architecturally defines: AF/OF after shifts, AF after logic ops
 * and every flag after DIV are undefined and differ between Intel and AMD silicon. */
static void kat(const char *name, u8 mode, u32 eflags, u32 fmask, const size_t init[16], const u8 *insn, size_t len)
{
	size_t regs[16];
	int rc, i;

	for (i = 0; i < 16; i++)
		regs[i] = init ? init[i] : 0;
	rc = run_one(mode, 1 | 2, eflags, 1, regs, insn, len);
	printf("%s rc=%d eax=%lx ecx=%lx edx=%lx ebx=%lx eflags=%lx eip=%lx len=%lu vec=%d opb=%d\n", name, rc,
	       (unsigned long)gpr[0], (unsigned long)gpr[1], (unsigned long)gpr[2], (unsigned long)gpr[3],
	       (unsigned long)(ctxt.eflags & fmask), (unsigned long)(ctxt.eip - 0x1000), (unsigned long)len,
	       ctxt.have_exception ? ctxt.exception.vector : -1, ctxt.op_bytes);
}

#define R(n) regs_##n
int main(void)
{
	static const size_t r0[16] = { 0x11111111, 0, 0, 0x22222222 };
	static const size_t r1[16] = { 5, 0, 0, 7 };
	static const size_t r2[16] = { 100, 7, 0 };
	static const size_t r3[16] = { 100, 0, 0 };
	static const size_t r4[16] = { 0x0f };
	static const size_t r5[16] = { 0, 0x20, 0, 0x1000 };
	static const size_t r6[16] = { 0x80000000, 0, 0, 0 };
	static const size_t r7[16] = { 0xf0, 0, 0, 0x0f };

	/* PROT32: add eax,ebx; sub eax,ebx; div ecx; div by zero; shl eax,4; mov eax,imm; lea eax,[ebx+ecx] */
	kat("add", X86EMUL_MODE_PROT32, 0, 0x8d5, r0, (const u8 *)"\x01\xd8", 2);
	kat("sub", X86EMUL_MODE_PROT32, 0, 0x8d5, r1, (const u8 *)"\x29\xd8", 2);
	kat("div", X86EMUL_MODE_PROT32, 0, 0, r2, (const u8 *)"\xf7\xf1", 2);
	kat("div0", X86EMUL_MODE_PROT32, 0, 0, r3, (const u8 *)"\xf7\xf1", 2);
	kat("shl", X86EMUL_MODE_PROT32, 0, 0xc5, r4, (const u8 *)"\xc1\xe0\x04", 3);
	kat("movimm", X86EMUL_MODE_PROT32, 0, 0x8d5, NULL, (const u8 *)"\xb8\x78\x56\x34\x12", 5);
	kat("lea", X86EMUL_MODE_PROT32, 0, 0x8d5, r5, (const u8 *)"\x8d\x04\x0b", 3);
	/* operand-size prefix, REX.W, conditional jumps, bswap, and/or/xor on registers */
	kat("opsize16", X86EMUL_MODE_PROT32, 0, 0x8d5, r0, (const u8 *)"\x66\x01\xd8", 3);
	kat("rexw_add", X86EMUL_MODE_PROT64, 0, 0x8d5, r0, (const u8 *)"\x48\x01\xd8", 3);
	kat("jz_taken", X86EMUL_MODE_PROT32, 0x40, 0x8d5, NULL, (const u8 *)"\x74\x05", 2);
	kat("jz_not_taken", X86EMUL_MODE_PROT32, 0, 0x8d5, NULL, (const u8 *)"\x74\x05", 2);
	kat("bswap", X86EMUL_MODE_PROT32, 0, 0x8d5, r6, (const u8 *)"\x0f\xc8", 2);
	kat("xor", X86EMUL_MODE_PROT32, 0, 0x8c5, r7, (const u8 *)"\x31\xd8", 2);
	/* faults: LOCK on a non-lockable instruction -> #UD (6); undefined opcode -> decode failure */
	kat("lock_mov", X86EMUL_MODE_PROT32, 0, 0x8d5, r0, (const u8 *)"\xf0\x89\xd8", 3);
	kat("undef", X86EMUL_MODE_PROT64, 0, 0x8d5, NULL, (const u8 *)"\x06", 1);
	return 0;
}
#endif
