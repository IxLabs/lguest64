/*
 * Lguest specific paravirt-ops implementation
 *
 * Copyright (C) 2007, Glauber de Oliveira Costa <gcosta@redhat.com>
 *                     Steven Rostedt <srostedt@redhat.com>
 *                     Red Hat Inc
 * Standing on the shoulders of Rusty Russell.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <linux/kernel.h>
#include <linux/start_kernel.h>
#include <linux/string.h>
#include <linux/console.h>
#include <linux/screen_info.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/clocksource.h>
#include <linux/pfn.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/lguest.h>
#include <linux/lguest_launcher.h>
#include <asm/lguest_64.h>
#include <asm/paravirt.h>
#include <asm/param.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/desc.h>
#include <asm/setup.h>
#include <asm/e820.h>
#include <asm/asm-offsets.h>
#include <asm/mce.h>
#include <asm/proto.h>
#include <asm/sections.h>
#include <asm/io.h>
#include <asm/hw_irq.h>
#include <asm/smp.h>
#include "../../../drivers/lguest/lg.h"

//EXPORT_SYMBOL_GPL(sched_clock);

/* Declarations for definitions in lguest_asm.S */
extern char lguest_noirq_start[], lguest_noirq_end[];
extern const char lgstart_cli[], lgend_cli[];
extern const char lgstart_sti[], lgend_sti[];
extern const char lgstart_popf[], lgend_popf[];
extern const char lgstart_pushf[], lgend_pushf[];
extern const char lgstart_iret[], lgend_iret[];
extern void lguest_iret(void);
extern void lguest_syscall_return(void);
extern void lguest_swapgs(struct lg_cpu *);

static struct e820entry *e820map;

extern void (*pm_idle)(void);

struct lguest_data lguest_data;
struct lg_cpu_data *lguest_data_vcpu;

static cycle_t clock_base;

struct lguest_device_desc *lguest_devices;
static struct lguest_text_ptr code_stack[2];
extern int acpi_disabled;
extern int acpi_ht;

extern const unsigned long kallsyms_addresses[] __attribute__((weak));
extern const unsigned long kallsyms_num_syms __attribute__((weak));
extern const u8 kallsyms_names[] __attribute__((weak));
extern const u8 kallsyms_token_table[] __attribute__((weak));
extern const u16 kallsyms_token_index[] __attribute__((weak));
extern const unsigned long kallsyms_markers[] __attribute__((weak));

//static DEFINE_SPINLOCK(hcall_print_lock);
#define HCALL_BUFF_SIZ 1024
static char hcall_buff[HCALL_BUFF_SIZ];

/* Set to true when the lguest_init is called. */
static int lguest_paravirt;

struct lguest_print_ops {
	void (*vprint)(const char *fmt, va_list ap);
} *lguest_pops;

void lguest_vprint(const char *fmt, va_list ap)
{
	if (lguest_pops)
		lguest_pops->vprint(fmt, ap);
}

void lguest_print(const char *fmt, ...)
{
	va_list ap;

	/* irq save? */
	va_start(ap, fmt);
	lguest_vprint(fmt, ap);
	va_end(ap);
}

static void __lguest_vprint(const char *fmt, va_list ap)
{
	/* need to do this with interrupts disabled */
//	spin_lock(&hcall_print_lock);
	vsnprintf(hcall_buff, HCALL_BUFF_SIZ-1, fmt, ap);

	hcall(LHCALL_PRINT, __pa(hcall_buff), 0, 0, 0);
//	spin_unlock(&hcall_print_lock);
}

struct lguest_print_ops local_pops = {__lguest_vprint };

#ifdef CONFIG_DEBUG_KERNEL
#define LG_DEBUG_BUFSIZ 1024
static char lguest_debug_buff[LG_DEBUG_BUFSIZ];

static void lguest_debug_write(struct console *con, const char *s, unsigned n)
{
	if (n >= LG_DEBUG_BUFSIZ)
		n = LG_DEBUG_BUFSIZ;
	memcpy(lguest_debug_buff, s, n);
	lguest_debug_buff[n] = 0;
	hcall(LHCALL_PRINT, __pa(lguest_debug_buff), 0, 0, 0);
}

static struct console lguest_debug_console = {
	.name =		"lguest",
	.write =	lguest_debug_write,
	.flags =	CON_PRINTBUFFER,
	.index =	-1,
};
#endif


void lguest_do_debug(u64 d, u64 data)
{
	d *= -1;
	if (lguest_paravirt)
		hcall(LHCALL_DEBUG_ME, d, data, 0, 0);
}
EXPORT_SYMBOL_GPL(lguest_do_debug);

void lguest_set_debug(int d)
{
	if (lguest_paravirt)
		hcall(LHCALL_DEBUG_ME, d, 0, 0, 0);
}
EXPORT_SYMBOL_GPL(lguest_set_debug);

void async_hcall(unsigned long call,
		 unsigned long arg1, unsigned long arg2, unsigned long arg3)
{
	static unsigned int next_call;
	unsigned long flags;

	local_irq_save(flags);
	if (lguest_data_vcpu->hcall_status[next_call] != 0xFF) {
		/* Table full, so do normal hcall which will flush table. */
		hcall(call, arg1, arg2, arg3, 0);
	} else {
		lguest_data_vcpu->hcalls[next_call].rax = call;
		lguest_data_vcpu->hcalls[next_call].rdx = arg1;
		lguest_data_vcpu->hcalls[next_call].rbx = arg2;
		lguest_data_vcpu->hcalls[next_call].rcx = arg3;
		wmb();
		lguest_data_vcpu->hcall_status[next_call] = 0;
		if (++next_call == LHCALL_RING_SIZE)
			next_call = 0;
	}
	local_irq_restore(flags);
}

/* For guests, device memory can be used as normal memory, so we cast away the
 * __iomem to quieten sparse. */
void *lguest_map(unsigned long phys_addr, unsigned long pages)
{
	return (__force void *)ioremap(phys_addr, PAGE_SIZE*pages);
}

void lguest_unmap(void *addr)
{
	iounmap((__force void __iomem *)addr);
}

static int lazy_mode;
static void lguest_enter_lazy_mmu(void)
{
    lazy_mode = PARAVIRT_LAZY_MMU;
}

static void lguest_leave_lazy_mmu(void)
{
    lazy_mode = PARAVIRT_LAZY_NONE;
}

static void lazy_hcall(unsigned long call,
		       unsigned long arg1,
		       unsigned long arg2,
		       unsigned long arg3)
{
	if (lazy_mode == PARAVIRT_LAZY_NONE)
		hcall(call, arg1, arg2, arg3, 0);
	else
		async_hcall(call, arg1, arg2, arg3);
}

static void lguest_idle(void)
{
	local_irq_enable();
	/* should we do a hcall to let the HV know we're idle ? */
	cpu_relax();
}

/*
 * The following interrupt enable/disable routines are called via paravirt
 * inline assembly. Which means that gcc has no idea we will muck around
 * with any registers.  So we implement this in assembly, just to have
 * full control. Using rax is okay, since paravirt_ops clobber this
 * register
 */

static unsigned long save_fl(void)
{
	unsigned long flags = 0;
	asm volatile (
		"movq " __stringify(LG_CPU_DATA_irq_enabled)"(%0), %0\n"
		: "=a" (flags)
		: "0" (lguest_data_vcpu));
	return flags;
}

static void lg_restore_fl(unsigned long flags)
{
	/*
	 * Now we need to be careful in testing for
	 * irqs pending.
	 */
	asm volatile (
		"movq %0,"__stringify(LG_CPU_DATA_irq_enabled)"(%1)\n"

		"testq %2,"
		__stringify(LG_CPU_DATA_flags)"(%1)\n"

		"jz 1f\n"
		"movq  $" __stringify(LHCALL_S2H) ", %%rax\n"
		"int   $" __stringify(LGUEST_TRAP_ENTRY) "\n"
		"1:"
		:
		: "D" (flags),
		  "a" (lguest_data_vcpu), "i" (LG_CPU_IRQPEND_FL));
}

static void lguest_irq_disable(void)
{
	asm volatile (
		"movq $0," __stringify(LG_CPU_DATA_irq_enabled)"(%0)\n"
		:: "a" (lguest_data_vcpu));

}


static void lguest_irq_enable(void)
{
	asm volatile (
		"movq $512," __stringify(LG_CPU_DATA_irq_enabled)"(%0)\n"
		"testq %1,"
		__stringify(LG_CPU_DATA_flags)"(%0)\n"

		"jz 1f\n"
		"movq  $" __stringify(LHCALL_S2H) ", %%rax\n"
		"int   $" __stringify(LGUEST_TRAP_ENTRY) "\n"
		"1:"

		:
		: "a" (lguest_data_vcpu), "i" (LG_CPU_IRQPEND_FL));
}

/*
 * Let's pause a moment.  Remember how I said these are called so often?
 * Jeremy Fitzhardinge optimized them so hard early in 2009 that he had to
 * break some rules.  In particular, these functions are assumed to save their
 * own registers if they need to: normal C functions assume they can trash the
 * eax register.  To use normal C functions, we use
 * PV_CALLEE_SAVE_REGS_THUNK(), which pushes %eax onto the stack, calls the
 * C function, then restores it.
 */
PV_CALLEE_SAVE_REGS_THUNK(save_fl);
PV_CALLEE_SAVE_REGS_THUNK(lguest_irq_disable);
/*:*/

static void lguest_load_gdt(const struct desc_ptr *desc)
{
	/* Does nothing. HV should have done everything for us */
}

static void lguest_load_idt(const struct desc_ptr *desc)
{
	unsigned int i;
	struct gate_struct64 *idt = (void *)desc->address;

	for (i = 0; i < (desc->size+1)/16; i++) {
		hcall(LHCALL_LOAD_IDT_ENTRY, i, __pa((u64)&idt[i]), 0, 0);
	}
}

static int lguest_panic(struct notifier_block *nb, unsigned long l, void *p)
{
	hcall(LHCALL_SHUTDOWN, __pa(p), 0, 0, 0);
	return NOTIFY_DONE;
}

static struct notifier_block paniced = {
	.notifier_call = lguest_panic
};

static __init void lguest_memory_setup(void)
{
	/* We do this here because lockcheck barfs if before start_kernel */
	atomic_notifier_chain_register(&panic_notifier_list, &paniced);

	e820_add_region(e820map->addr, e820map->size, e820map->type);
	return;
}

static void lguest_cpuid(unsigned int *eax, unsigned int *ebx,
				 unsigned int *ecx, unsigned int *edx)
{
	int is_feature = (*eax == 1);

	native_cpuid(eax, ebx, ecx, edx);
	if (is_feature) {
		unsigned int *features = (unsigned int *)edx;
		/* We don't have any features or extended capabilities! */
		*features = 0;
		/* But Hypervisor needs to know when we flush kernel pages. */
		set_bit(X86_FEATURE_PGE, features);
	}
}

static DEFINE_PER_CPU(unsigned long, current_cr3);

static void lguest_write_cr3(unsigned long cr3)
{
	hcall(LHCALL_NEW_PGTABLE, cr3, 0, 0, 0);
	__get_cpu_var(current_cr3) = cr3;
}

static unsigned long lguest_read_msr(unsigned int msr, int *err)
{
	unsigned long val;
	unsigned long flags;

	*err = 0;
	switch (msr) {
	case MSR_KERNEL_GS_BASE:
		local_irq_save(flags);
		val = (lguest_data_vcpu->guest_gs_shadow_a & ((1UL << 32)-1)) |
			(lguest_data_vcpu->guest_gs_shadow_d << 32);
		local_irq_restore(flags);
		break;
	case MSR_GS_BASE:
		local_irq_save(flags);
		val = (lguest_data_vcpu->guest_gs_a & ((1UL << 32)-1)) |
			(lguest_data_vcpu->guest_gs_d << 32);
		local_irq_restore(flags);
		break;
	default:
		hcall(LHCALL_RDMSR, msr, __pa(&val), 0, 0);
	}
	return val;
}

extern void system_call_after_swapgs(void);
/* The lg module will need this for the host */
EXPORT_SYMBOL_GPL(system_call_after_swapgs);

static long lguest_write_msr(unsigned int msr, unsigned long val)
{
	unsigned long flags;

	switch (msr) {

	/* Ignore MTRR writing. Policy is up to host */
	case 0x200 ... 0x3ff:
		break;
	case MSR_KERNEL_GS_BASE:
		local_irq_save(flags);
		lguest_data_vcpu->guest_gs_shadow_a = val;
		lguest_data_vcpu->guest_gs_shadow_d = val >> 32;
		local_irq_restore(flags);
		break;
	case MSR_GS_BASE:
		local_irq_save(flags);
		lguest_data_vcpu->guest_gs_a = val;
		lguest_data_vcpu->guest_gs_d = val >> 32;
		hcall(LHCALL_UPDATE_GS, 0, 0, 0, 0);
		local_irq_restore(flags);
		break;
	case MSR_FS_BASE:
		local_irq_save(flags);
		lguest_data_vcpu->guest_fs_a = val;
		lguest_data_vcpu->guest_fs_d = val >> 32;
		hcall(LHCALL_UPDATE_FS, 0, 0, 0, 0);
		local_irq_restore(flags);
		break;
	case MSR_LSTAR:
		/* The hypervisor will do the swapgs for us */
		if (val == (unsigned long)system_call) {
			lguest_data_set_bit(SWAPGS, lguest_data_vcpu);
			val = (u64)system_call_after_swapgs;
		} else
			printk(KERN_ERR "warning! system_call not at system_call??\n");
		printk("val = %lx\n", val);
		/* fall through */
	default:
		hcall(LHCALL_WRMSR, msr, (unsigned long)val, 0, 0);
	}
	return 0;
}

static unsigned long lguest_read_tsc(void)
{
	return native_read_tsc();
}

static void lguest_flush_tlb(void)
{
	lazy_hcall(LHCALL_FLUSH_TLB, 0, 0, 0);
}

static void lguest_flush_tlb_kernel(void)
{
	lazy_hcall(LHCALL_FLUSH_TLB, 1, 0, 0);
}

static void lguest_flush_tlb_single(unsigned long addr)
{
	lazy_hcall(LHCALL_FLUSH_TLB_SIG, addr, 0, 0);
}

static void lguest_release_pgd(pgd_t *pgd)
{
	lazy_hcall(LHCALL_RELEASE_PGD, __pa(pgd), 0, 0);
}

static void lguest_set_pte(pte_t *ptep, pte_t pteval)
{
	unsigned long flags;

	local_irq_save(flags);
	/*
	 * The hyper call will set the unique per_cpu flag if it
	 * updates the pte val for us.
	 */
	lguest_data_clear_bit(PGSET, lguest_data_vcpu);
	lazy_hcall(LHCALL_SET_PTE, __pa(ptep), pte_val(pteval), 0);
	if (!lguest_data_test_bit(PGSET, lguest_data_vcpu))
		*ptep = pteval;
	local_irq_restore(flags);
}

static void lguest_set_pte_at(struct mm_struct *mm, u64 addr, pte_t *ptep, pte_t pteval)
{
	unsigned long flags;

	local_irq_save(flags);
	/*
	 * The hyper call will set the unique per_cpu flag if it
	 * updates the pte val for us.
	 */
	lguest_data_clear_bit(PGSET, lguest_data_vcpu);
	lazy_hcall(LHCALL_SET_PTE, __pa(ptep), pte_val(pteval), 0);
	if (!lguest_data_test_bit(PGSET, lguest_data_vcpu))
		*ptep = pteval;
	local_irq_restore(flags);
}

static void lguest_set_pmd(pmd_t *pmdp, pmd_t pmdval)
{
	unsigned long flags;

	local_irq_save(flags);
	/*
	 * The hyper call will set the unique per_cpu flag if it
	 * updates the pte val for us.
	 */
	lguest_data_clear_bit(PGSET, lguest_data_vcpu);
	lazy_hcall(LHCALL_SET_PMD, __pa(pmdp), pmd_val(pmdval), 0);
	if (!lguest_data_test_bit(PGSET, lguest_data_vcpu))
		*pmdp = pmdval;
	local_irq_restore(flags);
}

static void lguest_set_pud(pud_t *pudp, pud_t pudval)
{
	unsigned long flags;

	local_irq_save(flags);
	/*
	 * The hyper call will set the unique per_cpu flag if it
	 * updates the pte val for us.
	 */
	lguest_data_clear_bit(PGSET, lguest_data_vcpu);
	lazy_hcall(LHCALL_SET_PUD, __pa(pudp), pud_val(pudval), 0);
	if (!lguest_data_test_bit(PGSET, lguest_data_vcpu))
		*pudp = pudval;
	local_irq_restore(flags);
}

static void lguest_set_pgd(pgd_t *pgdp, pgd_t pgdval)
{
	unsigned long flags;

	local_irq_save(flags);
	lazy_hcall(LHCALL_SET_PGD, __pa(pgdp), pgd_val(pgdval), 0);
	/* The setting must be after the call */
	*pgdp = pgdval;
	local_irq_restore(flags);
}

#ifdef CONFIG_X86_LOCAL_APIC
static void lguest_apic_write(unsigned long reg, unsigned int v)
{
	static unsigned long cpu;

	switch (reg) {
	case APIC_ICR:
		hcall(LHCALL_APIC_WRITE, reg , v, cpu, 0);
		break;
	case APIC_ICR2:
		cpu = GET_APIC_DEST_FIELD(v);
		break;

	case APIC_EOI:
		/* We don't care too much about acknowledgements by now */
	default:
		/* Nor do we care about any other APIC crap */
		break;
	}
}

static unsigned int lguest_apic_read(unsigned long reg)
{
	return 0;
}
#endif



//FIXME - De unde a scos rsp0 ca eu vad numai sp0 in thread_struct
/*static void lguest_load_rsp0(struct tss_struct *tss,
				     struct thread_struct *thread)
{
	lguest_data_vcpu->tss_rsp0 = (unsigned long)thread->rsp0;
	
}
*/

static void lguest_load_tr_desc(void)
{
	/* FIXME: should we handle IST? */
}

static void lguest_set_ldt(const void *addr, unsigned entries)
{
	/* FIXME: Implement. */
	if (entries)
		hcall(LHCALL_SHUTDOWN, __pa("set_ldt not supported"), 0, 0, 0);
}

static void lguest_load_tls(struct thread_struct *t, unsigned int cpu)
{
	lazy_hcall(LHCALL_LOAD_TLS, __pa(&t->tls_array), cpu, 0);
}

static void lguest_set_debugreg(unsigned long value, int regno)
{
	/* FIXME: Implement */
}

static DEFINE_PER_CPU(unsigned int, lguest_cr0);
static void lguest_clts(void)
{
	lazy_hcall(LHCALL_TS, 0, 0, 0);
	__get_cpu_var(lguest_cr0) &= ~8U;
}

static unsigned long lguest_read_cr0(void)
{
	return __get_cpu_var(lguest_cr0);
}

static void lguest_write_cr0(unsigned long val)
{
	hcall(LHCALL_TS, val & 8, 0, 0, 0);
	__get_cpu_var(lguest_cr0) = val;
}

static unsigned long lguest_read_cr2(void)
{
	return lguest_data_vcpu->cr2;
}

static unsigned long lguest_read_cr3(void)
{
	return __get_cpu_var(current_cr3);
}

/* Used to enable/disable PGE, but we don't care. */
static unsigned long lguest_read_cr4(void)
{
	return 0;
}

static void lguest_write_cr4(unsigned long val)
{
}

static void disable_lguest_irq(unsigned int irq)
{
	set_bit(irq, lguest_data_vcpu->interrupts);
}

static void enable_lguest_irq(unsigned int irq)
{
	clear_bit(irq, lguest_data_vcpu->interrupts);
	/* FIXME: If it's pending? */
}

static struct irq_chip lguest_irq_controller = {
	.name		= "lguest",
    //FIXME
	//.mask		= disable_lguest_irq,
	//.mask_ack	= disable_lguest_irq,
	//.unmask		= enable_lguest_irq,
};

static cycle_t lguest_clock_read(struct clocksource *cs)
{
	unsigned long sec, nsec;

	/* If the Host tells the TSC speed, we can trust that. */
	if (lguest_data.tsc_khz)
		return native_read_tsc();

	/* If we can't use the TSC, we read the time value written by the Host.
	 * Since it's in two parts (seconds and nanoseconds), we risk reading
	 * it just as it's changing from 99 & 0.999999999 to 100 and 0, and
	 * getting 99 and 0.  As Linux tends to come apart under the stress of
	 * time travel, we must be careful: */
	do {
		/* First we read the seconds part. */
		sec = lguest_data.time.tv_sec;
		/* This read memory barrier tells the compiler and the CPU that
		 * this can't be reordered: we have to complete the above
		 * before going on. */
		rmb();
		/* Now we read the nanoseconds part. */
		nsec = lguest_data.time.tv_nsec;
		/* Make sure we've done that. */
		rmb();
		/* Now if the seconds part has changed, try again. */
	} while (unlikely(lguest_data.time.tv_sec != sec));

	/* Our non-TSC clock is in real nanoseconds. */
	return sec*1000000000ULL + nsec;
}

static struct clocksource lguest_clock = {
	.name			= "lguest",
	.rating			= 400,
	.read			= lguest_clock_read,
	.mask			= CLOCKSOURCE_MASK(64),
	.shift			= 22,
	.mult			= 1 << 22,
};

/* The "scheduler clock" is just our real clock, adjusted to start at zero */
static unsigned long lguest_sched_clock(void)
{
	return clocksource_cyc2ns(lguest_clock_read(NULL) - clock_base,
                              lguest_clock.mult,
                              lguest_clock.shift);
}

static irqreturn_t lguest_time_irq(int irq, void *desc)
{
    //FIXME Gaseste inlocuitor
    //Are probleme in fiecare din urmatoarele linii
	//write_seqlock(&xtime_lock);
	//do_timer(hcall(LHCALL_TIMER_READ, 0, 0, 0, 0));
	//update_process_times(user_mode(get_irq_regs()));
	//write_sequnlock(&xtime_lock);

	return IRQ_HANDLED;
}

static struct irqaction lguest_timer = {
        .handler        = lguest_time_irq,
        .flags          = IRQF_DISABLED | IRQF_TIMER | IRQF_PERCPU | IRQF_NOBALANCING,
        //FIXME
        //.mask           = CPU_MASK_ALL,
        .name           = "timer"
};

static void lguest_time_init(void)
{
	setup_irq(0, &lguest_timer);

	if (lguest_data.tsc_khz) {
		lguest_clock.mult = clocksource_khz2mult(lguest_data.tsc_khz,
							 lguest_clock.shift);
		lguest_clock.flags = CLOCK_SOURCE_IS_CONTINUOUS;
	}

	clock_base = lguest_clock_read(NULL);
	clocksource_register(&lguest_clock);
	hcall(LHCALL_TIMER_START, HZ, 0, 0, 0);

	/* Now we've set up our clock, we can use it as the scheduler clock */
	pv_time_ops.sched_clock = lguest_sched_clock;
	enable_lguest_irq(0);
}

/* From i8259.c */
void call_function_interrupt(void);

static void __init lguest_init_IRQ(void)
{
	unsigned int i;

	for (i = 0; i < LGUEST_IRQS; i++) {
		int vector = FIRST_EXTERNAL_VECTOR + i;
		if (i >= NR_IRQS)
			break;
		/* FIXTHEM: We should be doing it in a lot of other places */
		if (vector != IA32_SYSCALL_VECTOR) {
			set_intr_gate(vector, interrupt[i]);
			/* Note that PIC stands for Puppie Interrupt Controller */
			//set_irq_chip_and_handler_name(i, &lguest_irq_controller,
			//				 handle_level_irq, "PIC");
			hcall(LHCALL_LOAD_IDT_ENTRY, vector, __pa((u64)&idt_table[vector]), 0, 0);
		}
	}

#ifdef CONFIG_SMP
	set_intr_gate(CALL_FUNCTION_VECTOR, call_function_interrupt);
    //FIXME
	//set_intr_gate(INVALIDATE_TLB_VECTOR_START+0, invalidate_interrupt0);
	//set_intr_gate(INVALIDATE_TLB_VECTOR_START+1, invalidate_interrupt1);
	//set_intr_gate(INVALIDATE_TLB_VECTOR_START+2, invalidate_interrupt2);
	//set_intr_gate(INVALIDATE_TLB_VECTOR_START+3, invalidate_interrupt3);
	//set_intr_gate(INVALIDATE_TLB_VECTOR_START+4, invalidate_interrupt4);
	//set_intr_gate(INVALIDATE_TLB_VECTOR_START+5, invalidate_interrupt5);
	//set_intr_gate(INVALIDATE_TLB_VECTOR_START+6, invalidate_interrupt6);
	//set_intr_gate(INVALIDATE_TLB_VECTOR_START+7, invalidate_interrupt7);

	set_intr_gate(RESCHEDULE_VECTOR, reschedule_interrupt);

	hcall(LHCALL_LOAD_IDT_ENTRY, CALL_FUNCTION_VECTOR, __pa((u64)&idt_table[CALL_FUNCTION_VECTOR]), 0, 0);
	//hcall(LHCALL_LOAD_IDT_ENTRY, INVALIDATE_TLB_VECTOR_START+0, __pa((u64)&idt_table[INVALIDATE_TLB_VECTOR_START+0]), 0, 0);
	//hcall(LHCALL_LOAD_IDT_ENTRY, INVALIDATE_TLB_VECTOR_START+1, __pa((u64)&idt_table[INVALIDATE_TLB_VECTOR_START+1]), 0, 0);
	//hcall(LHCALL_LOAD_IDT_ENTRY, INVALIDATE_TLB_VECTOR_START+2, __pa((u64)&idt_table[INVALIDATE_TLB_VECTOR_START+2]), 0, 0);
	//hcall(LHCALL_LOAD_IDT_ENTRY, INVALIDATE_TLB_VECTOR_START+3, __pa((u64)&idt_table[INVALIDATE_TLB_VECTOR_START+3]), 0, 0);
	//hcall(LHCALL_LOAD_IDT_ENTRY, INVALIDATE_TLB_VECTOR_START+4, __pa((u64)&idt_table[INVALIDATE_TLB_VECTOR_START+4]), 0, 0);
	//hcall(LHCALL_LOAD_IDT_ENTRY, INVALIDATE_TLB_VECTOR_START+5, __pa((u64)&idt_table[INVALIDATE_TLB_VECTOR_START+5]), 0, 0);
	//hcall(LHCALL_LOAD_IDT_ENTRY, INVALIDATE_TLB_VECTOR_START+6, __pa((u64)&idt_table[INVALIDATE_TLB_VECTOR_START+6]), 0, 0);
	//hcall(LHCALL_LOAD_IDT_ENTRY, INVALIDATE_TLB_VECTOR_START+7, __pa((u64)&idt_table[INVALIDATE_TLB_VECTOR_START+7]), 0, 0);
	hcall(LHCALL_LOAD_IDT_ENTRY, RESCHEDULE_VECTOR, __pa((u64)&idt_table[RESCHEDULE_VECTOR]), 0, 0);
#endif
	
}

//FIXME - Stefan
//This function was copied from x86_32
/*
 * Interrupt descriptors are allocated as-needed, but low-numbered ones are
 * reserved by the generic x86 code.  So we ignore irq_alloc_desc_at if it
 * tells us the irq is already used: other errors (ie. ENOMEM) we take
 * seriously.
 */
int lguest_setup_irq(unsigned int irq)
{
	int err;

	/* Returns -ve error or vector number. */
	err = irq_alloc_desc_at(irq, 0);
	if (err < 0 && err != -EEXIST)
		return err;

	irq_set_chip_and_handler_name(irq, &lguest_irq_controller,
				      handle_level_irq, "level");
	return 0;
}

static void lguest_write_ldt_entry(struct desc_struct *dt,
				   int entrynum, u32 low, u32 high)
{
	/* FIXME: Allow this. */
	hcall(LHCALL_SHUTDOWN, __pa("write_ldt not supported"), 0, 0, 0);
}

static void lguest_write_gdt_entry(void *ptr, void *entry,
				   unsigned type, unsigned size)
{
	native_write_gdt_entry(ptr, entry, type, size);
	hcall(LHCALL_LOAD_GDT, __pa(ptr), GDT_ENTRIES, 0, 0);
}

static void lguest_write_idt_entry(void *addr, struct gate_struct64 *s)
{
	native_write_idt_entry(addr, 0, s);
}

static const struct lguest_insns
{
	const char *start, *end;
} lguest_insns[] = {
	[PARAVIRT_PATCH(pv_irq_ops.irq_disable)] = { lgstart_cli, lgend_cli },
	[PARAVIRT_PATCH(pv_irq_ops.irq_enable)] = { lgstart_sti, lgend_sti },
	[PARAVIRT_PATCH(pv_irq_ops.restore_fl)] = { lgstart_popf, lgend_popf },
	[PARAVIRT_PATCH(pv_irq_ops.save_fl)] = { lgstart_pushf, lgend_pushf },
};
static unsigned lguest_patch(u8 type, u32 clobber,
			     void *insns, unsigned long addr,
                             unsigned len)
{
	unsigned int insn_len;
	return len;

	printk("could patch type:%d  len=%d\n", type, len);
	/* FIXME: */
	return len;

	/* Don't touch it if we don't have a replacement */
	if (type >= ARRAY_SIZE(lguest_insns) || !lguest_insns[type].start)
		return len;

	insn_len = lguest_insns[type].end - lguest_insns[type].start;

	/* Similarly if we can't fit replacement. */
	if (len < insn_len)
		return len;

	memcpy(insns, lguest_insns[type].start, insn_len);
	return insn_len;
}

static void lguest_safe_halt(void)
{
	hcall(LHCALL_HALT, 0, 0, 0, 0);
}

static void lguest_wbinvd(void)
{
}

static unsigned long lguest_get_wallclock(void)
{
	return lguest_data.time.tv_sec;
}

static void lguest_power_off(void)
{
	hcall(LHCALL_SHUTDOWN, __pa("Power down"), 0, 0, 0);
}

//FIXME - deoarece syscall_init nu exista in paravirt_ops
//l-am scos cu totul
/*static void lguest_syscall_init(void)
{
	u64 smask = EF_TF|EF_DF|EF_IE|0x3000;
	lguest_data_vcpu->SFMASK = smask;
	lguest_data_set_bit(SWAPGS, lguest_data_vcpu);
	lguest_data_vcpu->LSTAR = (u64)system_call_after_swapgs;
}
*/

extern unsigned int num_processors;
extern u8 bios_cpu_apicid[];

/* copied from head64.c */
#define NEW_CL_POINTER		0x228	/* Relative to real mode data */
static void __init copy_bootdata(char *real_mode_data)
{
	unsigned long new_data = 0;
	char * command_line;

	//FIXME
    //Cine e x86_boot_params si BOOT_PARAM_SIZE acum?
    //Inainte era definit in bootsetup.h
    //memcpy(x86_boot_params, real_mode_data, BOOT_PARAM_SIZE);
	//new_data = *(u32 *) (x86_boot_params + NEW_CL_POINTER);
	command_line = __va(new_data);
	memcpy(boot_command_line, command_line, COMMAND_LINE_SIZE);
}

#ifdef CONFIG_SMP
extern void native_smp_prepare_boot_cpu(void);
extern struct task_struct *create_idle_thread(int cpu);
extern int init_gdt(int cpu);
extern void set_cpu_sibling_map(int cpu);
extern void init_pda(int cpu);
//FIXME - nu mai exista structura
//static struct call_data_struct * call_data;
static struct completion lguest_cpu_up_completion;
extern void exit_idle(void);

static DEFINE_SPINLOCK(call_lock);
DECLARE_PER_CPU(int, cpu_state);

void lguest_smp_prepare_boot_cpu(void)
{
	int cpu;

	WARN_ON(smp_processor_id() != 0);

	native_smp_prepare_boot_cpu();
	for (cpu = 0; cpu < NR_CPUS; cpu++) {
		cpus_clear(cpu_sibling_map[cpu]);
		cpus_clear(cpu_core_map[cpu]);
	}
}

void lguest_smp_prepare_cpus(unsigned max_cpus)
{
	int cpu;

    //FIXME
    //Nu merge nici cu cpu_data[smp_processor_id()] ca nu stie
    //cine e cpu_data.
	//current_cpu_data = boot_cpu_data;
	current_thread_info()->cpu = 0;

	/* 
	 * We are no multicores,
	 * no ht, are the only one to share the llc space, IOW:
	 * we're the only dog in tha house.
	 */
	for (cpu = 0; cpu < NR_CPUS; cpu++) {
		cpus_clear(cpu_sibling_map[cpu]);
		cpus_clear(cpu_core_map[cpu]);
	}

	set_cpu_sibling_map(0);
}

void lguest_start_secondary(void)
{
	cpu_init();
	preempt_disable();
	barrier();

	set_cpu_sibling_map(smp_processor_id());

    //FIXME
	//spin_lock(&vector_lock);
	__setup_vector_irq(smp_processor_id());	
	//spin_unlock(&vector_lock);

	//FIXME
	//cpu_set(smp_processor_id(), cpu_online_map);
    //per_cpu(cpu_state, smp_processor_id()) = CPU_ONLINE;

	complete(&lguest_cpu_up_completion);
	cpu_idle();
}


//FIXME - Toata functia e facuta varza !!!!!!!!
int lguest_cpu_up(unsigned cpu)
{
	struct task_struct *idle;
/*
	if (init_gdt(cpu))
		return -1;

	init_pda(cpu);
	idle = create_idle_thread(cpu);
	if (IS_ERR(idle))
		return PTR_ERR(idle);
    
    clear_tsk_thread_flag(idle, TIF_FORK);

	load_rsp0(&per_cpu(init_tss,cpu), &idle->thread);

	per_cpu(cpu_state, cpu) = CPU_UP_PREPARE;

	hcall(LHCALL_NEW_VCPU, cpu, idle->thread.rsp, 
				(unsigned long)lguest_start_secondary, 0);
*/
	/* if irqs are disabled, we may never have the timer to expire */
	WARN_ON(irqs_disabled());

	/* now we can put back our smp variants */
	//alternatives_smp_switch(1);

	/* 
	 * Instead of looping waiting for the vcpu to set itself online,
	 * we sit in a wait queue, and wait for it to notify us 
	 */
	init_completion(&lguest_cpu_up_completion);
	wait_for_completion_timeout(&lguest_cpu_up_completion, 3 * HZ);

    //FIXME
	//if (!cpu_isset(cpu, cpu_online_map)) {
	/* 
	 * This is all software controlled, so if we could not put the cpu
	 * online, there might be a bug somewhere. Let the user know, at
	 * least
	 */
	//	WARN_ON(1);
	//	return -EAGAIN;
	//}
	return 0;
}

void lguest_smp_cpus_done(unsigned max_cpus)
{
	/* Do nothing */
}

	
void lguest_smp_send_stop(void)
{
	/* 
	 * We should be processor 0, but there is no real reason for
	 * such a hard assumption
	 */
	hcall(LHCALL_STOP_VCPUS, smp_processor_id(), 0, 0, 0);
}

void lguest_smp_send_reschedule(int cpu)
{
	hcall(LHCALL_REMOTE_CALL, 1, cpu, RESCHEDULE_VECTOR, 0);
}


static inline void lguest_set_data(void (*func) (void *info), 
					void *info, int wait)
{

    //FIXME - Guess what? Nici call_data_struct nu mai exista
    //in kernel/smp.c
	//struct call_data_struct data;

	//data.func = func;
	//data.info = info;
	//atomic_set(&data.started, 0);
	//data.wait = wait;
	//if (wait)
	//	atomic_set(&data.finished, 0);

	//call_data = &data;
	//wmb();
}

void lguest_wait_response(int cpus, int wait)
{
	/* Wait for response */
    //FIXME - din cauza lui call_data
	//while (atomic_read(&(call_data->started)) != cpus)
	//	cpu_relax();

	if (!wait)
		return;

	//while (atomic_read(&(call_data->finished)) != cpus)
	//	cpu_relax();
}

int lguest_smp_call_function(void (*func)(void *info), void *info,
			     int nonatomic, int wait)
{
	int cpus = num_online_cpus() - 1;
	
	if (!cpus)
		return 0;

	spin_lock(&call_lock);
	lguest_set_data(func, info, wait);
	hcall(LHCALL_REMOTE_CALL, 0, 0, CALL_FUNCTION_VECTOR, 0);
	lguest_wait_response(cpus, wait);
	spin_unlock(&call_lock);
	return 0;
}

int lguest_smp_call_function_single(int cpu, void (*func)(void *info),
				    void *info, int nonatomic, int wait)
{
	/* prevent preemption and reschedule on another processor */
	int me = get_cpu();

	/* Can deadlock when called with interrupts disabled */
	WARN_ON(irqs_disabled());

	if (cpu == me) {
		local_irq_disable();
		func(info);
		local_irq_enable();
		put_cpu();
		return 0;
	}

	spin_lock(&call_lock);
	lguest_set_data(func, info, wait);
	hcall(LHCALL_REMOTE_CALL, 1, cpu, CALL_FUNCTION_VECTOR, 0);
	lguest_wait_response(num_online_cpus() - 1, wait);
	spin_unlock(&call_lock);
	put_cpu();
	return 0;
}

void lguest_smp_call_function_interrupt(void)
{
    //FIXME - smp-ul asta chiar s-a schimbat, nu gluma!
	//void (*func) (void *info) = call_data->func;
	//void *info = call_data->info;
	//int wait = call_data->wait;

	/*
	 * Notify initiating CPU that I've grabbed the data and am
	 * about to execute the function
	 */
	mb();
	//atomic_inc(&call_data->started);
	/*
	 * At this point the info structure may be out of scope unless wait==1
	 */
	exit_idle();
	irq_enter();
	//(*func)(info);
	irq_exit();
	//if (wait) {
	//	mb();
	//	atomic_inc(&call_data->finished);
	//}
}
#endif

/*
 * According to the lguest launcher code (in Documentation)
 * we have the following fields for the boot variable.
 */
#define BOOT_NUM_VCPUS		0x240
#define BOOT_GUEST_TYPE		0x23c
#define BOOT_INITRD_START	0x218
#define BOOT_INITRD_SIZE	0x21c	/* Argh, 32 bits */

__init void lguest_init(void *boot)
{
	int i;

	/*
	 * Bah, we are using the generic lguest loader, that
	 * happens to pass the initrd stuff in as 32 bits.
	 * But since we know we stash it at the top of memory
	 * we only need to find size of memory.
	 * Of course this limits our guests to 4Gigs.
	 * 
	 * Lets see if we can still get by with it.
	 */
	unsigned int initrd_size;

	initrd_size = *(unsigned int*)(boot+BOOT_INITRD_SIZE);
	e820map = (struct e820entry *)(boot+E820MAP);

	/* Copy boot parameters first. */
	copy_bootdata(boot);

	/* We're under lguest. */
	pv_info.name = "lguest";
	/* Paravirt is enabled. */
	pv_info.paravirt_enabled = 1;
	/* We're running at privilege level 1, not 0 as normal. */
	pv_info.kernel_rpl = 1;
	/* Everyone except Xen runs with this set. */
	pv_info.shared_kernel_pmd = 1;
    //FIXME
	//paravirt_ops.syscall_init = lguest_syscall_init;
	//paravirt_ops.syscall_return = lguest_syscall_return;

	/* Setup operations */
	pv_init_ops.patch = lguest_patch;

	/* Interrupt-related operations */
	pv_irq_ops.save_fl = PV_CALLEE_SAVE(save_fl);
    pv_irq_ops.restore_fl = __PV_IS_CALLEE_SAVE(lg_restore_fl);
    pv_irq_ops.irq_disable = PV_CALLEE_SAVE(lguest_irq_disable);
    pv_irq_ops.irq_enable = __PV_IS_CALLEE_SAVE(lguest_irq_enable);
	pv_irq_ops.safe_halt = lguest_safe_halt;

    
	/* Intercepts of various CPU instructions */
    pv_cpu_ops.load_gdt = lguest_load_gdt;
    pv_cpu_ops.cpuid = lguest_cpuid;
	pv_cpu_ops.load_idt = lguest_load_idt;
	pv_cpu_ops.iret = lguest_iret;
    //FIXME
	//pv_cpu_ops.load_rsp0 = lguest_load_rsp0;
	pv_cpu_ops.load_tr_desc = lguest_load_tr_desc;
	pv_cpu_ops.set_ldt = lguest_set_ldt;
	pv_cpu_ops.load_tls = lguest_load_tls;
	pv_cpu_ops.set_debugreg = lguest_set_debugreg;
	pv_cpu_ops.clts = lguest_clts;
	pv_cpu_ops.read_cr0 = lguest_read_cr0;
	pv_cpu_ops.write_cr0 = lguest_write_cr0;
	pv_cpu_ops.read_cr4 = lguest_read_cr4;
	pv_cpu_ops.write_cr4 = lguest_write_cr4;
	pv_cpu_ops.write_ldt_entry = lguest_write_ldt_entry;
	pv_cpu_ops.write_gdt_entry = lguest_write_gdt_entry;
	pv_cpu_ops.write_idt_entry = lguest_write_idt_entry;
	pv_cpu_ops.wbinvd = lguest_wbinvd;
	pv_cpu_ops.read_msr = lguest_read_msr,
	pv_cpu_ops.write_msr = lguest_write_msr,
	pv_cpu_ops.read_tsc = lguest_read_tsc,

	/* Pagetable management */
	pv_mmu_ops.write_cr3 = lguest_write_cr3;
	pv_mmu_ops.flush_tlb_user = lguest_flush_tlb;
	pv_mmu_ops.flush_tlb_single = lguest_flush_tlb_single;
	pv_mmu_ops.flush_tlb_kernel = lguest_flush_tlb_kernel;
    pv_mmu_ops.set_pte = lguest_set_pte;
    pv_mmu_ops.set_pte_at = lguest_set_pte_at;
	pv_mmu_ops.set_pmd = lguest_set_pmd;
	pv_mmu_ops.set_pud = lguest_set_pud;
	pv_mmu_ops.set_pgd = lguest_set_pgd;
	//FIXME Nu exista asa ceva
    //pv_mmu_ops.release_pgd = lguest_release_pgd;
	pv_mmu_ops.read_cr2 = lguest_read_cr2;
	pv_mmu_ops.read_cr3 = lguest_read_cr3;
    pv_mmu_ops.lazy_mode.enter = lguest_enter_lazy_mmu;
    pv_mmu_ops.lazy_mode.leave = lguest_leave_lazy_mmu;

#ifdef CONFIG_X86_LOCAL_APIC
	apic->write = lguest_apic_write;
	apic->read = lguest_apic_read;
#endif

    x86_init.resources.memory_setup = lguest_memory_setup;
	x86_init.irqs.intr_init = lguest_init_IRQ;
	x86_init.timers.timer_init = lguest_time_init;
	x86_platform.get_wallclock =  lguest_get_wallclock;

#ifdef CONFIG_SMP
	smp_ops.smp_prepare_boot_cpu = lguest_smp_prepare_boot_cpu;
	smp_ops.smp_prepare_cpus = lguest_smp_prepare_cpus;
	smp_ops.cpu_up = lguest_cpu_up;
	smp_ops.smp_cpus_done = lguest_smp_cpus_done;
    smp_ops.stop_other_cpus = lguest_smp_send_stop;
    smp_ops.smp_send_reschedule = lguest_smp_send_reschedule;
    // FIXME - Stefan
    //  These SMP operations does NOT exist in any kernel
    //  RedHat guys added them. Should I add them, too?
    //  If yes, what other changes are necessary
    //  smp_ops.smp_call_function = lguest_smp_call_function;
    //	smp_ops.smp_call_function_single = lguest_smp_call_function_single;
    //	smp_ops.smp_call_function_interrupt = lguest_smp_call_function_interrupt;
#endif

	lguest_data.noirq_start = (u64)lguest_noirq_start;
	lguest_data.noirq_end = (u64)lguest_noirq_end;

	lguest_data.start_kernel_map = __START_KERNEL_map; /* current page offset */
	lguest_data.page_offset = PAGE_OFFSET;

	code_stack[0].next = __pa(&code_stack[1]);
	code_stack[0].start = (unsigned long)_stext;
	code_stack[0].end = (unsigned long)_etext;
	code_stack[1].next = 0;
	code_stack[1].start = (unsigned long)_sinittext;
	code_stack[1].end = (unsigned long)_einittext;

	lguest_data.text = __pa(&code_stack[0]);

	/* We won't provide any EBDA info, so signal that */
	*(unsigned short *)(__va(0x40E)) = 0;

	lguest_data.kallsyms_addresses = __pa(&kallsyms_addresses);
	lguest_data.kallsyms_num_syms = kallsyms_num_syms;
	lguest_data.kallsyms_names = __pa(&kallsyms_names);
	lguest_data.kallsyms_token_table = __pa(&kallsyms_token_table);
	lguest_data.kallsyms_token_index = __pa(&kallsyms_token_index);
	lguest_data.kallsyms_markers = __pa(&kallsyms_markers);

	/* Tell the HV what vector IRQ0 starts with */
	lguest_data.irq0_vector = IRQ0_VECTOR;
	
	hcall(LHCALL_LGUEST_INIT, __pa(&lguest_data), 0, 0, 0);

	lguest_data_vcpu = (struct lg_cpu_data*)lguest_data.vcpu_shared_data;

	lguest_pops = &local_pops;
	lguest_paravirt = 1;

	barrier();
	/* Now we can update lguest_swapgs (uses vcpu data) */
	pv_cpu_ops.swapgs = lguest_swapgs;

	lguest_write_cr3(__pa_symbol(&init_level4_pgt));

	for (i = 0; i < NR_CPUS; i++) {
        //FIXME
 		//cpu_pda(i) = &boot_cpu_pda[i];
		per_cpu(current_cr3, i) = __pa(&init_level4_pgt);
		//cpu_set(i, cpu_possible_map);
	}

	//pda_init(0);

#ifdef CONFIG_SMP
    //FIXME Cine e cpu_online_map
	//cpu_set(0, cpu_online_map);
#endif
	/* We use top of mem for initial pagetables. */
//	init_pg_tables_end = __pa(pg0);

//	reserve_top_address(lguest_data.reserve_mem);

	/* FIXME: Better way? */
	/* Suppress vgacon startup code */
    //Ce e SCREEN_INFO ?
	//SCREEN_INFO.orig_video_isVGA = VIDEO_TYPE_VLFB;

#ifdef CONFIG_DEBUG_KERNEL
	register_console(&lguest_debug_console);
#endif

	/* let the host time us! */
	lguest_data_set_bit(TIME, lguest_data_vcpu);
	hcall(LHCALL_S2H, 0, 0, 0, 0);
	hcall(LHCALL_S2H, 0, 0, 0, 0);

	add_preferred_console("hvc", 0, NULL);

	num_processors = *(int *)(boot+BOOT_NUM_VCPUS);
	for (i = 1; i < num_processors ; i++) {
        //FIXME
        //Nu stiu nici de cpu_present_map...
        //cpu_set(i, cpu_present_map);
		physid_set(i, phys_cpu_present_map);
	}

/*
#ifdef CONFIG_X86_MCE
	mcheck_disable(NULL);
#endif
*/
#ifdef CONFIG_ACPI
	acpi_disabled = 1;
	//FIXME - Nici macar nu stiu ce e ACPI...
    //Trebuie sa vad de ce nu gaseste acpi_ht, dar la compilare in gasea...
    //acpi_ht = 0;
#endif
	if (initrd_size) {
		/*
		 * We stash this at top of memory.
		 * We know we put the size of memory in our
		 * e820map->mem field
		 */
        //FIXME - Ce erau astea? Variabile globale
		//INITRD_START = e820map->size - initrd_size;
		//INITRD_SIZE = initrd_size;
		//LOADER_TYPE = 0xFF;
	}
	pm_power_off = lguest_power_off;

    //FIXME Cum poti sa faci
    //pointer la functie = pointer la alta functie
    //Pointerii nu sunt constanti ???
	//pm_idle = lguest_idle;

	start_kernel();
}
