#include <linux/module.h>
#include <linux/sched.h>
#include <linux/freezer.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <asm/paravirt.h>
#include <asm/uaccess.h>
#include <asm/i387.h>
#include <asm/msr.h>
#include <asm/pgtable.h>
/* for rtc emulation */
#include <linux/mc146818rtc.h>
#include <linux/bcd.h>
#include "lg.h"

#define HV_OFFSET(x) (typeof(x))((unsigned long)(x)+lguest_hv_offset)

/* Note: each level can really slow things down */
#define DEBUG_LEVEL 0
#define DEBUG_PAGE_CHECK 0

#if DEBUG_LEVEL > 0
#  define debug_hv_paranoid(vcpu) lguest_check_hv_pages(vcpu)
#  if DEBUG_LEVEL > 1
#    if DEBUG_LEVEL > 2
#      define debug_page_super_paranoid(vcpu) lguest_paranoid_page_check(vcpu, DEBUG_PAGE_CHECK)
#    else
#      define debug_page_paranoid(vcpu) lguest_paranoid_page_check(vcpu, DEBUG_PAGE_CHECK)
#    endif
#  endif
#endif
#ifndef debug_hv_paranoid
#  define debug_hv_paranoid(vcpu) do { } while(0)
#endif
#ifndef debug_page_paranoid
#  define debug_page_paranoid(vcpu) do { } while(0)
#endif
#ifndef debug_page_super_paranoid
#  define debug_page_super_paranoid(vcpu) do { } while(0)
#endif

struct vm_struct *lguest_vm_area;
unsigned long lguest_hv_start;
unsigned long lguest_hv_size;

/* syscall magic handling */
static DEFINE_PER_CPU(unsigned long, host_old_lstar);
#define LGUEST_SYSCALL_BYTES 16
static char host_jmp_to_syscall[LGUEST_SYSCALL_BYTES];
static DEFINE_PER_CPU(char [LGUEST_SYSCALL_BYTES], guest_jmp_to_syscall);
unsigned long lguest_host_system_call;
extern unsigned long system_call_after_swapgs;
extern unsigned long _lguest_syscall_host;

/* text section */
unsigned long lguest_hv_addr;
unsigned long lguest_hv_offset;
int lguest_hv_pages;

/* read only per cpu section */
int lg_cpu_pages;
int lg_cpu_order;
unsigned long lg_cpu_addr;

/* read write per cpu section */
int lg_cpu_data_pages;
int lg_cpu_data_order;
unsigned long lg_cpu_data_addr;

int lg_cpu_regs_pages;
int lg_cpu_regs_order;
unsigned long lg_cpu_regs_addr;

/* used for nmi stack */
static unsigned long lguest_nmi_playground;




/* FIXME: This is bogus, compute it on-demand */
struct list_head lguests;

u8 lgread_u8(struct lguest *lg, u64 addr)
{
	u8 val = 0;

	if (!lguest_address_ok(lg, addr, 8)
	    || get_user(val, (u8 __user *)addr) != 0)
			kill_guest(lg, "bad read address %llx", addr);
	return val;
}

u16 lgread_u16(struct lguest *lg, u64 addr)
{
	u16 val = 0;

	if (!lguest_address_ok(lg, addr, 16)
	    || get_user(val, (u16 __user *)addr) != 0)
			kill_guest(lg, "bad read address %llx", addr);
	return val;
}

u64 lgread_u32(struct lguest *lg, u64 addr)
{
	u64 val = 0;

	if (!lguest_address_ok(lg, addr, 32)
	    || get_user(val, (u32 __user *)addr) != 0)
			kill_guest(lg, "bad read address %llx", addr);
	return val;
}

u64 lgread_u64(struct lguest *lg, u64 addr)
{
	u64 val = 0;

	if (!lguest_address_ok(lg, addr, 64)
	    || get_user(val, (u64 __user *)addr) != 0)
			kill_guest(lg, "bad read address %llx", addr);
	return val;
}

void lgwrite_u32(struct lguest *lg, u64 addr, u64 val)
{
	if (!lguest_address_ok(lg, addr, 32)
	    || put_user(val, (u32 __user *)addr) != 0)
		kill_guest(lg, "bad write %llx <== %llx", addr, val);
}

void lgwrite_u64(struct lguest *lg, u64 addr, u64 val)
{
	if (!lguest_address_ok(lg, addr, 64)
	    || put_user(val, (u64 __user *)addr) != 0)
		kill_guest(lg, "bad write %llx <== %llx", addr, val);
}

void lgread(struct lguest *lg, void *b, u64 addr, unsigned bytes)
{
	if (addr + bytes < addr || !lguest_address_ok(lg, addr, bytes)
	   || copy_from_user(b, (void __user *)addr, bytes) != 0) {
		/* copy_from_user should do this, but as we rely on it... */
		memset(b, 0, bytes);
		kill_guest(lg, "bad read address %llx len %u", addr, bytes);
	}
}

void lgwrite(struct lguest *lg, u64 addr, const void *b,
								unsigned bytes)
{
	if (addr + bytes < addr
	    || !lguest_address_ok(lg, addr, bytes)
	   || copy_to_user((void __user *)addr, b, bytes) != 0)
		kill_guest(lg, "bad write address %llx len %u", addr, bytes);
}

static struct gate_struct *get_idt_table(void)
{
	struct desc_ptr idt;

	asm("sidt %0":"=m" (idt));
	return (void *)idt.address;
}

void lguest_swapgs(struct lg_cpu *cpu)
 {
	 unsigned long tmp_a, tmp_d;
	 tmp_a = cpu->lg_cpu_data->guest_gs_a;
	 tmp_d = cpu->lg_cpu_data->guest_gs_d;
	 cpu->lg_cpu_data->guest_gs_a = cpu->lg_cpu_data->guest_gs_shadow_a;
	 cpu->lg_cpu_data->guest_gs_d = cpu->lg_cpu_data->guest_gs_shadow_d;
	 cpu->lg_cpu_data->guest_gs_shadow_a = tmp_a;
	 cpu->lg_cpu_data->guest_gs_shadow_d = tmp_d;
	 lgdebug_lprint(LGD_GS_FL, "guest gs: %lx %lx  shadow: %lx %lx\n",
			cpu->lg_cpu_data->guest_gs_d, cpu->lg_cpu_data->guest_gs_a,
			cpu->lg_cpu_data->guest_gs_shadow_d,
			cpu->lg_cpu_data->guest_gs_shadow_a);
 }

static void emulate_rtc_read(struct lg_cpu *cpu)
{
	struct lguest_regs *regs = &cpu->regs;
	unsigned char type = cpu->lg->rtc;
	int t = -1;
	int offset = 0;
	int val = 0xff;
	struct rtc_time wtime; 
	int *ptr;

	switch(type) {
	case RTC_SECONDS: t = 0; ptr = &wtime.tm_sec; break;
	case RTC_MINUTES: t = 1; ptr = &wtime.tm_min; break;
	case RTC_HOURS: t = 2; ptr = &wtime.tm_hour; break;
	case RTC_DAY_OF_MONTH: t = 6; ptr = &wtime.tm_mday; break;
	case RTC_MONTH: t = 3; ptr = &wtime.tm_mon; break;
	case RTC_YEAR: t = 4; ptr = &wtime.tm_year; break;
	case RTC_DAY_OF_WEEK: t = 5; ptr = &wtime.tm_wday; break;

	case RTC_FREQ_SELECT:
	case RTC_CONTROL:
	case RTC_INTR_FLAGS:
	case RTC_VALID:
		val = 0;
		break;
	}

	if (t >= 0) {

#if 0 /* would be nice if rtc_get_rtc_time was exported */
		memset(&wtime, 0, sizeof(struct rtc_time));
		rtc_get_rtc_time(&wtime);
		offset = cpu->lg->rtc_offsets[t];
		val = *ptr + offset;
		val = bin2bcd(val);
#else
		offset = cpu->lg->rtc_offsets[t];
		val = CMOS_READ(type);
		val = bcd2bin(val);
		val += offset;
		val = bin2bcd(val);
#endif
	}
	regs->rax &= ~0xff;
	regs->rax |= val;
}

static void emulate_rtc_write(struct lg_cpu *cpu, unsigned int port)
{
	struct lguest_regs *regs = &cpu->regs;
	unsigned int rtc = (unsigned int)(regs->rax & 0xff);

	switch (port) {
	case 0x70:
		switch (rtc) {
		case RTC_FREQ_SELECT:
		case RTC_CONTROL:
		case RTC_INTR_FLAGS:
		case RTC_VALID:
		case RTC_SECONDS:
		case RTC_MINUTES:
		case RTC_HOURS:
		case RTC_MONTH:
		case RTC_YEAR:
		case RTC_DAY_OF_WEEK:
		case RTC_DAY_OF_MONTH:
			break;
		default:
			rtc = 0;
			/* Error ?? */
			break;
		}
		cpu->lg->rtc = rtc;
		break;

	case 0x71:
	{
		int t = -1;
		int r;

		switch(cpu->lg->rtc) {
		case RTC_SECONDS: t = 0; break;
		case RTC_MINUTES: t = 1; break;
		case RTC_HOURS: t = 2; break;
		case RTC_MONTH: t = 3; break;
		case RTC_YEAR: t = 4; break;
		case RTC_DAY_OF_WEEK: t = 5; break;
		case RTC_DAY_OF_MONTH: t = 6; break;
		default:
			/* Don't do anything to our rtc */
			break;
		}
		if (t < 0)
			return;
		r = (CMOS_READ(cpu->lg->rtc) & 0xff);
		r = bcd2bin(r);
		rtc = bcd2bin(rtc);
		cpu->lg->rtc_offsets[t] = rtc - r;
	}
	}
}

#define ddprintk(x...) do { } while(0)

static int emulate_insn(struct lg_cpu *cpu)
{
	u8 insn;
	u8 insn_b2;
	unsigned int insnlen = 0, in = 0, shift = 0;
	unsigned int byte;
	struct lguest_regs *regs = &cpu->regs;
	unsigned long physaddr = lguest_find_guest_paddr(cpu, regs->rip);

	/* FIXME: Handle physaddr's that crosses pages (modules are in VM) */
	if ((physaddr & PAGE_MASK) != ((physaddr+3) & PAGE_MASK))
		printk("WARNING! emulate instruction crossing page bounderies\n"
		       "  is not yet fully supported!\n");
	if (regs->rip < cpu->lg->page_offset)
		return 0;

	lgread(cpu->lg, &insn, physaddr, 1);

	/* Operand size prefix means it's actually for ax. */
	if (insn == 0x66) {
		shift = 16;
		insnlen = 1;
		printk("physaddr + len: %lx\n",physaddr+insnlen);
		lgread(cpu->lg, &insn, physaddr + insnlen, 1);
	}

	switch (insn & 0xFE) {
	case 0xE4: /* in     <next byte>,%al */
		lgread(cpu->lg, &byte, physaddr+1, 1);
		ddprintk("in %x, %x\n", (unsigned int)(byte),(unsigned int)(regs->rax&0xff));
		if (byte == RTC_PORT(1))
			emulate_rtc_read(cpu);
		else
			in = 1;
		insnlen += 2;
		break;
	case 0xEC: /* in     (%dx),%al */
		/* 0x71 is the rtc */
		ddprintk("in (%x), %x\n", (unsigned int)(regs->rdx & 0xffff),
		       (unsigned int)(regs->rax&0xff));
		if ((regs->rdx & 0xffff) == RTC_PORT(1))
			emulate_rtc_read(cpu);
		else
			in = 1;
		insnlen += 1;
		break;
	case 0xE6: /* out    %al,<next byte> */
		lgread(cpu->lg, &byte, physaddr+1, 1);
		ddprintk("out %x, %x\n", (unsigned int)(regs->rax & 0xff), byte);
		if ((byte & 0xfffe) == 0x70)
			emulate_rtc_write(cpu, byte);
		insnlen += 2;
		break;
	case 0xEE: /* out    %al,(%dx) */
		/* 0x70 or 0x71 is the rtc */
		ddprintk("out %x, (%x)\n", (unsigned int)(regs->rax & 0xff),
		       (unsigned int)(regs->rdx & 0xffff));
		if ((regs->rdx & 0xfffe) == 0x70)
			emulate_rtc_write(cpu, regs->rdx & 0xffff);
		insnlen += 1;
		break;
	default:
		if (insn == 0x0F)
			goto two_byte;

		printk("%llx: %02x unimplemented op\n", regs->rip, insn);
		kill_guest_dump(cpu, "bad one byte op");
		return 0;
	}
	if (in) {
		/* Lower bit tells is whether it's a 16 or 32 bit access */
		if (insn & 0x1)
			regs->rax = 0xFFFFFFFF;
		else
			regs->rax |= (0xFFFF << shift);
	}

	goto out;

two_byte:
	
	lgread(cpu->lg, &insn_b2, physaddr+1, 1);
	insnlen = 2;
	switch (insn_b2) {
	case 0x01: {
		u8 modrm;
		lgread(cpu->lg, &modrm, physaddr+2, 1);
		if (modrm == 0xF8) { 
			/* this is swapgs, in case you are wondering. 
			 * Some of the swapgs call sites (beginning/end of
			 * syscall are a bit problematic. So it is easier to
			 * let it fault, and do things behind the courtains.
			*/
			lgdebug_lprint(LGD_GS_FL, "guest doing a direct swapgs rip: %llx\n",
				       regs->rip);
			lguest_swapgs(cpu);
			insnlen++;
			break;
		}
	}
	default:
		printk("%llx: %02x %02x unimplemented op\n", regs->rip, insn, insn_b2);
		kill_guest_dump(cpu, "bad two byte op");
		return 0;
	}
		
		
out:
	regs->rip += insnlen;
	return 1;
}

void lguest_arch_handle_trap(struct lg_cpu *cpu){
    struct lguest_regs *regs = cpu->regs;
    unsigned long cr2 = 0;
    int ret;

    switch (regs->trapnum) {
    case 7:
        /* We've intercepted a Device Not Available fault. */
        /* If they don't want to know, just absorb it. */
        if (!cpu->ts)
            return;
        if (reflect_trap(cpu, 7, 0))
            return;
        kill_guest(cpu->lg, "Unhandled FPU trap at %#llx",
                   regs->rip);
    case 13:
        if (!regs->errcode) {
            ret = emulate_insn(cpu);
            if (ret < 0) {
                printk("bad emulate\n");
                lguest_dump_vcpu_regs(cpu);
                return;
            }
            return;
        }
        kill_guest_dump(cpu, "took gfp errcode %lld\n", regs->errcode);
        break;
    case 14:
        if (demand_page(cpu, cr2, regs->errcode & PF_WRITE))
            return;

        lgdebug_lprint(LGD_PF_FL, "pass faulting address %lx to guest ring %d\n",
                       cr2, cpu->regs->cs & 3);

        /* inform guest on the current state of cr2 */
        cpu->lg_cpu_data->cr2 = cr2;

        /*
         *           * Make the u/s bit of the error code reflect the
         *                       * mode that the fault was in.
         *                                   */
        if ((regs->cs & 3) == 3)
            regs->errcode |= PF_USER;
        else
            regs->errcode &= ~PF_USER;

        debug_page_paranoid(cpu);

        /* update the error code to see if this was a user trap */
        if (reflect_trap(cpu, 14, 1))
            return;

        kill_guest_dump(cpu, "unhandled page fault at %#lx"
                        " (rip=%#llx, errcode=%#llx)",
                        cr2, regs->rip, regs->errcode);
        break;
    case LGUEST_TRAP_ENTRY:
        /* hypercall! */
        return;

    case 32 ... 255:
        cond_resched();
        break;
#if 0
    case 252 ... 255:
        printk("Got in trap %llx\n",regs->trapnum);
        reflect_trap(cpu, regs->trapnum, 0);
        break;
#endif 

    case 0:
    case 4 ... 6:
        if (reflect_trap(cpu, regs->trapnum, 0))
            return;

    /* fall through */
    default:
        kill_guest_dump(cpu, "bad trapnum %lld in vcpu %d\n", regs->trapnum, cpu->id);
        return;
    }
}

void lguest_arch_setup_regs(struct lg_cpu *cpu, unsigned long start){
    //TODO
}

/*
 * _lguest_syscall_jumps - the per cpu array of text to jump to
 *    the specified syscall handlers.
 */
extern unsigned long _lguest_syscall_jumps;

/* lguest_get_syscall - return the address of the CPU syscall text */
static inline unsigned long lguest_get_syscall(int cpu)
{
	unsigned long ret = (unsigned long)&_lguest_syscall_jumps +
		(cpu * L1_CACHE_BYTES);
	return HV_OFFSET(ret);
}

/* lguest_set_syscall_host - change the syscall text to jump to host syscall */
static inline void lguest_set_syscall_host(int cpu)
{
	void *addr = (void*)lguest_get_syscall(cpu);

	memcpy(addr, host_jmp_to_syscall, LGUEST_SYSCALL_BYTES);
}

/* lguest_set_syscall_guest - change the syscall text to jump to guest syscall */
static inline void lguest_set_syscall_guest(int cpu)
{
	void *addr = (void*)lguest_get_syscall(cpu);

	memcpy(addr, per_cpu(guest_jmp_to_syscall, cpu), LGUEST_SYSCALL_BYTES);
}

#define SAVE_CR2(cr2)	asm volatile ("movq %%cr2, %0" : "=r" (cr2))

static void run_guest_once(struct lg_cpu *cpu)
{
	void (*sw_guest)(struct lg_cpu *) = HV_OFFSET(&switch_to_guest);
	unsigned long foo, bar;
	unsigned long old_fsbase = 0;
	unsigned long old_fs;
	u64 start = 0, end;
	struct lguest_regs *regs = cpu->regs;
	int cpuid = smp_processor_id();
	int ret;

	BUG_ON(!regs->cr3);
	BUG_ON(!cpu->pgd);

	if (lguest_data_test_bit(TIME, cpu->lg_cpu_data))
		start = sched_clock();

	debug_hv_paranoid(cpu);

	/*
	 * To simplify things (yeah, right!) we match the host
	 * pages to the guest pages WRT the HV.  The host will
	 * have all the guest pages as RW, but the guest
	 * will only have it's guest data RW and not the HV.
	 */
	ret = lguest_update_page_tables(cpu);
	if (ret) {
		printk("failed mapping cpu!\n");
		kill_guest_dump(cpu, "failed mapping cpu");
		return;
	}

	/* Make sure the guest has valid flags */
	regs->rflags &= LGUEST_FLAGS_MASK;
	regs->rflags |= LGUEST_FLAGS_SET;

	/*
	 * Set the syscall to jump to guest syscall.
	 * (see setup in init() below)
	 */
	lguest_set_syscall_guest(cpuid);

	/* save fs here */
	asm volatile ("movq %%fs, %0" : "=r"(old_fs));
	if (!old_fs)
		rdmsrl(MSR_FS_BASE, old_fsbase);
	if (regs->fs != old_fs)
		asm volatile ("pushq %0; popq %%fs" :: "r"(0UL));

	/*
	 * loading the FS segment register is very tricky.
	 * So we keep track of the actual descriptor and
	 * load it into the FS base instead.  If the FS reg
	 * is zero, we update the FS base with the stored base.
	 */
	if (regs->fs) {
		asm volatile ("movl %0, %%fs" :: "r"(FS_TLS_SEL));
		wrmsr(MSR_FS_BASE, cpu->lg_cpu_data->guest_fs_desc_a,
				   cpu->lg_cpu_data->guest_fs_desc_d);
	} else if ((cpu->lg_cpu_data->guest_fs_a) ||
		   (cpu->lg_cpu_data->guest_fs_d))
		wrmsr(MSR_FS_BASE, cpu->lg_cpu_data->guest_fs_a,
				   cpu->lg_cpu_data->guest_fs_d);

	/* stats */
	lguest_stat_start_time(cpu);

	asm volatile ("mov %%rsp, %%rax; pushq %2; pushq %%rax; pushfq; pushq %3; call *%6;"
		      : "=D"(foo), "=a"(bar)
		      : "i" (__KERNEL_DS), "i" (__KERNEL_CS), "0" (cpu->cpu),
			"1"(get_idt_table()),
			"r" (sw_guest)
		      : "memory", "cc");

    printk("*** Back in host ***\n");
	/* stats */
	lguest_stat_end_time(cpu);

	/* restore fsbase if needed */
	if (old_fs)
		asm volatile ("pushq %0; popq %%fs" :: "r"(old_fs));
	else if (old_fsbase)
		wrmsrl(MSR_FS_BASE, old_fsbase);

	/*
	 * Set the syscall to jump to host syscall.
	 */
	lguest_set_syscall_host(cpuid);

	if (start && lguest_data_test_bit(TIME, cpu->lg_cpu_data)) {
		end = sched_clock();
		printk("to and from guest took %lld cycles!\n", end - start);
		lguest_data_clear_bit(TIME, cpu->lg_cpu_data);
		start = 0;
	}
}

void lguest_arch_run_guest(struct lg_cpu *cpu)
{
    struct lguest_regs *regs = cpu->regs;

    cpu->host_gdt_ptr = (unsigned long) get_cpu_gdt_table(get_cpu());

    /* Even if *we* don't want FPU trap, guest might... */
    if (cpu->ts && user_has_fpu())
        stts();

    run_guest_once(cpu);

    if(cpu->ts && user_has_fpu())
        clts();

    /*
     * If the Guest page faulted, then the cr2 register will tell us the
     * bad virtual address.  We have to grab this now, because once we
     * re-enable interrupts an interrupt could fault and thus overwrite
     * cr2, or we could even move off to a different CPU.
     */
    if (regs->trapnum == 14) {
        cpu->arch.last_pagefault = read_cr2();
        //SAVE_CR2(cr2);
    }
    /*
     * Similarly, if we took a trap because the Guest used the FPU,
     * we have to restore the FPU it expects to see.
     * math_state_restore() may sleep and we may even move off to
     * a different CPU. So all the critical stuff should be done
     * before this.
     */
    else if (regs->trapnum == 7)
        math_state_restore();
}


extern long end_hyper_text;
extern long start_hyper_text;

/* Called by all CPUS */
static void update_star(void *unused)
{
	unsigned long rax;
	int cpu = smp_processor_id();

	/* Make the syscalls use the HV segments */
	rdmsrl(MSR_STAR, rax);
	rax &= ~0xffff;
	rax |= __LGUEST_HV_CS;
	wrmsrl(MSR_STAR, rax);

	/*
	 * Each CPU will point to a unique code path,
	 * that, for host, will do a swapgs and then
	 * jump to the syscall for the host (after the swapgs).
	 * On switch to guest, we modify this to jump to
	 * the guest syscall handler.
	 *
	 * BIG ASSUMPTION!! We assume that the kernel would
	 * never need to change the LSTAR reg. So we better not
	 * have another lguest module loaded ;-)
	 */

	/* save the old LSTAR for when we remove this module */
	rdmsrl(MSR_LSTAR, rax);
	__get_cpu_var(host_old_lstar) = rax;

	/*
	 * since the guest jump is relative, we
	 * initialized it already, so we can just grab
	 * what's there for later use.
	 */
	rax = lguest_get_syscall(cpu);
	memcpy(per_cpu(guest_jmp_to_syscall, cpu), (void*)rax, LGUEST_SYSCALL_BYTES);

	/* Now we need to make that code jump to the host syscall */
	lguest_set_syscall_host(cpu);

	/* OK, we now use our syscall handler */
	wrmsrl(MSR_LSTAR, rax);

	/* XXX TODO: handle hotplug CPUS */
}

/* Called by all CPUS */
static void reset_star(void *unused)
{
	unsigned long rax, rdx;
	unsigned long lstar = __get_cpu_var(host_old_lstar);

	/* use kernel CS again */
	rdmsr(MSR_STAR, rax, rdx);
	rdx &= ~0xffff;
	rdx |= __KERNEL_CS;
	wrmsr(MSR_STAR, rax, rdx);

	if (!lstar)
		return;

	/* put back the original LSTAR */
	rax = lstar;
	rdx = lstar >> 32;
	wrmsr(MSR_LSTAR, rax, rdx);
}

static int map_pte_fn(pte_t *pte, struct page *pmd_page,
		      unsigned long addr, void *data)
{
	unsigned long *pages = (unsigned long *)data;

	printk("loading %lx at %p for addr %lx\n", *pages, pte, addr);

	set_pte_at(&init_mm, addr, pte, __pte(*pages));
	*pages += PAGE_SIZE;
	return 0;
}

/*
 * map_mod_pte_fn - maps a module text section to a given
 *  location. This needs to be more careful than the map_pte_fn
 *  since modules are allocated as virtual memory, and not
 *  1 to 1 with physical. So the pages to map that is passed in
 *  are of the virtual address and not the physical address.
 *  This function needs to figure out each pages physical
 *  address to map.
 */
static int map_mod_pte_fn(pte_t *pte, struct page *pmd_page,
			  unsigned long addr, void *data)
{
	unsigned long *virt_pages = (unsigned long *)data;
	unsigned long prot = *virt_pages & (PAGE_SIZE-1);
	unsigned long pages;

	pages = lguest_get_actual_phys((void*)*virt_pages, NULL);
	printk("mod loading %lx at %p for addr %lx\n", pages | prot, pte, addr);
	
    set_pte_at(&init_mm, addr, pte, __pte(pages | prot));

	*virt_pages += PAGE_SIZE;

	return 0;
}

static unsigned long __init lguest_alloc_vm(void)
{
	unsigned long addr;

	/*
	 * alloc_vm_area unfortunately does not guarantee
	 * that we have an aligned 2M area. So we allocate
	 * 4 megs of VM space (heck we have at least 48 bits of VM
	 * area, I'm sure no one will miss 4 megs).
	 */
	lguest_vm_area = alloc_vm_area(4<<20, NULL);
	if (!lguest_vm_area)
		return -ENOMEM;

	/* Now get a contiguous 2M aligned virtual memory area */
	addr = (unsigned long)lguest_vm_area->addr;
	addr = (addr + ((2 << 20) - 1)) & ~((2 << 20) - 1);

	return addr;
}

void lguest_free_hv(void)
{
	if (lguest_vm_area)
		free_vm_area(lguest_vm_area);
	lguest_vm_area = NULL;
}

int init(void)
{
	unsigned long pages;
	unsigned long hvaddr;
	int order;
	int ret;
	int i;

	printk("start_hyper_text=%p\n",&start_hyper_text);
	printk("end_hyper_text=%p\n",&end_hyper_text);
	printk("default_idt_entries=%p\n",&_lguest_default_idt_entries);
	printk("sizeof(vcpu)=%ld\n",sizeof(struct lg_cpu));

	ret = paravirt_enabled();
	if (ret < 0)
		return -EPERM;

    ret = lguest_device_init();
    if(ret < 0){
        return ret;
    }

	/*
	 * The hypervisor pages are mapped in the HV VM area.
	 * The hypervisor text is mapped in the same location as the
	 * host and the guest.  But the vcpu data structures are not
	 * mapped in the HV VM for the host, but is for the guest.
	 * This is because each VCPU is mapped into the same location
	 * for the guest.
	 *
	 * The mapping looks like this:
	 *
	 *     +------------------+
	 *     |                  |
	 *     |                  |
	 *     |                  |
	 *     +------------------+
	 *     |                  |
	 *     | VCPU Scratch Pad |
	 *     |  (unique to CPU) |
	 *     |                  |
	 *     +------------------+
	 *     |                  |
	 *     |    VCPU Data     |
	 *     |  (unique to CPU) |
	 *     |                  |
	 *     +------------------+
	 *     |                  |
	 *     |    HV Text       |
	 *     |                  |
	 *     +------------------+
	 *     |                  |
	 *
	 */

	/* Figure out all the pages that are needed */
	pages = (unsigned long)&end_hyper_text -
		(unsigned long)&start_hyper_text;
	pages = (pages + (PAGE_SIZE - 1)) / PAGE_SIZE;
	lguest_hv_pages = pages;

	pages = (sizeof(struct lg_cpu)+(PAGE_SIZE-1))/PAGE_SIZE;
	for (order = 0; (1<<order) < pages; order++)
		;
	lg_cpu_order = order;
	lg_cpu_pages = pages;

	pages = (sizeof(struct lg_cpu_data)+(PAGE_SIZE-1))/PAGE_SIZE;
	for (order = 0; (1<<order) < pages; order++)
		;
	lg_cpu_data_order = order;
	lg_cpu_data_pages = pages;

	pages = (sizeof(struct lguest_regs)+(PAGE_SIZE-1))/PAGE_SIZE;
	for (order = 0; (1<<order) < pages; order++)
		;
	lg_cpu_regs_order = order;
	lg_cpu_regs_pages = pages;

	/* get the total pages */
	pages = lguest_hv_pages + lg_cpu_pages + lg_cpu_data_pages + lg_cpu_regs_pages;

	/*
	 * We need to allocate a 2M range (aligned by 2M).
	 * This is because the HV Text needs to be at the start of the
	 * 2M boundery. 
	 */
	hvaddr = lguest_alloc_vm();
	printk("hv text =\t\t%lx\n",hvaddr);
	if (hvaddr == -ENOMEM)
		goto device_remove;

	/* Mark the range that we don't want the guest to touch */
	lguest_hv_start = hvaddr;
	lguest_hv_size = (2<<20);

	/* Save the address for later use */
	lguest_hv_addr = hvaddr;

	/*
	 * Now map the Text portion to the memory. Since the text portion
	 * may be loaded via a module, we can't use a simple __pa.
	 * The map_mod_pte_fn will handle this for us.
	 * We still need to add the protection we want though.
	 */
	pages = (unsigned long)&start_hyper_text | __PAGE_KERNEL_EXEC;

	ret = apply_to_page_range(&init_mm, hvaddr,
				  PAGE_SIZE * lguest_hv_pages,
				  map_mod_pte_fn, &pages);
	if (ret < 0)
		goto out;

	/*
	 * Make sure that it really did map.
	 */
	{
		long dummy;

		asm volatile (
			"	xorl %0,%0\n"
			"1:\n"
#if 0
//This is a huge TODO - everytime I access %2
//I get NULL pointer
			"1:	movq 0(%2),%1\n"
#endif
			"2:\n"
			".section .fixup,\"ax\"\n"
			"3:	movl $(-"__stringify(ENOMEM)"),%0\n"
			"	jmp 2b\n"
			".previous\n"
			".section __ex_table,\"a\"\n"
			"	.align 8\n"
			"	.quad 1b,3b\n"
			".previous"
			: "=r"(ret), "=r"(dummy)
			: "r"(lguest_hv_addr));

		if (ret) {
			printk("Can't read HV text mappings\n");
			goto out;
		}
	}

	/*
	 * Calculate the offset between the original mapped text
	 * and the new mapping in the hvaddr space.
	 */
	lguest_hv_offset = hvaddr - (unsigned long)&start_hyper_text;

	/* Now get the locations to map the */
	lg_cpu_addr = hvaddr + (PAGE_SIZE * lguest_hv_pages);
	printk("hv vcpu data =\t\t%lx\n", lg_cpu_addr);

	/*
	 * Now map a zero page after the hypervisor. This is
	 * to let the NMI know, incase it happens to go off
	 * when switching to guest but before we switched cr3s
	 * that we are still in the host cr3. That is
	 * the scratch pad of the vcpu struct will be NULL.
	 */
	pages = (page_to_pfn(ZERO_PAGE(0)) << PAGE_SHIFT) | __PAGE_KERNEL_RO;
	ret = apply_to_page_range(&init_mm, lg_cpu_addr,
				  PAGE_SIZE, map_pte_fn, &pages);
	if (ret < 0)
		goto out;

	lg_cpu_data_addr = lg_cpu_addr + (PAGE_SIZE * lg_cpu_pages);
	printk("hv vcpu guest data =\t%lx\n", lg_cpu_data_addr);

	lg_cpu_regs_addr = lg_cpu_data_addr + (PAGE_SIZE * lg_cpu_data_pages);
	printk("hv vcpu regs data =\t%lx\n", lg_cpu_regs_addr);
	/*
	 * God how I hate the NMI!
	 * In the switch code, there's a race where we set up the
	 * NMI stack to point to the vcpu RW section, but before
	 * we switch the cr3's. (I'd love to switch CR3s first but
	 * but then we need a writable GDT, because the loading of
	 * the TSS sets that stupid "busy" bit in the TSS descriptor).
	 *
	 * So we map in a empty pages at the location of the RW data.
	 * If two NMIs go off at the same time on two different CPUs
	 * they will overwrite each other's irq stack info.
	 * we don't care, since the registers that are saved in this
	 * instance, will be pretty much the same. The point of this
	 * race, knows that this can happen and it will not trust
	 * those regs at that time (this includes the RSP).
	 */
	lguest_nmi_playground = __get_free_pages(lg_cpu_data_pages, GFP_KERNEL);
	pages = lguest_nmi_playground | __PAGE_KERNEL;
	ret = apply_to_page_range(&init_mm, lg_cpu_data_addr,
				  lg_cpu_data_pages << PAGE_SHIFT,
				  map_pte_fn, &pages);
	if (ret < 0)
		goto out;

	lguest_io_init();
	INIT_LIST_HEAD(&lguests);

    /* Setup LGUEST segments on all cpus */
    for_each_possible_cpu(i) {
        struct desc_struct *gdt_table;

        gdt_table = get_cpu_gdt_table(i);
        if (!gdt_table)
            continue;

        gdt_table[GDT_ENTRY_LGUEST_HV_CS] = gdt_table[gdt_index(__KERNEL_CS)];
        gdt_table[GDT_ENTRY_LGUEST_HV_DS] = gdt_table[gdt_index(__KERNEL_DS)];
    }

	/*
	 * System call magic!!! To keep from updating the LSTAR reg
	 * (thats the MSR register that tells the CPU where to go on
	 * system calls) we point the LSTAR to our own code.
	 * Since the guest will want to jump to itself on system calls
	 * we need to have a way to switch where the system call goes.
	 * So we set up a per CPU area of code (cached aligned) that
	 * will do a swapgs, and jump to either the host or the
	 * HV syscall handler.  When we are about to switch to guest
	 * we update this per CPU code to jump to the guest syscall HV handler,
	 * and when we come back to host, we jump to the host syscall
	 * handler.
	 * All this, so we don't need to mess with the LSTAR MSR every
	 * time we switch to and from host.
	 */

	/* The switcher code already set up what we needed. Copy that */
	memcpy(host_jmp_to_syscall, &_lguest_syscall_host, LGUEST_SYSCALL_BYTES);

	/* we need a ljmp *location, so we set a variable to use for that */
	lguest_host_system_call = (unsigned long)&system_call_after_swapgs;

	/* Now update the LSTAR register on all CPUS */
	update_star(NULL);
	smp_call_function(update_star, NULL, 1);

	lguest_stat_init();

	return 0;

out:
	lguest_free_hv();
	free_pages(lguest_nmi_playground, lg_cpu_data_pages);
	lguest_nmi_playground = 0;
device_remove:
	lguest_device_remove();
	return ret;
}

void fini(void)
{
	reset_star(NULL);
	smp_call_function(reset_star, NULL, 1);
	lguest_free_hv();
	free_pages(lguest_nmi_playground, lg_cpu_data_pages);
	lguest_stat_cleanup();
	lguest_device_remove();
	lguest_nmi_playground = 0;
	lguest_remove_vm_shrinker();
}

module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
