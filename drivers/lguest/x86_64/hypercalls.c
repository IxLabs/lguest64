/*  Actual hypercalls, which allow guests to actually do something.
    Copyright (C) 2007, Glauber de Oliveira Costa <gcosta@redhat.com>
                        Steven Rostedt <srostedt@redhat.com>
                        Red Hat Inc
    Standing on the shoulders of Rusty Russell.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
*/
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/msr.h>
#include <asm/apicdef.h>
#include "lguest.h"
#include "lg.h"

/* FIXME: add this to Kconfig */
#define CONFIG_LGUEST_DEBUG 1

static DEFINE_MUTEX(hcall_print_lock);
#define HCALL_PRINT_SIZ 1024
static char hcall_print_buf[HCALL_PRINT_SIZ];


static unsigned long apic_icr(struct lguest_vcpu *vcpu, 
					unsigned long val, unsigned long cpu)
{
	unsigned int vector;
	unsigned int shortcut;
	cpumask_t receivers;


	/* We ignore the physical vs logical distinction. We have control of 
	 * that, and can make them appear as the same */
	vector = val & APIC_VECTOR_MASK;
	shortcut = val & 0xC0000;

	/* The cpu value is interpreted as a mask in this operation */
	cpus_clear(receivers);	
		
	switch (shortcut) {
	case 0:
		/* We can safely do it here since the APIC mask would not
		 * let more than 256 cpus to be visible anyway */
		receivers.bits[0] = cpu;
		break;
	case 0x40000:
		cpu_clear(vcpu->id, receivers);
		break;
	case 0x80000:
		receivers = cpu_online_map;
		break;
	case 0xC0000:
		receivers = cpu_online_map;
		cpu_clear(vcpu->id, receivers);
		break;
	default:
		kill_guest_dump(vcpu, "Unexpected APIC destination specified\n");
		return -EFAULT;
	}

#if 0		
	for_each_cpu_mask(dest, receivers) {
		/* we now queue the interrupt for the other vcpu */
		rvcpu = vcpu->guest->vcpu_map[dest].vcpu;
		/* Note that this _must_ be the atomic version */
		set_bit(vector - FIRST_EXTERNAL_VECTOR, rvcpu->irqs_pending);
	}
#endif
		
	return 0;
}

/* Return true if DMA to host userspace now pending. */
static int do_hcall(struct lguest_vcpu *vcpu, struct lguest_regs *regs)
{
	struct lguest *lg = vcpu->guest;
	unsigned long val;
	unsigned long ret;
	static int max_mtrr_cnt = 0;
	static int newline = 1;

	switch (regs->rax) {
	case LHCALL_PRINT:
		mutex_lock(&hcall_print_lock);
		ret = strncpy_from_user(hcall_print_buf,
					(const char __user *)regs->rdx,
					HCALL_PRINT_SIZ);
		if (ret < 0) {
			kill_guest_dump(vcpu,
					"bad hcall print pointer (%llx)",
					regs->rdx);
			mutex_unlock(&hcall_print_lock);
			return -EFAULT;
		}
		if (!ret)
			return 0;
		if (newline)
			printk("LGUEST: ");
		printk("%s", hcall_print_buf);
		if (hcall_print_buf[ret-1] == '\n')
			newline = 1;
		else
			newline = 0;
		mutex_unlock(&hcall_print_lock);

		break;
	case LHCALL_FLUSH_ASYNC:
		break;
	case LHCALL_LGUEST_INIT:
		kill_guest_dump(vcpu, "already have lguest_data");
		break;

	case LHCALL_TIMER_READ: {
		u32 now = jiffies;
		mb();
		regs->rax = now - vcpu->last_timer;
		vcpu->last_timer = now;
		break;
	}

       case LHCALL_TIMER_START:
               lg->timer_on = 1;
               if (regs->rdx != HZ) {
                       kill_guest_dump(vcpu, "Bad clock speed %lli",
                        regs->rdx);
                       return -EFAULT;
               }
               vcpu->last_timer = jiffies;
               break;

	case LHCALL_RDMSR:
		switch (regs->rdx) {
		/* MTRR cases. Report native's */
		case MSR_MTRRcap:
			rdmsrl(regs->rdx,val);
			max_mtrr_cnt = 0x200 + ((val & 0xff) << 1);
			break;
		case 0x200 ... 0x3ff:
			if (regs->rdx > max_mtrr_cnt)
				val = 0;
			else
				rdmsrl(regs->rdx, val);
			break;
		case MSR_IA32_MCG_CAP:
		case MSR_IA32_MCG_STATUS:
		case MSR_IA32_MCG_CTL:
		case MSR_IA32_MISC_ENABLE:
			/* Don't support anything, go away */
			val = 0;
			break;
		case MSR_KERNEL_GS_BASE:
			val = (vcpu->vcpu_data->guest_gs_shadow_a & ((1UL << 32)-1)) |
				(vcpu->vcpu_data->guest_gs_shadow_d << 32);
			lgwrite_u64(lg, regs->rbx, val);
			break;
		case MSR_GS_BASE:
			val = (vcpu->vcpu_data->guest_gs_a & ((1UL << 32)-1)) |
				(vcpu->vcpu_data->guest_gs_d << 32);
			lgwrite_u64(lg, regs->rbx, val);
		break;
		case MSR_FS_BASE:
			val = (vcpu->vcpu_data->guest_fs_a & ((1UL << 32)-1)) |
				(vcpu->vcpu_data->guest_fs_d << 32);
			lgwrite_u64(lg, regs->rbx, val);
		break;
		case MSR_EFER:
			val = EFER_SCE | EFER_LME | EFER_LMA | EFER_NX;
			lgwrite_u64(lg, regs->rbx, val);
		break;
		default:
			kill_guest_dump(vcpu, "bad read of msr %llx\n", regs->rdx);
		}
		break;
	case LHCALL_WRMSR:
		kill_guest_dump(vcpu, "bad write to msr %llx\n", regs->rdx);
		break;
	case LHCALL_SET_PMD:
		guest_set_pmd(vcpu, regs->rdx, regs->rbx);
		break;
	case LHCALL_SET_PUD:
		guest_set_pud(vcpu, regs->rdx, regs->rbx);
		break;
	case LHCALL_SET_PGD:
		guest_set_pgd(vcpu, regs->rdx, regs->rbx);
		break;
	case LHCALL_SET_PTE:
		guest_set_pte(vcpu, regs->rdx, regs->rbx);
		break;

	case LHCALL_RELEASE_PGD:
		guest_release_pgd(vcpu, regs->rdx);
		break;

	case LHCALL_FLUSH_TLB_SIG:
		/* Do we really need to do anything ? */
		break;
		guest_flush_tlb_single(vcpu, regs->rdx);
		break;
	case LHCALL_FLUSH_TLB:
		if (regs->rdx)
			guest_pagetable_clear_all(vcpu);
		else
			guest_pagetable_flush_user(vcpu);
		break;

	case LHCALL_NEW_PGTABLE:
		guest_new_pagetable(vcpu, (u64)regs->rdx);
		break;

	case LHCALL_CRASH: {
		char msg[128];
		lgread(lg, msg, regs->rdx, sizeof(msg));
		msg[sizeof(msg)-1] = '\0';
		kill_guest_dump(vcpu, "CRASH: %s", msg);
		break;
	}
	case LHCALL_LOAD_GDT:
		/* i386 does a lot of gdt reloads. We don't.
		 * we may want to support it in the future for more
		 * strange code paths. Not now */
		return -ENOSYS;

	case LHCALL_LOAD_IDT_ENTRY: {
		struct gate_struct g;

		if (regs->rdx > 0xFF) {
			kill_guest_dump(vcpu, "There are just 255 idt entries."
					"What are you trying to do??");
			return -EFAULT;
		}
		lgread(lg, &g, regs->rbx, sizeof(g));
		load_guest_idt_entry(vcpu, regs->rdx, &g);
		break;
	}
	case LHCALL_TS:
		vcpu->ts = regs->rdx;
		break;
	case LHCALL_HALT:
		lg->halted = 1;
		break;
	case LHCALL_BIND_DMA:
		regs->rax = bind_dma(lg, regs->rdx, regs->rbx,
				     regs->rcx >> 8, regs->rcx & 0xFF);
		break;
	case LHCALL_SEND_DMA:
		send_dma(lg, regs->rdx, regs->rbx);
		return 0;

	case LHCALL_LOAD_TLS: {
		/* Theoretically, we could be running in a cpu, filling it for 
		 * another */
		struct lguest_vcpu *t;
		struct desc_struct tls[3];
		int i;
		if (regs->rbx >= LGUEST_NR_CPUS) {
			kill_guest_dump(vcpu, "Illegal CPU number in LOAD TLS");
			return -EFAULT;
		}
#if 0
		t = vcpu->guest->vcpu_map[regs->rbx].vcpu;
#else
		t = vcpu;
#endif
		lgread(vcpu->guest, &tls, regs->rdx, 3*sizeof(struct desc_struct));
		for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++) {
			/*
			 * The GDT is read only for the guest kernel, so when
			 * it loads the fs reg, that action will set the
			 * Access bit in the type field. But since the GDT is read
			 * only, it will page fault the guest. So instead we
			 * set it now.
			 */
			if (tls[i].dpl)
				tls[i].type |= 1;
			t->gdt_table[GDT_ENTRY_TLS_MIN + i] = tls[i];
		}

		/* save the FS descriptor, for loading before switch_to_guest */
		vcpu->vcpu_data->guest_fs_desc_a = 
			DESC_ADDRESS(t->gdt_table[GDT_ENTRY_TLS_MIN+FS_TLS]);

		vcpu->vcpu_data->guest_fs_desc_d = 
		DESC_ADDRESS(t->gdt_table[GDT_ENTRY_TLS_MIN+FS_TLS]) >> 32;
		break;
	}
	case LHCALL_SYSRET: {
		u64 paddr;
		u64 user_rsp;
		/*
		 * This is tricky, we pushed the original rax and rdx
		 * onto the stack, so we could use them for parameters
		 * to the hcall.  The rbx now holds the stack to
		 * switch to, and we haven't done a swapgs either.
		 * so that must also be done.
		 */

		/* rdx holds the user stack we go to */
		user_rsp = regs->rdx;

		/* get the original rdx */
		paddr = guest_pa(vcpu->guest, regs->rsp);
		regs->rdx = lgread_u64(lg, paddr);
		/* and also the original rax */
		paddr += sizeof(u64);
		regs->rax = lgread_u64(lg, paddr);

		/* put in the user stack */
		regs->rsp = user_rsp;

		/* The guest also wants us to do a swapgs for it */
		lguest_swapgs(vcpu);

		/* sysret uses RCX to return to */
		regs->rip = regs->rcx;

		/* Set the flags for the user space */
		/*   Note: run_guest will make sure rflags is OK */
		regs->rflags = regs->r11;

		/* See if the guest wants interrupts disabled or enabled */
		if (regs->r11 & (1<<9))
			vcpu->vcpu_data->irq_enabled |= (1<<9);
		else
			vcpu->vcpu_data->irq_enabled &= ~(1<<9);

		/* Going back to user land */
		regs->cs = __USER_CS;
		regs->ss = __USER_DS;

		break;
	}
	case LHCALL_SWAPGS:
		lguest_swapgs(vcpu);
		break;

	case LHCALL_APIC_WRITE: 
		break;
	case LHCALL_APIC_READ:
		break;

	case LHCALL_CPU_IDLE:
		/* go back to user land? */
		break;

	case LHCALL_UPDATE_GS:
		/* just switch to host */
	case LHCALL_S2H:
		/* the guest simply wanted to switch to host :-) */
		break;

	case LHCALL_NEW_VCPU: {
		unsigned long cpu;
		/* 
		 * The guest kernel told us that time has come to pop up
		 * a new puppie, aka cpu. We need to return to the launcher,
		 * so it can fire a new thread to run it.
		 */
		cpu = regs->rdx;
		if (!(cpu < NR_CPUS)) {
			printk("Ignoring attempt to create cpu %lx\n",cpu);
			break;
		}
		vcpu->new_vcpu = cpu;
		lg->init_rsp = regs->rbx;
		lg->start_secondary = regs->rdi;
		break;
	}
	case LHCALL_REMOTE_CALL:
	{
		unsigned long vector = regs->rdi - lg->irq0_vector;
		int i;
		if (!regs->rdx) {
			int cpus = atomic_read(&lg->num_vcpus);
			for (i = 0; i < cpus; i++) {
				if (i == vcpu->id)
					continue;
				set_bit(vector, lg->vcpus[i]->irqs_pending);
			}
		}
		else
			set_bit(vector, lg->vcpus[regs->rbx]->irqs_pending);
		break;
	}
	case LHCALL_STOP_VCPUS: {
		int i, cpus;
		/* 
		 * This is usually called when we're shutting down, or when
		 * something got really, really wrong, like a panic. So we
		 * stop everybody, and make sure we're the only puppie in
		 * town
		 */
		cpus = atomic_read(&lg->num_vcpus);
		for (i = 0; i < cpus; i++) {
			if (i == regs->rdx)
				continue;
			lg->vcpus[i]->tsk->state = TASK_INTERRUPTIBLE;
			set_tsk_need_resched(lg->vcpus[i]->tsk);	
		}			 	
		break;	
	}
	case LHCALL_DEBUG_ME:
#ifdef CONFIG_LGUEST_DEBUG
		if ((long)regs->rdx < 0) {
			/* special instructions */
			long cmd = regs->rdx * -1;
			u64 paddr;
			switch (cmd) {
			case 1:
				lguest_dump_vcpu_regs(vcpu);
				/* try to read stack ptr */
				printk("reading stack %llx\n",
				       regs->rbx);
				paddr = lguest_find_guest_paddr(vcpu, regs->rbx);
				if (paddr == (u64)-1) {
					printk(" stack unreadable\n");
					break;
				}
				paddr = lgread_u64(lg, paddr);
				printk("   *stack=%llx\n", paddr);
				break;
			}
			break;
		}
			
		lguest_debug = regs->rdx;
		printk("lguest debug turned %s\n", regs->rdx ? "on" : "off");
		lguest_dump_vcpu_regs(vcpu);
#else
		{
			static int once = 1;
			if (once) {
				once = 0;
				printk("lguest debug is disabled, to use this "
				       "please enable CONFIG_LGUEST_DEBUG\n");
			}
		}
#endif
		break;
	default:
		kill_guest_dump(vcpu, "Bad hypercall %lli\n", regs->rax);
	}
	return 0;
}

/* We always do queued calls before actual hypercall. */
void do_async_hcalls(struct lguest_vcpu *vcpu)
{
	unsigned int i;
	struct lguest *lg = vcpu->guest;
	u8 st[LHCALL_RING_SIZE];

	/* For simplicity, we copy the entire call status array in at once. */
	memcpy(&st, &vcpu->lguest_vcpu_data->hcall_status, sizeof(st));

	/* We process "struct lguest_data"s hcalls[] ring once. */
	for (i = 0; i < ARRAY_SIZE(st); i++) {
		struct lguest_regs regs;
		/* We remember where we were up to from last time.  This makes
		 * sure that the hypercalls are done in the order the Guest
		 * places them in the ring. */
		unsigned int n = vcpu->next_hcall;

		/* 0xFF means there's no call here (yet). */
		if (st[n] == 0xFF)
			break;

		/* OK, we have hypercall.  Increment the "next_hcall" cursor,
		 * and wrap back to 0 if we reach the end. */
		if (++vcpu->next_hcall == LHCALL_RING_SIZE)
			vcpu->next_hcall = 0;

		/* We copy the hypercall arguments into a fake register
		 * structure.  This makes life simple for do_hcall(). */
		regs.rax = vcpu->lguest_vcpu_data->hcalls[n].rax;
		regs.rdx = vcpu->lguest_vcpu_data->hcalls[n].rdx;
		regs.rcx = vcpu->lguest_vcpu_data->hcalls[n].rcx;
		regs.rbx = vcpu->lguest_vcpu_data->hcalls[n].rbx;

		/* Do the hypercall, same as a normal one. */
		do_hcall(vcpu, &regs);

		/* Mark the hypercall done. */
		vcpu->lguest_vcpu_data->hcall_status[i] = 0xFF;

 		/* Stop doing hypercalls if we've just done a DMA to the
		 * Launcher: it needs to service this first. */
		if (lg->dma_is_pending)
			break;
	}

}

static void initialize(struct lguest_vcpu *vcpu)
{
	struct lguest *lg = vcpu->guest;
	struct lguest_regs *regs = &vcpu->vcpu_data->regs;
	int i;
	u32 tsc_speed;

	if (regs->rax != LHCALL_LGUEST_INIT) {
		kill_guest(lg, "hypercall %lli before LGUEST_INIT",
			   regs->rax);
		return;
	}

	if (boot_cpu_has(X86_FEATURE_CONSTANT_TSC) && !check_tsc_unstable())
		tsc_speed = tsc_khz;
	else
		tsc_speed = 0;

	lg->lguest_data = (struct lguest_data __user *)regs->rdx;
	/* We check here so we can simply copy_to_user/from_user */
	if (!lguest_address_ok(lg, (long)lg->lguest_data, 2)) {
		kill_guest(lg, "bad guest page %p", lg->lguest_data);
		return;
	}

	/* update the page_offset info */
	get_user(lg->page_offset, &lg->lguest_data->page_offset);
	get_user(lg->start_kernel_map, &lg->lguest_data->start_kernel_map);

	get_user(lg->noirq_start, &lg->lguest_data->noirq_start);
	get_user(lg->noirq_end, &lg->lguest_data->noirq_end);

	get_user(lg->irq0_vector, &lg->lguest_data->irq0_vector);

	/* We reserve the top pgd entry. */
	put_user(4U*1024*1024, &lg->lguest_data->reserve_mem);
	put_user(lg->guestid, &lg->lguest_data->guestid);
	put_user(tsc_speed, &lg->lguest_data->tsc_khz);

	for (i = 0; i < LHCALL_RING_SIZE -1; i++)
		vcpu->lguest_vcpu_data->hcall_status[i] = 0xFF;

	/* Give the user the address of the guest data */
	put_user(lguest_vcpu_data_addr, &lg->lguest_data->vcpu_shared_data);
	
	write_timestamp(lg);
}

int hypercall(struct lguest_vcpu *vcpu)
{
	struct lguest *lg = vcpu->guest;
	int pending;

	if (!lg->lguest_data) {
		initialize(vcpu);
		return 0;
	}

	do_async_hcalls(vcpu);

	pending = do_hcall(vcpu, &vcpu->vcpu_data->regs);
	return pending;
}

/* This routine supplies the Guest with time: it's used for wallclock time at
 * initial boot and as a rough time source if the TSC isn't available. */
void write_timestamp(struct lguest *lg)
{
	struct timespec now;
	ktime_get_real_ts(&now);
	if (copy_to_user(&lg->lguest_data->time, &now, sizeof(now)))
		kill_guest(lg, "Writting timestamp");
}
