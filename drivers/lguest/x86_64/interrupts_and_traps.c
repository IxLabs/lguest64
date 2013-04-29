#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <asm/desc.h>
#include <asm/hw_irq.h>
#include <asm/lguest_64.h>
#include "lg.h"

#define LGUEST_INTERRUPT_BIT  (1<<9) /* 512 */
#define LGUEST_IRQ_HOLD_BIT  (1<<10) /* 1024 */

static void push_guest_stack(struct lguest *lg,
					u64 __user **gstack, u64 val)
{
	lgwrite_u64(lg, (u64)--(*gstack), val);
}

void lguest_disable_interrupts(struct lg_cpu *cpu)
{
	cpu->lg_cpu_data->irq_enabled = 0;
}

static int trap_has_err(u64 trap)
{
	switch(trap) {
	case 8:
	case 10 ... 14:
	case 17:
		return 1;
	default:
		return 0;
	}
}

/* force the guest to take a trap */
void lguest_force_trap(struct lg_cpu *cpu)
{
	struct lguest *lg = cpu->lg;
	printk("forcing trap %d\n", lg->trap);
	lguest_dump_vcpu_regs(cpu);
	cpu->regs->trapnum = lg->trap;
	cpu->regs->errcode = lg->err;

	reflect_trap(cpu, lg->trap, trap_has_err(lg->trap));
	lg->trap = 0;
}

int reflect_trap(struct lg_cpu *cpu, int trap_num, int has_err)
{
	struct lguest *lg = cpu->lg;
	struct lguest_regs *regs = cpu->regs;
	u64 __user *gstack;
	u64 rflags, irq_enable;
	u64 offset;
	u64 rsp;
	int user = 0;

	if (!cpu->interrupt[trap_num]) {
		printk("Not yet registered trap handler for %d\n",trap_num);
		return 0;
	}

	/* Save this current stack */
	rsp = regs->rsp;
	/* If we are coming from user space, then change the stack we go to */
	if ((regs->cs & ~1) != __KERNEL_CS) {
		user = 1;
		regs->rsp = cpu->lg_cpu_data->tss_rsp0;
	}

	gstack = (u64 __user *)guest_pa(lg, regs->rsp);
	offset = regs->rsp - (u64)gstack;

	/* We use IF bit in eflags to indicate whether irqs were disabled
	   (it's always 0, since irqs are enabled when guest is running). */
	irq_enable = cpu->lg_cpu_data->irq_enabled;

	rflags = regs->rflags & ~LGUEST_INTERRUPT_BIT;
	rflags |= (irq_enable & LGUEST_INTERRUPT_BIT);

	/* if the previous SS was 0, load that back in the stack */
	if (!cpu->lg_cpu_data->old_ss) {
		WARN_ON(regs->cs != (__KERNEL_CS | 1));
		push_guest_stack(lg, &gstack, 0);
	} else
		push_guest_stack(lg, &gstack, regs->ss);

	/* Push the stack for the user */
	push_guest_stack(lg, &gstack, rsp);
	push_guest_stack(lg, &gstack, rflags);
	if (user)
		push_guest_stack(lg, &gstack, __USER_CS);
	else
		push_guest_stack(lg, &gstack, __KERNEL_CS);
	push_guest_stack(lg, &gstack, regs->rip);

	if (has_err)
		push_guest_stack(lg, &gstack, regs->errcode);

	/* Change the real stack so hypervisor returns to trap handler */
	regs->ss = __KERNEL_DS | GUEST_KERNEL_DPL;
	regs->rsp = (u64)gstack + offset;
	regs->cs = __KERNEL_CS | GUEST_KERNEL_DPL;
	lgdebug_lprint(LGD_IRQ_FL, "trap: %x  rip was at %p\n",
		       trap_num, (void*)regs->rip);
	regs->rip = cpu->interrupt[trap_num];

	/* Disable interrupts for an interrupt gate. */
	if (test_bit(trap_num, cpu->interrupt_disabled))
		cpu->lg_cpu_data->irq_enabled = 0;

	return 1;
}

void maybe_do_interrupt(struct lg_cpu *cpu)
{
	struct lguest *lg = cpu->lg;
	unsigned int irq;
	DECLARE_BITMAP(irqs, LGUEST_IRQS);

	if (!cpu->lg_cpu_data)
		return;

	/* If it has been a reasonable time since last timer interrupt, 
	 * trigger guest's. We need the (u32) for safe comparison */
	if ((lg->timer_on) && ((u32)jiffies > cpu->last_timer))
		set_bit(0, cpu->irqs_pending);

	/* Mask out any interrupts they have blocked. */
	memcpy(irqs , cpu->lg_cpu_data->interrupts,
				sizeof(cpu->lg_cpu_data->interrupts));

	bitmap_andnot(irqs, cpu->irqs_pending, irqs, LGUEST_IRQS);

	irq = find_first_bit(irqs, LGUEST_IRQS);

	if (irq >= LGUEST_IRQS)
		return;

	/* let the guest know there's one pending */
	lguest_data_set_bit(IRQPEND, cpu->lg_cpu_data);

	/* If they're halted, we re-enable interrupts. */
	if (lg->halted) {
		/* Re-enable interrupts. */
		cpu->lg_cpu_data->irq_enabled = LGUEST_INTERRUPT_BIT;
		lg->halted = 0;
	} else {
		lgdebug_lprint(LGD_IRQ_FL, "send irq: %d  rip %llx (%s)\n",
			       irq, cpu->regs->rip,
			       cpu->lg_cpu_data->irq_enabled ? "maybe": "not yet");

		/* Maybe they have interrupts disabled? */
		if (!cpu->lg_cpu_data->irq_enabled)
			return;

		/* Or maybe, they are in a too-critical place to handle it */
		if ((cpu->regs->rip >= lg->noirq_start) &&
		   (cpu->regs->rip <= lg->noirq_end)) {
			return;
		}
		/*
		 * To prevent a race in iret, we don't send an interrupt
		 * if it is about to jump to user land. The guest should
		 * set bit 10 if it is about to do so.
		 * If bit 10 is set, and we are still in the kernel, we
		 * just return, otherwise, clear bit 10 and send the
		 * interrupt.
		 */
		if (cpu->lg_cpu_data->irq_enabled & LGUEST_IRQ_HOLD_BIT) {
			lgdebug_lprint(LGD_IRQ_FL, "   On hold, rip is in %s\n",
				       (cpu->regs->cs & 3) == 1 ?
				       "kernel": "userspace");
			/*
			 * If we are still in the kernel, ignore it.
			 * Otherwise, clear the bit and send.
			 */
			if ((cpu->regs->cs & 3) == 1)
				return;

			cpu->lg_cpu_data->irq_enabled &= ~LGUEST_IRQ_HOLD_BIT;
		}
	}

	lgdebug_lprint(LGD_IRQ_FL, "   Sending irq %d\n", irq);

	if (cpu->interrupt[irq + lg->irq0_vector] != 0) {
		clear_bit(irq, cpu->irqs_pending);
		reflect_trap(cpu, irq + lg->irq0_vector, 0);
	}

	/* guest no longer needs to know */
	lguest_data_clear_bit(IRQPEND, cpu->lg_cpu_data);

	/* Every time we deliver an interrupt, we update the timestamp in the
	 * Guest's lguest_data struct.  It would be better for the Guest if we
	 * did this more often, but it can actually be quite slow: doing it
	 * here is a compromise which means at least it gets updated every
	 * timer interrupt. */
	write_timestamp(lg);

}

void check_bug_kill(struct lg_cpu *cpu)
{
}

static void copy_trap(struct lg_cpu *cpu,
		      unsigned int trap_num,
		      const struct gate_struct64 *desc)
{
	struct lguest *lg = cpu->lg;

	/* Not present? */
	if (!desc->p) {
		cpu->interrupt[trap_num] = 0;
		return;
	}

	switch (desc->type) {
		case 0xE:
			set_bit(trap_num,cpu->interrupt_disabled);
			break;
		case 0xF:
			clear_bit(trap_num,cpu->interrupt_disabled);
			break;
		default:
			kill_guest(lg, "bad IDT type %i for irq %x",
				desc->type,trap_num);
	}

	cpu->interrupt[trap_num] = GATE_ADDRESS((*desc));

	/* Save page faults */
	if (trap_num == 14) {
		cpu->page_fault_handler = cpu->interrupt[trap_num];
		cpu->page_fault_clear_if = !!test_bit(trap_num, cpu->interrupt_disabled);
	}
}

void load_guest_idt_entry(struct lg_cpu *cpu, unsigned int i,
				struct gate_struct64 *d)
{
	switch (i) {
	/* Ignore NMI, doublefault, hypercall, spurious interrupt. */
	case 2:
	case 8:
	case 15:
	case LGUEST_TRAP_ENTRY:
	/* FIXME: We should handle debug and int3 */
	case 1:
	case 3:
		return;
	default:
		copy_trap(cpu, i, d);
	}
}


//TODO - Stefan - Just mockUps
unsigned int interrupt_pending(struct lg_cpu *cpu, bool *more){
    return 0;
}

void try_deliver_interrupt(struct lg_cpu *cpu, unsigned int irq, bool more){
}

/* And this is the routine when we want to set an interrupt for the Guest. */
void set_interrupt(struct lg_cpu *cpu, unsigned int irq)
{
	/*
	 * Next time the Guest runs, the core code will see if it can deliver
	 * this interrupt.
	 */
	set_bit(irq, cpu->irqs_pending);

	/*
	 * Make sure it sees it; it might be asleep (eg. halted), or running
	 * the Guest right now, in which case kick_process() will knock it out.
	 */
	if (!wake_up_process(cpu->tsk))
		kick_process(cpu->tsk);
}

/* This is the function called when the Guest's timer expires. */
static enum hrtimer_restart clockdev_fn(struct hrtimer *timer)
{
	struct lg_cpu *cpu = container_of(timer, struct lg_cpu, hrt);

	/* Remember the first interrupt is the timer interrupt. */
	set_interrupt(cpu, 0);
	return HRTIMER_NORESTART;
}

/* This sets up the timer for this Guest. */
void init_clockdev(struct lg_cpu *cpu)
{
	hrtimer_init(&cpu->hrt, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	cpu->hrt.function = clockdev_fn;
}


int init_interrupts(void){
    return 0;
}

void free_interrupts(void){
}
