/*P:400
 * This contains run_guest() which actually calls into the Host<->Guest
 * Switcher and analyzes the return, such as determining if the Guest wants the
 * Host to do something.  This file also contains useful helper routines.
:*/
#include <linux/module.h>
#include <linux/stringify.h>
#include <linux/stddef.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/cpu.h>
#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <asm/paravirt.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/poll.h>
#include <asm/asm-offsets.h>
#include "lg.h"


/* This One Big lock protects all inter-guest data structures. */
DEFINE_MUTEX(lguest_lock);

/*H:032
 * Dealing With Guest Memory.
 *
 * Before we go too much further into the Host, we need to grok the routines
 * we use to deal with Guest memory.
 *
 * When the Guest gives us (what it thinks is) a physical address, we can use
 * the normal copy_from_user() & copy_to_user() on the corresponding place in
 * the memory region allocated by the Launcher.
 *
 * But we can't trust the Guest: it might be trying to access the Launcher
 * code.  We have to check that the range is below the pfn_limit the Launcher
 * gave us.  We have to make sure that addr + len doesn't give us a false
 * positive by overflowing, too.
 */
bool lguest_address_ok(const struct lguest *lg,
		       unsigned long addr, unsigned long len)
{
	return (addr+len) / PAGE_SIZE < lg->pfn_limit && (addr+len >= addr);
}

/*
 * This routine copies memory from the Guest.  Here we can see how useful the
 * kill_lguest() routine we met in the Launcher can be: we return a random
 * value (all zeroes) instead of needing to return an error.
 */
void __lgread(struct lg_cpu *cpu, void *b, unsigned long addr, unsigned bytes)
{
	if (!lguest_address_ok(cpu->lg, addr, bytes)
	    || copy_from_user(b, cpu->lg->mem_base + addr, bytes) != 0) {
		/* copy_from_user should do this, but as we rely on it... */
		memset(b, 0, bytes);
		kill_guest(cpu->lg, "bad read address %#lx len %u", addr, bytes);
	}
}

/* This is the write (copy into Guest) version. */
void __lgwrite(struct lg_cpu *cpu, unsigned long addr, const void *b,
	       unsigned bytes)
{
	if (!lguest_address_ok(cpu->lg, addr, bytes)
	    || copy_to_user(cpu->lg->mem_base + addr, b, bytes) != 0)
		kill_guest(cpu->lg, "bad write address %#lx len %u", addr, bytes);
}
/*:*/

/*H:030
 * Let's jump straight to the the main loop which runs the Guest.
 * Remember, this is called by the Launcher reading /dev/lguest, and we keep
 * going around and around until something interesting happens.
 */
int run_guest(struct lg_cpu *cpu, unsigned long __user *user)
{
	/* We stop running once the Guest is dead. */
	while (!cpu->lg->dead) {
		unsigned int irq;
		bool more;

		/* First we run any hypercalls the Guest wants done. */
		if (cpu->hcall)
			do_hypercalls(cpu);

		/*
		 * It's possible the Guest did a NOTIFY hypercall to the
		 * Launcher.
		 */
		if (cpu->pending_notify) {
			/*
			 * Does it just needs to write to a registered
			 * eventfd (ie. the appropriate virtqueue thread)?
			 */
			if (!send_notify_to_eventfd(cpu)) {
				/* OK, we tell the main Launcher. */
				if (put_user(cpu->pending_notify, user))
					return -EFAULT;
				return sizeof(cpu->pending_notify);
			}
		}

		/*
		 * All long-lived kernel loops need to check with this horrible
		 * thing called the freezer.  If the Host is trying to suspend,
		 * it stops us.
		 */
		try_to_freeze();

		/* Check for signals */
		if (signal_pending(current))
			return -ERESTARTSYS;

		/*
		 * Check if there are any interrupts which can be delivered now:
		 * if so, this sets up the hander to be executed when we next
		 * run the Guest.
		 */
		irq = interrupt_pending(cpu, &more);
		if (irq < LGUEST_IRQS)
			try_deliver_interrupt(cpu, irq, more);

		/*
		 * Just make absolutely sure the Guest is still alive.  One of
		 * those hypercalls could have been fatal, for example.
		 */
		if (cpu->lg->dead)
			break;

		/*
		 * If the Guest asked to be stopped, we sleep.  The Guest's
		 * clock timer will wake us.
		 */
		if (cpu->halted) {
			set_current_state(TASK_INTERRUPTIBLE);
			/*
			 * Just before we sleep, make sure no interrupt snuck in
			 * which we should be doing.
			 */
			if (interrupt_pending(cpu, &more) < LGUEST_IRQS)
				set_current_state(TASK_RUNNING);
			else
				schedule();
			continue;
		}

		/*
		 * OK, now we're ready to jump into the Guest.  First we put up
		 * the "Do Not Disturb" sign:
		 */
		local_irq_disable();

		/* Actually run the Guest until something happens. */
		lguest_arch_run_guest(cpu);

		/* Now we're ready to be interrupted or moved to other CPUs */
		local_irq_enable();

		/* Now we deal with whatever happened to the Guest. */
		lguest_arch_handle_trap(cpu);
	}

	/* Special case: Guest is 'dead' but wants a reboot. */
	if (cpu->lg->dead == ERR_PTR(-ERESTART))
		return -ERESTART;

	/* The Guest is dead => "No such file or directory" */
	return -ENOENT;
}

