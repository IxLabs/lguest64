#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/export.h>
#include "lg.h"

/*L:025
 * This actually initializes a CPU.  For the moment, a Guest is only
 * uniprocessor, so "id" is always 0.
 */
static int lg_cpu_start(struct lg_cpu *cpu, unsigned id, unsigned long start_ip)
{
	/* We have a limited number the number of CPUs in the lguest struct. */
	if (id >= ARRAY_SIZE(cpu->lg->cpus))
		return -EINVAL;

	/* Set up this CPU's id, and pointer back to the lguest struct. */
	cpu->id = id;
	cpu->lg = container_of((cpu - id), struct lguest, cpus[0]);
	atomic_inc(&cpu->lg->nr_cpus);

	/* Each CPU has a timer it can set. */
	init_clockdev(cpu);

	/*
	 * We need a complete page for the Guest registers: they are accessible
	 * to the Guest and we can only grant it access to whole pages.
	 */
	cpu->regs_page = get_zeroed_page(GFP_KERNEL);
	if (!cpu->regs_page)
		return -ENOMEM;

	/* We actually put the registers at the bottom of the page. */
	cpu->regs = (void *)cpu->regs_page + PAGE_SIZE - sizeof(*cpu->regs);

	/*
	 * Now we initialize the Guest's registers, handing it the start
	 * address.
	 */
	lguest_arch_setup_regs(cpu, start_ip);

	/*
	 * We keep a pointer to the Launcher task (ie. current task) for when
	 * other Guests want to wake this one (eg. console input).
	 */
	cpu->tsk = current;

	/*
	 * We need to keep a pointer to the Launcher's memory map, because if
	 * the Launcher dies we need to clean it up.  If we don't keep a
	 * reference, it is destroyed before close() is called.
	 */
	cpu->mm = get_task_mm(cpu->tsk);

	/*
	 * We remember which CPU's pages this Guest used last, for optimization
	 * when the same Guest runs on the same CPU twice.
	 */
	cpu->last_pages = NULL;

	/* No error == success. */
	return 0;
}


/*L:020
 * The initialization write supplies 3 pointer sized (32 or 64 bit) values (in
 * addition to the LHREQ_INITIALIZE value).  These are:
 *
 * base: The start of the Guest-physical memory inside the Launcher memory.
 *
 * pfnlimit: The highest (Guest-physical) page number the Guest should be
 * allowed to access.  The Guest memory lives inside the Launcher, so it sets
 * this to ensure the Guest can only reach its own memory.
 *
 * start: The first instruction to execute ("eip" in x86-speak).
 */
static int initialize(struct file *file, const unsigned long __user *input)
{
	/* "struct lguest" contains all we (the Host) know about a Guest. */
	struct lguest *lg;
	int err;
	unsigned long args[3];

	/*
	 * We grab the Big Lguest lock, which protects against multiple
	 * simultaneous initializations.
	 */
	mutex_lock(&lguest_lock);
	/* You can't initialize twice!  Close the device and start again... */
	if (file->private_data) {
		err = -EBUSY;
		goto unlock;
	}

	if (copy_from_user(args, input, sizeof(args)) != 0) {
		err = -EFAULT;
		goto unlock;
	}

	lg = kzalloc(sizeof(*lg), GFP_KERNEL);
	if (!lg) {
		err = -ENOMEM;
		goto unlock;
	}

	lg->eventfds = kmalloc(sizeof(*lg->eventfds), GFP_KERNEL);
	if (!lg->eventfds) {
		err = -ENOMEM;
		goto free_lg;
	}
	lg->eventfds->num = 0;

	/* Populate the easy fields of our "struct lguest" */
	lg->mem_base = (void __user *)args[0];
	lg->pfn_limit = args[1];

	/* This is the first cpu (cpu 0) and it will start booting at args[2] */
	err = lg_cpu_start(&lg->cpus[0], 0, args[2]);
	if (err)
		goto free_eventfds;

	/*
	 * Initialize the Guest's shadow page tables.  This allocates
	 * memory, so can fail.
	 */
	err = init_guest_pagetable(lg);
	if (err)
		goto free_regs;

	/* We keep our "struct lguest" in the file's private_data. */
	file->private_data = lg;

	mutex_unlock(&lguest_lock);

	/* And because this is a write() call, we return the length used. */
	return sizeof(args);

free_regs:
	/* FIXME: This should be in free_vcpu */
	free_page(lg->cpus[0].regs_page);
free_eventfds:
	kfree(lg->eventfds);
free_lg:
	kfree(lg);
unlock:
	mutex_unlock(&lguest_lock);
	return err;
}
