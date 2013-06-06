/*P:200 This contains all the /dev/lguest code, whereby the userspace
 * launcher controls and communicates with the Guest.  For example,
 * the first write will tell us the Guest's memory layout and entry
 * point.  A read will run the Guest until something happens, such as
 * a signal or the Guest doing a NOTIFY out to the Launcher.  There is
 * also a way for the Launcher to attach eventfds to particular NOTIFY
 * values instead of returning from the read() call.
:*/
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/export.h>
#include "lg.h"


#ifdef CONFIG_SMP
struct lg_cpu *lguest_get_cpu(struct lguest *lg,
				    unsigned long __user *arg)
{
	unsigned long vcpu_num;

	if (get_user(vcpu_num, arg))
		return NULL;

	if (vcpu_num >= atomic_read(&lg->nr_cpus))
		return NULL;

	return &lg->cpus[vcpu_num];
}
#endif

/*L:056
 * Before we move on, let's jump ahead and look at what the kernel does when
 * it needs to look up the eventfds.  That will complete our picture of how we
 * use RCU.
 *
 * The notification value is in cpu->pending_notify: we return true if it went
 * to an eventfd.
 */
bool send_notify_to_eventfd(struct lg_cpu *cpu)
{
	unsigned int i;
	struct lg_eventfd_map *map;

	/*
	 * This "rcu_read_lock()" helps track when someone is still looking at
	 * the (RCU-using) eventfds array.  It's not actually a lock at all;
	 * indeed it's a noop in many configurations.  (You didn't expect me to
	 * explain all the RCU secrets here, did you?)
	 */
	rcu_read_lock();
	/*
	 * rcu_dereference is the counter-side of rcu_assign_pointer(); it
	 * makes sure we don't access the memory pointed to by
	 * cpu->lg->eventfds before cpu->lg->eventfds is set.  Sounds crazy,
	 * but Alpha allows this!  Paul McKenney points out that a really
	 * aggressive compiler could have the same effect:
	 *   http://lists.ozlabs.org/pipermail/lguest/2009-July/001560.html
	 *
	 * So play safe, use rcu_dereference to get the rcu-protected pointer:
	 */
	map = rcu_dereference(cpu->lg->eventfds);
	/*
	 * Simple array search: even if they add an eventfd while we do this,
	 * we'll continue to use the old array and just won't see the new one.
	 */
	for (i = 0; i < map->num; i++) {
		if (map->map[i].addr == cpu->pending_notify) {
			eventfd_signal(map->map[i].event, 1);
			cpu->pending_notify = 0;
			break;
		}
	}
	/* We're done with the rcu-protected variable cpu->lg->eventfds. */
	rcu_read_unlock();

	/* If we cleared the notification, it's because we found a match. */
	return cpu->pending_notify == 0;
}

/*L:055
 * One of the more tricksy tricks in the Linux Kernel is a technique called
 * Read Copy Update.  Since one point of lguest is to teach lguest journeyers
 * about kernel coding, I use it here.  (In case you're curious, other purposes
 * include learning about virtualization and instilling a deep appreciation for
 * simplicity and puppies).
 *
 * We keep a simple array which maps LHCALL_NOTIFY values to eventfds, but we
 * add new eventfds without ever blocking readers from accessing the array.
 * The current Launcher only does this during boot, so that never happens.  But
 * Read Copy Update is cool, and adding a lock risks damaging even more puppies
 * than this code does.
 *
 * We allocate a brand new one-larger array, copy the old one and add our new
 * element.  Then we make the lg eventfd pointer point to the new array.
 * That's the easy part: now we need to free the old one, but we need to make
 * sure no slow CPU somewhere is still looking at it.  That's what
 * synchronize_rcu does for us: waits until every CPU has indicated that it has
 * moved on to know it's no longer using the old one.
 *
 * If that's unclear, see http://en.wikipedia.org/wiki/Read-copy-update.
 */
static int add_eventfd(struct lguest *lg, unsigned long addr, int fd)
{
	struct lg_eventfd_map *new, *old = lg->eventfds;

	/*
	 * We don't allow notifications on value 0 anyway (pending_notify of
	 * 0 means "nothing pending").
	 */
	if (!addr)
		return -EINVAL;

	/*
	 * Replace the old array with the new one, carefully: others can
	 * be accessing it at the same time.
	 */
	new = kmalloc(sizeof(*new) + sizeof(new->map[0]) * (old->num + 1),
		      GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	/* First make identical copy. */
	memcpy(new->map, old->map, sizeof(old->map[0]) * old->num);
	new->num = old->num;

	/* Now append new entry. */
	new->map[new->num].addr = addr;
	new->map[new->num].event = eventfd_ctx_fdget(fd);
	if (IS_ERR(new->map[new->num].event)) {
		int err =  PTR_ERR(new->map[new->num].event);
		kfree(new);
		return err;
	}
	new->num++;

	/*
	 * Now put new one in place: rcu_assign_pointer() is a fancy way of
	 * doing "lg->eventfds = new", but it uses memory barriers to make
	 * absolutely sure that the contents of "new" written above is nailed
	 * down before we actually do the assignment.
	 *
	 * We have to think about these kinds of things when we're operating on
	 * live data without locks.
	 */
	rcu_assign_pointer(lg->eventfds, new);

	/*
	 * We're not in a big hurry.  Wait until no one's looking at old
	 * version, then free it.
	 */
	synchronize_rcu();
	kfree(old);

	return 0;
}

/*L:052
 * Receiving notifications from the Guest is usually done by attaching a
 * particular LHCALL_NOTIFY value to an event filedescriptor.  The eventfd will
 * become readable when the Guest does an LHCALL_NOTIFY with that value.
 *
 * This is really convenient for processing each virtqueue in a separate
 * thread.
 */
static int attach_eventfd(struct lguest *lg, const unsigned long __user *input)
{
	unsigned long addr, fd;
	int err;

	if (get_user(addr, input) != 0)
		return -EFAULT;
	input++;
	if (get_user(fd, input) != 0)
		return -EFAULT;

	/*
	 * Just make sure two callers don't add eventfds at once.  We really
	 * only need to lock against callers adding to the same Guest, so using
	 * the Big Lguest Lock is overkill.  But this is setup, not a fast path.
	 */
	mutex_lock(&lguest_lock);
	err = add_eventfd(lg, addr, fd);
	mutex_unlock(&lguest_lock);

	return err;
}

/*L:050
 * Sending an interrupt is done by writing LHREQ_IRQ and an interrupt
 * number to /dev/lguest.
 */
static int user_send_irq(struct lg_cpu *cpu, const unsigned long __user *input)
{
	unsigned long irq;

	if (get_user(irq, input) != 0)
		return -EFAULT;
	if (irq >= LGUEST_IRQS)
		return -EINVAL;

	/*
	 * Next time the Guest runs, the core code will see if it can deliver
	 * this interrupt.
	 */
	set_interrupt(cpu, irq);
	return 0;
}

/*L:040
 * Once our Guest is initialized, the Launcher makes it run by reading
 * from /dev/lguest.
 */
static ssize_t read(struct file *file, char __user *user, size_t size,loff_t*o)
{
	struct lguest *lg = file->private_data;
	struct lg_cpu *cpu;
	unsigned int cpu_id = *o;

	/* You must write LHREQ_INITIALIZE first! */
	if (!lg)
		return -EINVAL;

	/* Watch out for arbitrary vcpu indexes! */
	if (cpu_id >= atomic_read(&lg->nr_cpus))
		return -EINVAL;

	cpu = &lg->cpus[cpu_id];

	/* If you're not the task which owns the Guest, go away. */
	if (current != cpu->tsk)
		return -EPERM;

	/* If the Guest is already dead, we indicate why */
	if (lg->dead) {
		size_t len;

		/* lg->dead either contains an error code, or a string. */
		if (IS_ERR(lg->dead))
			return PTR_ERR(lg->dead);

		/* We can only return as much as the buffer they read with. */
		len = min(size, strlen(lg->dead)+1);
		if (copy_to_user(user, lg->dead, len) != 0)
			return -EFAULT;
		return len;
	}

	/*
	 * If we returned from read() last time because the Guest sent I/O,
	 * clear the flag.
	 */
	if (cpu->pending_notify)
		cpu->pending_notify = 0;

	/* Run the Guest until something interesting happens. */
	return run_guest(cpu, (unsigned long __user *)user);
}

int initialize(struct file*, const unsigned long *);

/*L:010
 * The first operation the Launcher does must be a write.  All writes
 * start with an unsigned long number: for the first write this must be
 * LHREQ_INITIALIZE to set up the Guest.  After that the Launcher can use
 * writes of other values to send interrupts or set up receipt of notifications.
 *
 * Note that we overload the "offset" in the /dev/lguest file to indicate what
 * CPU number we're dealing with.  Currently this is always 0 since we only
 * support uniprocessor Guests, but you can see the beginnings of SMP support
 * here.
 */
static ssize_t write(struct file *file, const char __user *in,
		     size_t size, loff_t *off)
{
	/*
	 * Once the Guest is initialized, we hold the "struct lguest" in the
	 * file private data.
	 */
	struct lguest *lg = file->private_data;
	const unsigned long __user *input = (const unsigned long __user *)in;
	unsigned long req;
	struct lg_cpu *uninitialized_var(cpu);
	unsigned int cpu_id = *off;

	/* The first value tells us what this request is. */
	if (get_user(req, input) != 0)
		return -EFAULT;
	input++;

	/* If you haven't initialized, you must do that first. */
	if (req != LHREQ_INITIALIZE) {
		if (!lg || (cpu_id >= atomic_read(&lg->nr_cpus)))
			return -EINVAL;
		cpu = &lg->cpus[cpu_id];

		/* Once the Guest is dead, you can only read() why it died. */
		if (lg->dead)
			return -ENOENT;
	}

	switch (req) {
	case LHREQ_INITIALIZE:
	    return initialize(file, input);
	case LHREQ_IRQ:
		return user_send_irq(cpu, input);
	case LHREQ_EVENTFD:
		return attach_eventfd(lg, input);
	default:
		return -EINVAL;
	}
}

/*L:060
 * The final piece of interface code is the close() routine.  It reverses
 * everything done in initialize().  This is usually called because the
 * Launcher exited.
 *
 * Note that the close routine returns 0 or a negative error number: it can't
 * really fail, but it can whine.  I blame Sun for this wart, and K&R C for
 * letting them do it.
:*/
static int close(struct inode *inode, struct file *file)
{
	struct lguest *lg = file->private_data;
	unsigned int i;

	/* If we never successfully initialized, there's nothing to clean up */
	if (!lg)
		return 0;

	/*
	 * We need the big lock, to protect from inter-guest I/O and other
	 * Launchers initializing guests.
	 */
	mutex_lock(&lguest_lock);

	/* Free up the shadow page tables for the Guest. */
	free_guest_pagetable(lg);

	for (i = 0; i < atomic_read(&lg->nr_cpus); i++) {
		/* Cancels the hrtimer set via LHCALL_SET_CLOCKEVENT. */
		hrtimer_cancel(&lg->cpus[i].hrt);
		/* We can free up the register page we allocated. */
		free_page(lg->cpus[i].regs_page);
		/*
		 * Now all the memory cleanups are done, it's safe to release
		 * the Launcher's memory management structure.
		 */
		mmput(lg->cpus[i].mm);
	}

	/* Release any eventfds they registered. */
	for (i = 0; i < lg->eventfds->num; i++)
		eventfd_ctx_put(lg->eventfds->map[i].event);
	kfree(lg->eventfds);

	/*
	 * If lg->dead doesn't contain an error code it will be NULL or a
	 * kmalloc()ed string, either of which is ok to hand to kfree().
	 */
	if (!IS_ERR(lg->dead))
		kfree(lg->dead);
	/* Free the memory allocated to the lguest_struct */
	kfree(lg);
	/* Release lock and exit. */
	mutex_unlock(&lguest_lock);

	return 0;
}

/*L:000
 * Welcome to our journey through the Launcher!
 *
 * The Launcher is the Host userspace program which sets up, runs and services
 * the Guest.  In fact, many comments in the Drivers which refer to "the Host"
 * doing things are inaccurate: the Launcher does all the device handling for
 * the Guest, but the Guest can't know that.
 *
 * Just to confuse you: to the Host kernel, the Launcher *is* the Guest and we
 * shall see more of that later.
 *
 * We begin our understanding with the Host kernel interface which the Launcher
 * uses: reading and writing a character device called /dev/lguest.  All the
 * work happens in the read(), write() and close() routines:
 */
static const struct file_operations lguest_fops = {
	.owner	 = THIS_MODULE,
	.release = close,
	.write	 = write,
	.read	 = read,
	.llseek  = default_llseek,
};
/*:*/

/*
 * This is a textbook example of a "misc" character device.  Populate a "struct
 * miscdevice" and register it with misc_register().
 */
static struct miscdevice lguest_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "lguest",
	.fops	= &lguest_fops,
};

int __init lguest_device_init(void)
{
	return misc_register(&lguest_dev);
}

void __exit lguest_device_remove(void)
{
	misc_deregister(&lguest_dev);
}
