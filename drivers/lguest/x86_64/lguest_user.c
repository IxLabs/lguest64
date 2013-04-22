/* Userspace control of the guest, via /dev/lguest. */
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/lguest_launcher.h>
#include <linux/slab.h>
#include <asm/lguest_64.h>
#include "lg.h"

static int next_guest_id;

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

/* + irq */
static int user_send_irq(struct lg_cpu *cpu, 
					const unsigned long __user *input)
{
	u32 irq; /* there are only 32 registered interrupts */

	if (get_user(irq, input) != 0)
		return -EFAULT;
    //FIXME
    //Nu cred ca se mai foloseste DMA, dupa cum spunea Rusty
	/* Hack to let the console know where we are */
	/*if (irq == LGUEST_MAX_DMA) {
		struct lguest *lg = cpu->lg;
		int cpus = atomic_read(&lg->nr_cpus);
		int i;
		for (i = 0; i < cpus; i++)
			lguest_dump_vcpu_regs(lg->cpus[i]);
		return 0;
	}
	if (irq > LGUEST_MAX_DMA)
		return -EINVAL;*/
	set_bit(irq, cpu->irqs_pending);
	return 0;
}

static int break_guest_out(struct lg_cpu *cpu, const long __user *input)
{
	unsigned long on;

	/* Fetch whether they're turning break on or off.. */
	if (get_user(on, input) != 0)
		return -EFAULT;

	if (on) {
		cpu->break_out = 1;
		/* Pop it out (may be running on different CPU) */
		wake_up_process(cpu->tsk);
		/* Wait for them to reset it */
		return wait_event_interruptible(cpu->break_wq, !cpu->break_out);
	} else {
		cpu->break_out = 0;
		wake_up(&cpu->break_wq);
		return 0;
	}
}


static ssize_t read(struct file *file, char __user *user, size_t size,loff_t*o)
{
	struct lg_cpu *cpu = NULL; 
	struct lguest *lg = file->private_data;
	unsigned int vcpu_id = *o;

	if (!lg)
		return -EINVAL;

	if (lg->dead) {
		size_t len;

		if (lg->dead == (void *)-1)
			return -ENOMEM;

		len = min(size, strlen(lg->dead)+1);
		if (copy_to_user(user, lg->dead, len) != 0)
			return -EFAULT;
		return len;
	}
    if(vcpu_id >= atomic_read(&lg->nr_cpus))
        return -EINVAL;
	cpu = &lg->cpus[vcpu_id];

	return run_guest(cpu, (unsigned long *)user);
}

struct lg_cpu *allocate_vcpu(struct lguest *lg)
{
	struct lg_cpu *cpu;
	int ret;

	/*
	 * The vcpu struct is mapped to the guest as RO.
	 * It is RW while we are using the host cr3.
	 * But we need to keep this separate than other pages.
	 */
	cpu = (void*)__get_free_pages(GFP_KERNEL, lg_cpu_order);
	if (!cpu)
		return NULL;
	memset(cpu, 0, (1<<(lg_cpu_order+PAGE_SHIFT)));

	/* Set a pointer to where the vcpu struct is when we use the guest cr3 */
	cpu->cpu_hv = lg_cpu_addr;

	/*
	 * Now we allocate the vcpu RW data. This will be writable by bothe
	 * the host as well as the guest.  It contains only untrusted fields
	 * except it is also used as an interrupt and exception stack. Where
	 * the hardware places the data, and then we can trust it.
	 */
	cpu->lg_cpu_data = (void*)__get_free_pages(GFP_KERNEL, lg_cpu_data_order);
	if (!cpu->lg_cpu_data)
		goto out;
	memset(cpu->lg_cpu_data, 0, (1<<(lg_cpu_data_order+PAGE_SHIFT)));
	/* The guest can do more than one hypercall, initialize that field. */
	memset(cpu->lg_cpu_data->hcall_status, 0xFF,
	       sizeof(cpu->lg_cpu_data->hcall_status));

	/* We also want a pointer to the RW data section when we use the guest cr3 */
	cpu->cpu_data_hv = lg_cpu_data_addr;

	/* Now map all this where it belongs in the guest cr3 */
	ret = lguest_map_guest_vcpu(cpu);
	if (ret < 0)
		goto out;

	return cpu;

out:
	free_pages((unsigned long)cpu->lg_cpu_data, lg_cpu_data_order);
	free_pages((unsigned long)cpu, lg_cpu_order);
	return NULL;
}

void free_cpu(struct lguest *lg, struct lg_cpu *cpu)
{
	free_pages((unsigned long)cpu->lg_cpu_data, lg_cpu_data_order);
	free_pages((unsigned long)cpu, lg_cpu_order);
	lguest_free_vcpu_mappings(cpu);
}

#if 0
static void print_tss(struct ldttss_desc *tss)
{
	u64 base;
	u64 limit;
	int i;
	u16 iobp = 0x64;

	base = (tss->base0) + ((u64)tss->base1 << 16) +
		((u64)tss->base2 << 24) + ((u64)tss->base3 << 32);
	limit = (tss->limit0) + ((u64)tss->limit1 << 16);
	if (tss->g)
		limit <<= 12;
	printk("    base: %016llx\n", base);
	printk("   limit: %llx\n", limit);
	printk("    type: %x\n", tss->type);
	printk("     dpl: %d\n", tss->dpl);
	printk("       p: %d\n", tss->p);
	printk("       g: %d\n", tss->g);

	for (i=0; i < limit; i += 4) {
		printk("   %8x: %08x\n", i, *(u32*)(base+i));
		if (i == 0x64) {
			iobp = (u16)((*(u32*)(base+i))>>16);
		}
		if (i >= iobp && *(s32*)(base+i) == -1L)
			break;
	}
}
#endif

int cpu_start(struct lguest *lg, int id,
				unsigned long entry_point,
				void *pgd)
{
	struct lg_cpu *cpu;
	struct desc_struct *gdt_table;
	struct lguest_regs *regs;
	struct desc_struct *tss;
	struct lg_cpu_data *cpu_data;
	struct lg_cpu *hv_vcpu;
	u64 limit;
	u64 base;
	int i;

	if (!(id < NR_CPUS)) {
		return -EINVAL;
	}
	atomic_add(1, &lg->nr_cpus);
	printk("A new vcpu will be created, with id %d\n",id);
	if (id > NR_CPUS)
		return -EINVAL;

	cpu = allocate_vcpu(lg);
	if (!cpu)
		return -ENOMEM;

	memcpy(&lg->cpus[id], &cpu, sizeof(cpu));

	cpu->id = id;
	cpu->tsk = current;

	printk("cpu: %p\n", cpu);

	/*
	 * Have the VCPU point back to itself so we can easily
	 * switch to the host version of the VCPU when switching
	 * back to the host cr3.
	 */
	cpu->cpu = cpu;

	//TODO - Stefan - find a replacement for function in 3.8
    //gdt_table = cpu_gdt(get_cpu());
	put_cpu();

	/* Our gdt is basically host's, except for the privilege level */
	for (i = 0; i < GDT_ENTRIES; i++) {
		cpu->gdt_table[i] = gdt_table[i];

		if (!gdt_table[i].type)
			continue;

		switch (i) {
		/* Keep TSS, and HV, and Host KERNEL segments the same */
		case GDT_ENTRY_TSS:
		/* The TSS will be modified below */
		case GDT_ENTRY_HV_CS:
            break;
		case GDT_ENTRY_HV_DS:
			break;
		default:
			if (!cpu->gdt_table[i].dpl)
				cpu->gdt_table[i].dpl = GUEST_KERNEL_DPL;
			else
				cpu->gdt_table[i].dpl = GUEST_USER_DPL;
		}
	}

	for (i = 0; i < IDT_ENTRIES; i++) {
		unsigned dpl = i == LGUEST_TRAP_ENTRY ? GUEST_KERNEL_DPL : 0;
		/*
		 * NMI gets its own stack
		 * But use the same host IST.
		 */
		int ist = (i == 2) ? NMI_STACK :
			/* temp debug for now */
			(i == 8) ? 6 :   /* Double Fault */
			0;

		_lguest_set_gate(&cpu->idt_table[i], 0xe,
				 _lguest_default_idt_entries[i] +
				 lguest_hv_offset, dpl, ist);
	}

	hv_vcpu = (struct lg_cpu*)lg_cpu_addr;

	/*
	 * The we have gdt pointers:
	 *   1) points to the host side gdt
	 *   2) points to the HV gdt
	 */
	cpu->gdt.size = 8 * GDT_ENTRIES - 1;
	cpu->gdt.address = (unsigned long)&cpu->gdt_table;
	cpu->hv_gdt.size = 8 * GDT_ENTRIES - 1;
	cpu->hv_gdt.address = (unsigned long)&hv_vcpu->gdt_table;

	cpu->idt.size = 16 * IDT_ENTRIES -1;
	cpu->idt.address = (unsigned long)&hv_vcpu->idt_table;
	rdmsrl(MSR_LSTAR, cpu->host_syscall);

	cpu->lg = lg;

	printk("Creating map with pid %d\n", current->pid);
	lguest_init_vcpu_pagetable(cpu);

	/* setup the tss */
	tss = &cpu->gdt_table[GDT_ENTRY_TSS];
	limit = sizeof(struct lguest_tss_struct);
	base = (u64)&hv_vcpu->tss;
	tss->limit0 = (u16)limit;
	tss->base0 = (u16)base;
	tss->base1 = (u8)(base>>16);
	tss->base2 = (u8)(base>>24);
	//TODO - base3 nu exista in desc_struct
    //tss->base3 = (u32)(base>>32);
	tss->type = 0x9;
	tss->g = 0; /* small tss */

	/* Make the cpu_data point to the HV cpu_data */
	cpu_data = (struct lg_cpu_data*)lg_cpu_data_addr;

    //TODO Not sure
	//cpu->tss.rsp0 = (unsigned long)(&cpu->regs.size);
	cpu->tss.rsp0 = (unsigned long)(&cpu->regs.size);

	/* NMI can happen at any time, so give it its own stack */
	cpu->tss.ist[NMI_STACK-1] = (unsigned long)(&cpu_data->nmi_stack_end);
	printk("nmi stack at: %llx\n", cpu->tss.ist[NMI_STACK-1]);

	/* safe double fault */
	cpu->tss.ist[6-1] = (unsigned long)(&cpu_data->df_stack_end);
	printk("df stack at: %llx\n", cpu->tss.ist[6-1]);

	/*
	 * The rsp0 had better be on 16 bytes aligned, or the interrupt
	 * will put the stack at a undesireable location.
	 */
	/* Don't remove this test!!! */
	if (unlikely(cpu->tss.rsp0 & 0xf)) {
		printk("HV ALIGNMENT BUG! don't put stack here!!\n");
		printk(" tss.rsp0 stack was set to %llx\n",
		       cpu->tss.rsp0);
		goto out;
	}

	cpu->tss.io_bitmap_base = 0x68;
	cpu->tss.io_bitmap[0] = -1UL;
	cpu->tss.io_bitmap[1] = -1UL;

	regs = &cpu->regs;
	memset(regs, 0, sizeof(*regs));
	regs->cr3 = __pa(cpu->pgd->hcr3);
	regs->rip = entry_point;
	printk("starting at %lx\n", entry_point);
	regs->cs = __KERNEL_CS | GUEST_KERNEL_DPL;
	regs->rflags = 0x202;   /* Interrupts enabled. */
	regs->rsp = 0;
	regs->ss = __KERNEL_DS | GUEST_KERNEL_DPL;

	printk("gdt_table:\n");
	for (i=1; i < 18; i++) {
		if (!cpu->gdt_table[i].type)
			continue;
		printk("  %d: %lx dpl=%d\n",i,
		       ((unsigned long*)cpu->gdt_table)[i],
		       cpu->gdt_table[i].dpl);
	}

	init_waitqueue_head(&cpu->break_wq);

	return id;
out:
	free_cpu(lg, cpu);
	return -EINVAL;
}

//extern volatile unsigned long init_rsp;
//extern void (*initial_code)(void);

static int initialize_guest(struct file *file, 
					const unsigned long __user *input)
{
	struct lguest *lg;
	int err;
	u64 args[4];
	int i;

	if (file->private_data)
		return -EBUSY;

	if (copy_from_user(args, input, sizeof(args)) != 0)
		return -EFAULT;

	lg = kzalloc(sizeof(*lg), GFP_KERNEL);
	if (!lg)
		return -ENOMEM;

	list_add(&lg->list, &lguests);

	/* FIXME: protect the guest_id counter */
	/* guest ids start at 1 */
	lg->guestid = ++next_guest_id;

	lg->pfn_limit = args[0];
	lg->page_offset = args[3];
	lg->start_kernel_map = args[3];

	mutex_init(&lg->page_lock);

	INIT_LIST_HEAD(&lg->pgd_lru);
	INIT_LIST_HEAD(&lg->pg_lru);

	for (i=0; i < LGUEST_MAP_SIZE; i++) {
		INIT_LIST_HEAD(&lg->g2h[i]);
		INIT_LIST_HEAD(&lg->h2g[i]);
	}
	for (i=0; i < LGUEST_2MMAP_SIZE; i++)
		INIT_LIST_HEAD(&lg->g2h2M[i]);

	err = init_guest_pagetable(lg, args[1]);
	if (err)
		return -ENOMEM; /* what else to return ?? */
#if 0

	lg->state = setup_guest_state(i, lg->pgdirs[lg->pgdidx].pgdir,args[2]);
	if (!lg->state) {
		err = -ENOEXEC;
		goto release_pgtable;
	}
#endif

	atomic_set(&lg->nr_cpus , 0);
	err = cpu_start(lg, 0, args[2], __va(read_cr3()));
	if (err < 0)
		return err;

	file->private_data = lg;

	lguest_stat_add_guest(lg);

	return sizeof(args);
}

static ssize_t write(struct file *file, const char __user *input,
		     size_t size, loff_t *off)
{
	struct lg_cpu *cpu = NULL;
	struct lguest *lg = file->private_data;
	u64 req;
	unsigned int cpu_id;
	
	cpu_id = *off;

	if (get_user(req, input) != 0)
		return -EFAULT;
	input += sizeof(req);

	if (req != LHREQ_INITIALIZE) {
		if (!lg || cpu_id>=atomic_read(&lg->nr_cpus))
			return -EINVAL;
		cpu = &lg->cpus[cpu_id];
	}

	switch (req) {
	case LHREQ_INITIALIZE:
		return initialize_guest(file, 
					(const unsigned long __user *)input);
	case LHREQ_IRQ:
		return user_send_irq(cpu, (const unsigned long __user *)input);
	case LHREQ_BREAK:
		return break_guest_out(cpu, (const long __user *)input);
	default:
		return -EINVAL;
	}
}

static int close(struct inode *inode, struct file *file)
{
	struct lguest *lg = file->private_data;

	if (!lg)
		return -EBADFD;

    //TODO - Cred ca aici as putea face dezalocarea resurselor
    //Vezi regs din lg_cpu

	printk("  HV Mapped Pages:     %lu\n", lg->stat_mappings);
	printk("  Guest Faulted Pages: %lu\n", lg->stat_guest_faults);

	lguest_stat_remove_guest(lg);
	list_del(&lg->list);
	lguest_free_guest_pages(lg);
	kfree(lg);
	return 0;
}

static struct file_operations lguest_fops = {
	.owner	 = THIS_MODULE,
	.release = close,
	.write	 = write,
	.read	 = read,
};
static struct miscdevice lguest_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "lguest",
	.fops	= &lguest_fops,
};

int __init lguest_device_init(void)
{
	return  misc_register(&lguest_dev);
}

void lguest_device_remove(void)
{
	misc_deregister(&lguest_dev);
}
