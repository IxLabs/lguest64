/* Userspace control of the guest, via /dev/lguest. */
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/lguest_launcher.h>
#include "lg.h"
#include "lguest.h"

static int next_guest_id;

#ifdef CONFIG_SMP
struct lguest_vcpu *lguest_get_vcpu(struct lguest *lg,
				    unsigned long __user *arg)
{
	unsigned long vcpu_num;

	if (get_user(vcpu_num, arg))
		return NULL;

	if (vcpu_num >= atomic_read(&lg->num_vcpus))
		return NULL;

	return lg->vcpus[vcpu_num];
}
#endif

/* + addr */
static long user_get_dma(struct lguest_vcpu *vcpu,
					const unsigned long __user *input)
{
	unsigned long key, udma, irq;
	struct lguest *lg = vcpu->guest;

	if (get_user(key, input) != 0)
		return -EFAULT;

	udma = get_dma_buffer(lg, key, &irq);
	if (!udma)
		return -ENOENT;

	/* We put irq number in udma->used_len. */
	lgwrite_u64(lg, udma + offsetof(struct lguest_dma, used_len), irq);
	return udma;
}

/* + irq */
static int user_send_irq(struct lguest_vcpu *vcpu, 
					const unsigned long __user *input)
{
	u32 irq; /* there are only 32 registered interrupts */

	if (get_user(irq, input) != 0)
		return -EFAULT;
	/* Hack to let the console know where we are */
	if (irq == LGUEST_MAX_DMA) {
		struct lguest *lg = vcpu->guest;
		int cpus = atomic_read(&lg->num_vcpus);
		int i;
		for (i = 0; i < cpus; i++)
			lguest_dump_vcpu_regs(lg->vcpus[i]);
		return 0;
	}
	if (irq > LGUEST_MAX_DMA)
		return -EINVAL;
	set_bit(irq, vcpu->irqs_pending);
	return 0;
}

static int break_guest_out(struct lguest_vcpu *vcpu, const long __user *input)
{
	unsigned long on;

	/* Fetch whether they're turning break on or off.. */
	if (get_user(on, input) != 0)
		return -EFAULT;

	if (on) {
		vcpu->break_out = 1;
		/* Pop it out (may be running on different CPU) */
		wake_up_process(vcpu->tsk);
		/* Wait for them to reset it */
		return wait_event_interruptible(vcpu->break_wq, !vcpu->break_out);
	} else {
		vcpu->break_out = 0;
		wake_up(&vcpu->break_wq);
		return 0;
	}
}


static ssize_t read(struct file *file, char __user *user, size_t size,loff_t*o)
{
	struct lguest_vcpu *vcpu = NULL; 
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
	vcpu = lg->vcpus[vcpu_id];
	if (!vcpu)
		return -EFAULT;

	return run_guest(vcpu, user);
}

struct lguest_vcpu *allocate_vcpu(struct lguest *lg)
{
	struct lguest_vcpu *vcpu;
	int ret;

	/*
	 * The vcpu struct is mapped to the guest as RO.
	 * It is RW while we are using the host cr3.
	 * But we need to keep this separate than other pages.
	 */
	vcpu = (void*)__get_free_pages(GFP_KERNEL, lguest_vcpu_order);
	if (!vcpu)
		return NULL;
	memset(vcpu, 0, (1<<(lguest_vcpu_order+PAGE_SHIFT)));

	/* Set a pointer to where the vcpu struct is when we use the guest cr3 */
	vcpu->vcpu_hv = lguest_vcpu_addr;

	/*
	 * Now we allocate the vcpu RW data. This will be writable by bothe
	 * the host as well as the guest.  It contains only untrusted fields
	 * except it is also used as an interrupt and exception stack. Where
	 * the hardware places the data, and then we can trust it.
	 */
	vcpu->vcpu_data = (void*)__get_free_pages(GFP_KERNEL, lguest_vcpu_data_order);
	if (!vcpu->vcpu_data)
		goto out;
	memset(vcpu->vcpu_data, 0, (1<<(lguest_vcpu_data_order+PAGE_SHIFT)));
	/* The guest can do more than one hypercall, initialize that field. */
	memset(vcpu->vcpu_data->hcall_status, 0xFF,
	       sizeof(vcpu->vcpu_data->hcall_status));

	/* We also want a pointer to the RW data section when we use the guest cr3 */
	vcpu->vcpu_data_hv = lguest_vcpu_data_addr;

	/* Now map all this where it belongs in the guest cr3 */
	ret = lguest_map_guest_vcpu(vcpu);
	if (ret < 0)
		goto out;

	return vcpu;

out:
	free_pages((unsigned long)vcpu->vcpu_data, lguest_vcpu_data_order);
	free_pages((unsigned long)vcpu, lguest_vcpu_order);
	return NULL;
}

void free_vcpu(struct lguest *lg, struct lguest_vcpu *vcpu)
{
	lg->vcpus[vcpu->id] = NULL;
	free_pages((unsigned long)vcpu->vcpu_data, lguest_vcpu_data_order);
	free_pages((unsigned long)vcpu, lguest_vcpu_order);
	lguest_free_vcpu_mappings(vcpu);
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

int vcpu_start(struct lguest *lg, int id,
				unsigned long entry_point,
				void *pgd)
{
	struct lguest_vcpu *vcpu;
	struct desc_struct *gdt_table;
	struct lguest_regs *regs;
	struct ldttss_desc *tss;
	struct lguest_vcpu_data *vcpu_data;
	struct lguest_vcpu *hv_vcpu;
	u64 limit;
	u64 base;
	int i;

	if (!(id < NR_CPUS)) {
		return -EINVAL;
	}
	atomic_add(1, &lg->num_vcpus);
	printk("A new vcpu will be created, with id %d\n",id);
	if (id > LGUEST_NR_CPUS)
		return -EINVAL;

	vcpu = allocate_vcpu(lg);
	if (!vcpu)
		return -ENOMEM;

	lg->vcpus[id] = vcpu;

	vcpu->id = id;
	vcpu->tsk = current;

	printk("vcpu: %p\n", vcpu);

	/*
	 * Have the VCPU point back to itself so we can easily
	 * switch to the host version of the VCPU when switching
	 * back to the host cr3.
	 */
	vcpu->vcpu = vcpu;

	gdt_table = cpu_gdt(get_cpu());
	put_cpu();

	/* Our gdt is basically host's, except for the privilege level */
	for (i = 0; i < GDT_ENTRIES; i++) {
		vcpu->gdt_table[i] = gdt_table[i];

		if (!gdt_table[i].type)
			continue;

		switch (i) {
		/* Keep TSS, and HV, and Host KERNEL segments the same */
		case GDT_ENTRY_TSS:
		/* The TSS will be modified below */
		case GDT_ENTRY_HV_CS:
		case GDT_ENTRY_HV_DS:
			break;
		default:
			if (!vcpu->gdt_table[i].dpl)
				vcpu->gdt_table[i].dpl = GUEST_KERNEL_DPL;
			else
				vcpu->gdt_table[i].dpl = GUEST_USER_DPL;
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

		_lguest_set_gate(&vcpu->idt_table[i], 0xe,
				 _lguest_default_idt_entries[i] +
				 lguest_hv_offset, dpl, ist);
	}

	hv_vcpu = (struct lguest_vcpu*)lguest_vcpu_addr;

	/*
	 * The we have gdt pointers:
	 *   1) points to the host side gdt
	 *   2) points to the HV gdt
	 */
	vcpu->gdt.size = 8 * GDT_ENTRIES - 1;
	vcpu->gdt.address = (unsigned long)&vcpu->gdt_table;
	vcpu->hv_gdt.size = 8 * GDT_ENTRIES - 1;
	vcpu->hv_gdt.address = (unsigned long)&hv_vcpu->gdt_table;

	vcpu->idt.size = 16 * IDT_ENTRIES -1;
	vcpu->idt.address = (unsigned long)&hv_vcpu->idt_table;
	rdmsrl(MSR_LSTAR, vcpu->host_syscall);

	vcpu->guest = lg;

	printk("Creating map with pid %d\n", current->pid);
	lguest_init_vcpu_pagetable(vcpu);

	/* setup the tss */
	tss = (struct ldttss_desc*)&vcpu->gdt_table[GDT_ENTRY_TSS];
	limit = sizeof(struct lguest_tss_struct);
	base = (u64)&hv_vcpu->tss;
	tss->limit0 = (u16)limit;
	tss->base0 = (u16)base;
	tss->base1 = (u8)(base>>16);
	tss->base2 = (u8)(base>>24);
	tss->base3 = (u32)(base>>32);
	tss->type = 0x9;
	tss->g = 0; /* small tss */

	/* Make the vcpu_data point to the HV vcpu_data */
	vcpu_data = (struct lguest_vcpu_data*)lguest_vcpu_data_addr;

	vcpu->tss.rsp0 = (unsigned long)(&vcpu_data->regs.size);

	/* NMI can happen at any time, so give it its own stack */
	vcpu->tss.ist[NMI_STACK-1] = (unsigned long)(&vcpu_data->nmi_stack_end);
	printk("nmi stack at: %llx\n", vcpu->tss.ist[NMI_STACK-1]);

	/* safe double fault */
	vcpu->tss.ist[6-1] = (unsigned long)(&vcpu_data->df_stack_end);
	printk("df stack at: %llx\n", vcpu->tss.ist[6-1]);

	/*
	 * The rsp0 had better be on 16 bytes aligned, or the interrupt
	 * will put the stack at a undesireable location.
	 */
	/* Don't remove this test!!! */
	if (unlikely(vcpu->tss.rsp0 & 0xf)) {
		printk("HV ALIGNMENT BUG! don't put stack here!!\n");
		printk(" tss.rsp0 stack was set to %llx\n",
		       vcpu->tss.rsp0);
		goto out;
	}

	vcpu->tss.io_bitmap_base = 0x68;
	vcpu->tss.io_bitmap[0] = -1UL;
	vcpu->tss.io_bitmap[1] = -1UL;

	regs = &vcpu->vcpu_data->regs;
	memset(regs, 0, sizeof(*regs));
	regs->cr3 = __pa(vcpu->pgd->hcr3);
	regs->rip = entry_point;
	printk("starting at %lx\n", entry_point);
	regs->cs = __KERNEL_CS | GUEST_KERNEL_DPL;
	regs->rflags = 0x202;   /* Interrupts enabled. */
	regs->rsp = 0;
	regs->ss = __KERNEL_DS | GUEST_KERNEL_DPL;

	printk("gdt_table:\n");
	for (i=1; i < 18; i++) {
		if (!vcpu->gdt_table[i].type)
			continue;
		printk("  %d: %lx dpl=%d\n",i,
		       ((unsigned long*)vcpu->gdt_table)[i],
		       vcpu->gdt_table[i].dpl);
	}

	init_waitqueue_head(&vcpu->break_wq);

	return id;
out:
	free_vcpu(lg, vcpu);
	return -EINVAL;
}

extern volatile unsigned long init_rsp;
extern void (*initial_code)(void);

/* There are three main tasks to be acomplished here: First, we need to
 * grab information about kernel symbols needed during the smp bootup process.
 * They are the ones listed above. But everything in this life comes at a
 * cost, and userspace told us that they would not tell us the addresses if
 * we did not tell them the vcpu number. Bad userspace! At least we got two 
 * pieces of information for the cost of one */
static int user_vcpu_add(struct lguest *lg, 
					const unsigned long __user *input)
{
	int err;
	int vcpu_id;

	if (!(lg->start_secondary)) {
		WARN_ON(1);
		return -EINVAL;
	}
		
	if (copy_from_user(&vcpu_id, input, sizeof(int)))
		return -EFAULT;

	err = vcpu_start(lg, vcpu_id, lg->start_secondary, NULL);
	if (err < 0)
		return err;

	lg->vcpus[vcpu_id]->vcpu_data->regs.rsp = lg->init_rsp;
	
	return 0;
}

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

	atomic_set(&lg->num_vcpus , 0);
	err = vcpu_start(lg, 0, args[2], __va(read_cr3()));
	if (err < 0)
		return err;

	file->private_data = lg;

	lguest_stat_add_guest(lg);

	return sizeof(args);
}

static ssize_t write(struct file *file, const char __user *input,
		     size_t size, loff_t *off)
{
	struct lguest_vcpu *vcpu = NULL;
	struct lguest *lg = file->private_data;
	u64 req;
	unsigned int vcpu_id;
	
	vcpu_id = *off;

	if (get_user(req, input) != 0)
		return -EFAULT;
	input += sizeof(req);

	if (req != LHREQ_INITIALIZE) {
		if (!lg)
			return -EINVAL;
		vcpu = lg->vcpus[vcpu_id];
		if (!vcpu && (req != LHREQ_VCPU_ADD))
			return -EFAULT;
	}

	switch (req) {
	case LHREQ_INITIALIZE:
		return initialize_guest(file, 
					(const unsigned long __user *)input);
	case LHREQ_GETDMA:
		return user_get_dma(vcpu, (const unsigned long __user *)input);
	case LHREQ_IRQ:
		return user_send_irq(vcpu, (const unsigned long __user *)input);
	case LHREQ_VCPU_ADD:
		return user_vcpu_add(lg , (const unsigned long __user *)input);
	case LHREQ_BREAK:
		return break_guest_out(vcpu, (const long __user *)input);
	default:
		return -EINVAL;
	}
}

static int close(struct inode *inode, struct file *file)
{
	struct lguest *lg = file->private_data;
	int i;

	if (!lg)
		return -EBADFD;

	for (i=0; i < LGUEST_NR_CPUS; i++)
		if (lg->vcpus[i])
			free_vcpu(lg, lg->vcpus[i]);

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
