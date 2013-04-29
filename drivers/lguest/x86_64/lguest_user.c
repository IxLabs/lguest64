/* Userspace control of the guest, via /dev/lguest. */
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/lguest_launcher.h>
#include <linux/slab.h>
#include <asm/lguest_64.h>
#include "lg.h"

static int next_guest_id;

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

	cpu->tss.rsp0 = (unsigned long)(&cpu->regs->size);

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
