#ifndef _LGUEST_H_
#define _LGUEST_H_

#define LGUEST_IRQS (NR_VECTORS - FIRST_EXTERNAL_VECTOR)

#define LGUEST_PGDS_PER_VCPU 8
#define LGUEST_PGDIRS (LGUEST_MAX_VCPUS * LGUEST_PGDS_PER_VCPU)

#define LHCALL_FLUSH_ASYNC	0
#define LHCALL_LGUEST_INIT	1
#define LHCALL_CRASH		2
#define LHCALL_LOAD_GDT		3
#define LHCALL_NEW_PGTABLE	4
#define LHCALL_FLUSH_TLB	5
#define LHCALL_LOAD_IDT_ENTRY	6
#define LHCALL_SET_STACK	7
#define LHCALL_TS		8
#define LHCALL_TIMER_READ	9
#define LHCALL_TIMER_START	10
#define LHCALL_HALT		11
#define LHCALL_BIND_DMA		13
#define LHCALL_SEND_DMA		14
#define LHCALL_FLUSH_TLB_SIG	15
#define LHCALL_SET_PTE		16
#define LHCALL_SET_PMD		17
#define LHCALL_SET_PUD		18
#define LHCALL_SET_PGD		19
#define LHCALL_CLEAR_PTE	20
#define LHCALL_CLEAR_PMD	21
#define LHCALL_CLEAR_PUD	22
#define LHCALL_CLEAR_PGD	23
#define LHCALL_LOAD_TLS		24
#define LHCALL_RDMSR		25
#define LHCALL_WRMSR		26
#define LHCALL_IRET		27
#define LHCALL_SWAPGS		28
#define LHCALL_SYSRET		31
#define LHCALL_RELEASE_PGD	32
#define LHCALL_APIC_WRITE	33
#define LHCALL_APIC_READ	34
#define LHCALL_S2H		35	/* switch to host */
#define LHCALL_UPDATE_GS	36
#define LHCALL_UPDATE_FS	37
#define LHCALL_CPU_IDLE		38
#define LHCALL_NEW_VCPU		39
#define LHCALL_REMOTE_CALL	40	
#define LHCALL_STOP_VCPUS	41	

#define LHCALL_PRINT		60
#define LHCALL_DEBUG_ME		99

#define LGUEST_MAX_HCALLS	100

#define LGUEST_TRAP_ENTRY 0x1F

/* Used with lguest_vcpu_data flags */
 /* generic bit to let guest know there's an irq pending. */
#define LGUEST_VCPU_IRQPEND_FL	(1<<0)
  /* test for HV page faulting */
#define LGUEST_VCPU_PGFAULT_FL	(1<<1)
  /* test for HV fault other than page */
#define LGUEST_VCPU_IRQFAULT_FL	(1<<2)
#define LGUEST_VCPU_ANYFAULT_FL (LGUEST_VCPU_IRQFAULT_FL | LGUEST_VCPU_PGFAULT_FL)
 /* Used to notify guest that a page table entry was updated */
#define LGUEST_VCPU_PGSET_FL	(1<<3)
 /* Used to tell the HV that we are a hypercall */
#define LGUEST_VCPU_HC_FL	(1<<4)
 /* do swapgs on syscall */
#define LGUEST_VCPU_SWAPGS_FL	(1<<5)
 /* debug time me! */
#define LGUEST_VCPU_TIME_FL	(1<<6)

#define lguest_data_set_bit(bit, data)			\
	do { (data)->flags |= LGUEST_VCPU_##bit##_FL ; } while(0)
#define lguest_data_clear_bit(bit, data)		\
	do { (data)->flags &= ~LGUEST_VCPU_##bit##_FL ; } while(0)
#define lguest_data_test_bit(bit, data)			\
	((data)->flags & LGUEST_VCPU_##bit##_FL)

#ifndef __ASSEMBLY__
#include <asm/desc.h>
#include <asm/hw_irq.h>
#include <linux/futex.h>
#include <linux/lguest_launcher.h>

void async_hcall(unsigned long call,
		 unsigned long arg1, unsigned long arg2, unsigned long arg3);


#define LHCALL_RING_SIZE 64
struct hcall_ring
{
	unsigned long rax, rdx, rbx, rcx;
};

/* Fields to pass in to the HV information to read kallsyms */
struct lguest_text_ptr {
	unsigned long next; /* guest pa address of next pointer */
	unsigned long start;
	unsigned long end;
};

/* Fields initialized by the hypervisor at boot: (per guest info) */
struct lguest_data
{
	/* Memory not to try to access */
	unsigned long reserve_mem;
	/* ID of this guest (used by network driver to set ethernet address) */
	u32 guestid;

/* Fields initialized by the guest at boot: */
	/* Instruction range to suppress interrupts even if enabled */
	unsigned long noirq_start, noirq_end;

	unsigned long start_kernel_map;
	unsigned long page_offset;
	unsigned long text; /* pa address of lguest_text_ptr addresses */

	unsigned long startup_routine;
	unsigned long initial_stack;

	/* Wallclock time set by the Host. */
	struct timespec time;

	unsigned long tsc_khz;

	unsigned long irq0_vector;

	/* Address of the VCPU HV guest shared RW data */
	unsigned long vcpu_shared_data;

/* If the kernel has kallsyms, we can use it to do backtraces of a guest */
	unsigned long kallsyms_addresses;
	unsigned long kallsyms_num_syms;
	unsigned long kallsyms_names;
	unsigned long kallsyms_token_table;
	unsigned long kallsyms_token_index;
	unsigned long kallsyms_markers;
};

/* copied from old lguest code. Not sure if it's the best layout for us */
struct lguest_regs
{
	u64 cr3;			/*   0 ( 0x0) */
        /* Manually saved part. */
        u64 rbx, rcx, rdx;		/*   8 ( 0x8) */
        u64 rsi, rdi, rbp;		/*  32 (0x20) */
        u64 r8, r9, r10, r11;		/*  56 (0x38) */
        u64 r12, r13, r14, r15;		/*  88 (0x58) */
        u64 rax;			/* 120 (0x78) */
        u64 fs; /* ds; */		/* 128 (0x80) */
        u64 trapnum, errcode;		/* 136 (0x88) */
        /* Trap pushed part */
        u64 rip;			/* 152 (0x98) */
        u64 cs;				/* 160 (0xa0) */
        u64 rflags;			/* 168 (0xa8) */
        u64 rsp;			/* 176 (0xb0) */
	u64 ss; /* Crappy Segment! */	/* 184 (0xb8) */
	/* size = 192  (0xc0) */
	char size[0];
};

/*
 * The lguest_vcpu_data struct is put into the writable section
 * of the guest. It can write to it whenever it pleases, but that's
 * OK, since the host only uses this to write into too, and doesn't
 * depend on any data from here, that it doesn't write to first.
 *
 * So the guest can't get access to it from another CPU, each CPU
 * has its own unique mapping of this structure. The data here
 * is per CPU specific.
 */
struct lguest_vcpu_data {
	/* Make plenty of buffer on the stack for play */
	char start_buff[64];
	struct lguest_regs dummy_regs; /* in case of second page fault */

	/* Must be 16 bytes aligned at regs+sizeof(regs) */
	struct lguest_regs regs;

	/* Blocked interrupts. */
	DECLARE_BITMAP(interrupts, LGUEST_IRQS);

	/* Async hypercall ring.  0xFF == done, 0 == pending. */
	u8 hcall_status[LHCALL_RING_SIZE];
	struct hcall_ring hcalls[LHCALL_RING_SIZE];

	/*
	 * Store the guest LSTAR here. If the guest wants
	 * to mess with it, so be it. We only use it to
	 * jump back to the guest.
	 */
	unsigned long LSTAR;
	unsigned long SFMASK;

	/* the guest can get it's cr2 from here */
	unsigned long cr2;

	/* 512 == enabled (same as eflags) */
	unsigned long irq_enabled;

	unsigned long tss_rsp0;  /* guests tss rsp0 */
	unsigned long flags;

	/* Test for double faults in guest kenel */
	struct lguest_pgd *last_pgd;
	u64 last_rip;
	u64 last_vaddr;

	/* save guest fs base pointer */
	unsigned long guest_fs_a;
	unsigned long guest_fs_d;

	/* save guest fs desc pointer */
	unsigned long guest_fs_desc_a;
	unsigned long guest_fs_desc_d;

	/* save guest gs base pointer */
	unsigned long guest_gs_a;
	unsigned long guest_gs_d;

	/* used for guest calling swapgs */
	unsigned long guest_gs_shadow_a;
	unsigned long guest_gs_shadow_d;

	/* Saved off SS to load back into stack */
	unsigned long old_ss;

	/* nmi trampoline storage */

	struct lguest_regs nmi_regs;
	unsigned long nmi_gs_a;
	unsigned long nmi_gs_d;
	unsigned long nmi_gs_shadow_a;
	unsigned long nmi_gs_shadow_d;
	struct desc_ptr nmi_gdt;
	u16 nmi_gdt_buff[3];

	/* Hold the vcpu pointer for nmi handling */
	/* written by the NMI, so we trust it!    */
	unsigned long nmi_vcpu;

	/* is this enough? */
	char nmi_stack[4096];
	char nmi_stack_end[0];
	char df_stack[1048];
	char df_stack_end[0];
} __attribute__((packed)) ____cacheline_aligned;

static inline unsigned long
hcall_int(unsigned long call,
      unsigned long arg1, unsigned long arg2, unsigned long arg3)
{
	asm volatile("int $" __stringify(LGUEST_TRAP_ENTRY)
		     : "=a"(call)
		     : "a"(call), "d"(arg1), "b"(arg2), "c"(arg3)
		     : "memory");
	return call;
}

static inline unsigned long
hcall(unsigned long call,
      unsigned long arg1, unsigned long arg2, unsigned long arg3)
{
	long foo;
	unsigned long flags;
	extern struct lguest_vcpu_data *lguest_data_vcpu;

	/* On startup, we don't have the lguest_data initialized yet */
	if (unlikely(!lguest_data_vcpu))
		return hcall_int(call, arg1, arg2, arg3);

	/* Note, using syscall hcall may disable interrupts anyway */
	local_irq_save(flags);
	lguest_data_set_bit(HC, lguest_data_vcpu);
	asm volatile("syscall"
		     : "=a"(call), "=c"(foo)
		     : "a"(call), "d"(arg1), "b"(arg2), "D"(arg3)
		     : "memory");
	local_irq_restore(flags);

	return call;
}

extern struct lguest_data lguest_data;
extern struct lguest_device_desc *lguest_devices; /* Just past max_pfn */
extern struct list_head lguests;

#endif /* ! __ASSEMBLY__ */
#endif
