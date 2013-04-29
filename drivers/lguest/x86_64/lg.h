#ifndef _LGUEST_GUEST_H_
#define _LGUEST_GUEST_H_

#include <asm/lguest_hcall.h>
#include <asm/lguest_64.h>
#include <asm/segment.h>

#define GUEST_USER_DPL		3
#define GUEST_KERNEL_DPL	1

#define gdt_index(x) ((x) >> 3)

#define LGUEST_NMI_IST 7

/*
 * These are the rflags we let the guest modify.
 *  AC, ID, OF, DF, SF, ZF, AF, PF, CF
 *  Bits 0,2,4,6,7,10,11,18,21.
 *   0010 0100 0000 1100 1101 0101
 *    2     4    0    C    D    5
 */
#define LGUEST_FLAGS_MASK (0x240cd5)

/*
 * These are the flags that are always set for the guest.
 *   IF set, and bit 1.
 */
#define LGUEST_FLAGS_SET ((1<<9) | (1<<1))

#ifndef __ASSEMBLY__
#include <linux/hrtimer.h>
#include "lguest_pg.h"

/*
 * To simplify the output of stats, we make the hcall and
 * trap array the same size. We use this so that we get
 * a constant at the end.
 */
#define LGUEST_MAX_STAT_SZ				\
	(((LGUEST_MAX_HCALLS+1) >			\
	  (LGUEST_IRQS + FIRST_EXTERNAL_VECTOR)) ?	\
	 (LGUEST_MAX_HCALLS+1) :			\
	 LGUEST_IRQS + FIRST_EXTERNAL_VECTOR)

//TODO poate nu vor fi aceleasi functii
/* ../page_tables.c */
void free_pagetables(void);
int init_pagetables(struct page **switcher_page, unsigned int pages);

/* io.c */
void lguest_io_init(void);


//TODO - Structuri bagate de mine ca sa compileze
//Foarte probabil vor fi scoase sau adaptate
struct lg_eventfd {
    unsigned long addr;
    struct eventfd_ctx *event;
};

struct lg_eventfd_map {
    unsigned int num;
    struct lg_eventfd map[];
};

#define GDT_ENTRY_HV_CS 16
#define GDT_ENTRY_HV_DS 17

//TODO - Am mutat-o din asm/lguest_64.h
/*
 * The lg_cpu_data struct is put into the writable section
 * of the guest. It can write to it whenever it pleases, but that's
 * OK, since the host only uses this to write into too, and doesn't
 * depend on any data from here, that it doesn't write to first.
 *
 * So the guest can't get access to it from another CPU, each CPU
 * has its own unique mapping of this structure. The data here
 * is per CPU specific.
 */
struct lg_cpu_data {
	/* Make plenty of buffer on the stack for play */
	char start_buff[64];
	struct lguest_regs dummy_regs; /* in case of second page fault */

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



struct lguest_tss_struct {
	u32 reserved1;
	u64 rsp0;
	u64 rsp1;
	u64 rsp2;
	u64 reserved2;
	u64 ist[7];
	u32 reserved3;
	u32 reserved4;
	u16 reserved5;
	u16 io_bitmap_base;
	/* we don't let the guest have io privileges (yet) */
	u64 io_bitmap[2];
} __attribute__((packed)) ____cacheline_aligned;

/*
 * The lg_cpu struct is mapped into the guest address space
 * as read only. This stores the information needed to get back to
 * the host, and perhaps any thing else that is unique to a VCPU.
 */
struct lg_cpu {
	unsigned int  id;
	struct lguest *lg;
	struct task_struct *tsk;
	struct mm_struct *mm;

	/* keep vcpu guest data (RW portion) as first element (HV then Host) */
	unsigned long cpu_data_hv; /* pointer to guest data (RW) in HV land */
	struct lg_cpu_data *lg_cpu_data; /* pointer in Host for RW data */

	/* Must be 16 bytes aligned at regs+sizeof(regs) */
	unsigned long regs_page;
	struct lguest_regs *regs;

	struct lguest_pages *last_pages;

	unsigned long cpu_hv; /* pointer to guest vcpu (RO) in HV land */
	struct lg_cpu *cpu; /* pointer to itself */

	unsigned long host_syscall;



	/* If a hypercall was asked for, this points to the arguments. */
	struct hcall_args *hcall; //TODO puse cu japca
	unsigned long pending_notify; /* pfn from LHCALL_NOTIFY */

	/* Did the Guest tell us to halt? */
	int halted;

	struct lg_cpu_arch arch;

	/* Virtual clock device */
	struct hrtimer hrt;





	unsigned long debug;
	unsigned long magic;
	unsigned long host_stack;
	unsigned long guest_stack;
	unsigned long gcr3;		/* mythical guest cr3 */
	unsigned long guest_cr3;	/* real cr3 for guest side */
	unsigned long host_cr3;		/* real cr3 for host side */
	struct desc_ptr host_gdt;
	u16 host_gdt_buff[3];
	struct desc_ptr host_idt;
	u16 host_idt_buff[3];
	unsigned long host_gdt_ptr;
	
	/* Host save gs base pointer */
	unsigned long host_gs_a;
	unsigned long host_gs_d;

	/* save host process gs base pointer */
	unsigned long host_proc_gs_a;
	unsigned long host_proc_gs_d;

	/* hold a pte for the HV */
	u64 *hv_pte;

	struct lguest_pgd *pgd;

	struct desc_ptr gdt; /* address of the GDT at this vcpu */
	u16 gdt_buff[3];
	struct desc_ptr hv_gdt; /* address of GDT in HV addr of vcpu */
	u16 hv_gdt_buff[3];
	struct desc_struct gdt_table[GDT_ENTRIES];

	struct desc_ptr idt; /* address of the IDT at this vcpu */
	u16 idt_buff[3];
	struct gate_struct64 idt_table[IDT_ENTRIES];

	unsigned long rsp; /* saved rsp for iret */

	u64 tss_ist[7]; /* guests ist's */
	u64 page_fault_handler;
	u64 page_fault_clear_if;

	/* stat stuff */
	u64 stat_pf;
	u64 stat_time;
	long stat_cause;

	/* Last time this vcpu saw a timer interrupt */
	int last_timer;

	/* Cached wakeup: we hold a reference to this task. */
	struct task_struct *wake;

	struct lguest_tss_struct tss;

	/* guest ts flag (fpu) */
	unsigned long ts;

	/* host ist 7 - we use it to prevent the NMI race */
	unsigned long host_ist;

	/* For async_hcalls, this is our pointer */
	unsigned long next_hcall;

	/* Do we need to stop what we're doing and return to userspace? */
	int break_out;
	wait_queue_head_t break_wq;

	/* 
	 * If this cpu is given the job to create another one, this is
	 * its number
	 */
	unsigned long new_cpu;
	/* those are general. We catch every possible interrupt */
	DECLARE_BITMAP(interrupt_disabled, LGUEST_IRQS + FIRST_EXTERNAL_VECTOR);
	unsigned long interrupt[LGUEST_IRQS + FIRST_EXTERNAL_VECTOR];

	/* only for those above FIRST_EXTERNAL_VECTOR */
	DECLARE_BITMAP(irqs_pending, LGUEST_IRQS);
};


struct lguest {
	struct list_head list;
	struct lguest_data *lguest_data;
	struct list_head vm_list;
	u32 guestid;
	u64 pfn_limit;
	u64 start_kernel_map;
	u64 page_offset;
	u64 noirq_start, noirq_end;
	unsigned hv_pgd_idx; /* pgd entry index that holds hv */
	unsigned hv_pud_idx; /* pud entry index that holds hv */
	unsigned hv_pmd_idx; /* pmd entry index that holds hv */

	/*
	 * This provides the offset to the base of guest-physical memory in the
	 * Launcher.
	 */
	void __user *mem_base; /* TODO Nesetat - l-am bagat cu japca */
	struct lg_eventfd_map *eventfds;

	/* emulated rtc handling */
	unsigned long rtc;
	unsigned char rtc_offsets[8];

	int halted;
	/* does it really belong here? (yes, - SDR) */
	char *dead;
	/* but this doesn't - SDR ;-) */
	int trap;
	int err;
#if 0
	unsigned long noirq_start, noirq_end;
#endif
	unsigned long pending_key; /* address they're sending to */

	u64 cr3; /* startup cr3 */
	struct lguest_pgd pgds[LGUEST_PGD_SIZE];
	struct list_head g2h[LGUEST_MAP_SIZE];
	struct list_head h2g[LGUEST_MAP_SIZE];
	struct list_head g2h2M[LGUEST_2MMAP_SIZE];
	struct list_head pgd_lru;
	struct list_head pg_lru;
	unsigned long nr_pgds;
	unsigned long nr_pgs;

	struct mutex page_lock;

	/* stat stuff */
	unsigned long stat_hcalls[LGUEST_MAX_STAT_SZ];
	unsigned long stat_traps[LGUEST_MAX_STAT_SZ];
	struct dentry *dentry;
	struct dentry *hcdentry;
	struct dentry *trdentry;

	int timer_on;

	struct lg_cpu cpus[NR_CPUS];
	atomic_t nr_cpus;

	/* statistics */
	unsigned long stat_mappings;
	unsigned long stat_guest_faults;

	/* need to map lguest_data too */
	int irq0_vector;

	unsigned long start_secondary;
	unsigned long init_rsp;
};


extern void switch_to_guest(struct lg_cpu *);
extern unsigned long lguest_hv_addr;
extern int lguest_hv_pages;
extern unsigned long lguest_hv_offset;
extern unsigned long lg_cpu_addr;
extern int lg_cpu_pages;
extern int lg_cpu_order;
extern unsigned long lg_cpu_data_addr;
extern int lg_cpu_data_pages;
extern int lg_cpu_data_order;
extern unsigned long _lguest_default_idt_entries[];

#if  0
extern unsigned long hcall_teste;
extern unsigned long host_syscall;
#endif
extern unsigned long lguest_hv_start;
extern unsigned long lguest_hv_size;

extern struct mutex lguest_lock;

/* Acessors for fields that live in a different place than IA32 */
#define lguest_task(__lg) __lg->vcpus[0]->tsk 
/* No reason for being more complicated than that. It kills puppies */
#define lguest_irqs_pending(__lg) __lg->vcpus[0]->irqs_pending

/* FIXME: Those would live better in some main kernel header */
/* Page fault error code bits */
#define PF_PROT	(1<<0)		/* or no page found */
#define PF_WRITE	(1<<1)
#define PF_USER	(1<<2)
#define PF_RSVD	(1<<3)
#define PF_INSTR	(1<<4)

#define kill_guest(lg, fmt...)				\
do {								\
	if (!(lg)->dead) {					\
		(lg)->dead = kasprintf(GFP_ATOMIC, fmt);	\
		if (!(lg)->dead)				\
			(lg)->dead = ERR_PTR(-ENOMEM);		\
	}							\
} while (0)

#define kill_guest_dump(vcpu, fmt...)		\
do {						\
	lguest_debug = 0;			\
	if (!(vcpu)->lg->dead) {		\
		kill_guest((vcpu)->lg, fmt);	\
		lguest_dump_vcpu_regs(vcpu);	\
	}					\
}  while(0)

//TODO - Cateva lucruri care lipsesc din kernelul acesta si existau in 2.6
#define __HV_CS 0x80
#define GATE_ADDRESS(g) ((unsigned long)((unsigned long)g.offset_high << 32) \
                         | (g.offset_middle << 16) | g.offset_low)

#define DESC_ADDRESS(d) ((unsigned long)((unsigned long)d.base2 << 24)  \
                        | (d.base1 << 16) | d.base0)



static inline void _lguest_set_gate(struct gate_struct64 *s, unsigned type, unsigned long func,
				    unsigned dpl, unsigned ist)
{
        s->offset_low = PTR_LOW(func);
        s->segment = __HV_CS;
        s->ist = ist;
        s->p = 1;
        s->dpl = dpl;
        s->zero0 = 0;
        s->zero1 = 0;
        s->type = type;
        s->offset_middle = PTR_MIDDLE(func);
        s->offset_high = PTR_HIGH(func);
}

static inline unsigned long guest_pa(struct lguest *lg, u64 addr)
{
	return (addr >= lg->start_kernel_map) ?
		(addr - lg->start_kernel_map) :
		(addr - lg->page_offset);
}

static inline u64 convert_idx_to_addr(u64 pgd_idx, u64 pud_idx, u64 pmd_idx, u64 pte_idx)
{
	u64 addr;

	addr = pgd_idx << PGDIR_SHIFT | ((pgd_idx & 0x100) ? 0xffffULL << 48 : 0);
	addr |= pud_idx << PUD_SHIFT |
		pmd_idx << PMD_SHIFT |
		pte_idx << PAGE_SHIFT;
	return addr;
}

static inline int is_hv_page(int pgd_idx, int pud_idx, int pmd_idx, int pte_idx)
{
	/* Never release the hv pages */
	u64 addr = (u64)pgd_idx << PGDIR_SHIFT |
		(u64)pud_idx << PUD_SHIFT |
		(u64)pmd_idx << PMD_SHIFT |
		(u64)pte_idx << PAGE_SHIFT;
	/* sign extend */
	if (pgd_idx & (1<<8))
		addr |= 0xffffULL << 48;
	return (addr >= lguest_hv_start) &&
		(addr < (lguest_hv_start + lguest_hv_size));
}

int demand_page(struct lg_cpu *, u64, int);

void write_timestamp(struct lguest *lg);

int lguest_device_init(void);
void lguest_device_remove(void);

int run_guest(struct lg_cpu *cpu, unsigned long __user *user);
#ifdef CONFIG_SMP
struct lg_cpu *lguest_get_vcpu(struct lguest *lg,
				    unsigned long __user *arg);
#else
#define lguest_get_vcpu(lg, arg) ({ (void)arg; (lg)->vcpus[0];})
#endif /* CONFIG_SMP */

/* page_tables.h */
int lguest_check_hv_pages(struct lg_cpu *cpu);
void lguest_free_all_cr3(u64 *cr3);
int lguest_map_guest_vcpu(struct lg_cpu *cpu);
int lguest_map_guest_page(struct lguest *lguest,
			  unsigned long vaddr, unsigned long paddr,
			  pgprot_t prot);
void lguest_unmap_guest_pages(struct lguest *lguest,
			      unsigned long vaddr, int pages);
void lguest_free_guest_pages(struct lguest *lguest);

void *lguest_mem_addr(struct lg_cpu *cpu, u64 vaddr);

u64 lguest_find_guest_paddr(struct lg_cpu *cpu, u64 addr);

void guest_release_pgd(struct lg_cpu *cpu, u64 cr3);
void guest_set_pte(struct lg_cpu *cpu,
		   unsigned long gaddr,
		   unsigned long val);
void guest_set_pmd(struct lg_cpu *cpu,
		   unsigned long gaddr,
		   unsigned long val);
void guest_set_pud(struct lg_cpu *cpu,
		   unsigned long gaddr,
		   unsigned long val);
void guest_set_pgd(struct lg_cpu *cpu,
		   unsigned long base, unsigned long val);
void guest_flush_tlb_single(struct lg_cpu *cpu, u64 gaddr);
void guest_pagetable_clear_all(struct lg_cpu *cpu);
void guest_pagetable_flush_user(struct lg_cpu *cpu);
void guest_new_pagetable(struct lg_cpu *cpu, u64 cr3);

int init_guest_pagetable(struct lguest *lg/*, u64 pgtable*/);
void free_guest_pagetable(struct lguest *lg);
int lguest_init_vcpu_pagetable(struct lg_cpu *cpu);
int lguest_setup_guest_pages(struct lg_cpu *cpu);
void lguest_add_vm_shrinker(void);
void lguest_remove_vm_shrinker(void);
int lguest_update_page_tables(struct lg_cpu *cpu);
void lguest_free_host_hv_pages(void);
unsigned long lguest_get_actual_phys(void *vaddr, pgprot_t *prot);

/* hypercalls.c */
void do_hypercalls(struct lg_cpu *cpu);

/* core.c */
bool lguest_address_ok(const struct lguest *lg,
		      unsigned long addr, unsigned long len);
void lguest_swapgs(struct lg_cpu *cpu);
u8 lgread_u8(struct lguest *lg, u64 addr);
u16 lgread_u16(struct lguest *lg, u64 addr);
u64 lgread_u32(struct lguest *lg, u64 addr);
u64 lgread_u64(struct lguest *lg, u64 addr);
void lgwrite_u32(struct lguest *lg, u64 addr, u64 val);
void lgwrite_u64(struct lguest *lg, u64 addr, u64 val);

void lgread(struct lguest *, void *, u64, unsigned);
void lgwrite(struct lguest *, u64, const void *, unsigned);

//TODO
int lguest_arch_host_init(void);
void lguest_arch_host_fini(void);
void lguest_arch_run_guest(struct lg_cpu *cpu);
void lguest_arch_handle_trap(struct lg_cpu *cpu);
int lguest_arch_init_hypercalls(struct lg_cpu *cpu);
int lguest_arch_do_hcall(struct lg_cpu *cpu, struct hcall_args *args);
void lguest_arch_setup_regs(struct lg_cpu *cpu, unsigned long start);


/* interrupts_and_traps.c */
/* This is what RedHat offered - if we want to use this,
 * we need to use another core.c program*/
void load_guest_idt_entry(struct lg_cpu *, unsigned int,
						struct gate_struct64 *);
void lguest_disable_interrupts(struct lg_cpu *vcpu);
void maybe_do_interrupt(struct lg_cpu *);
void guest_iret(struct lg_cpu *vcpu);
int reflect_trap(struct lg_cpu *, int, int);
void lguest_force_trap(struct lg_cpu *vcpu);
void init_clockdev(struct lg_cpu *cpu);

//TODO
/*To compile it with old core.c, we need functions like: */
unsigned int interrupt_pending(struct lg_cpu *cpu, bool *more);
void try_deliver_interrupt(struct lg_cpu *cpu, unsigned int irq, bool more);
void set_interrupt(struct lg_cpu*, unsigned int irq);
int init_interrupts(void);
void free_interrupts(void);






/* lguest_user.c */
bool send_notify_to_eventfd(struct lg_cpu *cpu);

/* lguest_stat.c */
extern void lguest_stat_return_to_host(struct lg_cpu *vcpu);
extern void lguest_stat_init(void);
extern void lguest_stat_cleanup(void);
extern void lguest_stat_add_guest(struct lguest *lg);
extern void lguest_stat_remove_guest(struct lguest *lg);
extern void lguest_stat_start_pagefault(struct lg_cpu *vcpu);
extern void lguest_stat_end_pagefault(struct lg_cpu *vcpu);
extern void lguest_stat_start_time(struct lg_cpu *vcpu);
extern void lguest_stat_end_time(struct lg_cpu *vcpu);

/* lguest_debug.c */
extern int lguest_debug;
#define LGD_HC_FL (1<<1)	/* Print Hypercalls */
#define LGD_SW_FL (1<<2)	/* Print guest/host switching */
#define LGD_GS_FL (1<<3)	/* Print swapgs updates */
#define LGD_PF_FL (1<<4)	/* Print Page faulting */
#define LGD_TRAP_FL (1<<5)	/* print traps */
#define LGD_IRQ_FL (1<<6)	/* print irqs */
#define LGD_PG_FL (1<<7)	/* Print paging */
void lgdebug_print(const char *fmt, ...);
void lgdebug_vprint(const char *fmt, va_list ap);
void lgdebug_lprint(unsigned flags, const char *fmt, ...);
void lgdebug_lvprint(unsigned flags, const char *fmt, va_list ap);
void lguest_dump_vcpu_regs(struct lg_cpu *cpu);
void lguest_dump_trace(struct lg_cpu *cpu, struct lguest_regs *regs);
void lguest_print_address(struct lg_cpu *cpu, unsigned long address);
void lguest_free_vcpu_mappings(struct lg_cpu *cpu);
void lguest_print_guest_page_tables(struct lg_cpu *cpu, u64 cr3);
void lguest_paranoid_page_check(struct lg_cpu *cpu, int check);
void lguest_print_page_tables(u64 *cr3);

/* <arch>/switcher.S: */
extern char start_switcher_text[], end_switcher_text[];

#endif /* !__ASSEMBLY__ */

#endif
