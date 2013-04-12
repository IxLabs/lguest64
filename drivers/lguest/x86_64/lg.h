#ifndef _LGUEST_GUEST_H_
#define _LGUEST_GUEST_H_

#include "lguest.h"

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

/* XXX: Make this into a real config option */
#ifndef CONFIG_LGUEST_NR_CPUS
# define CONFIG_LGUEST_NR_CPUS NR_CPUS
#endif

#define LGUEST_NR_CPUS CONFIG_LGUEST_NR_CPUS

#ifndef __ASSEMBLY__
#include "../lg.h"
#include <linux/lguest_dma.h>
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

struct lguest {
	struct list_head list;
	struct lguest_data *lguest_data;
	struct mm_struct *mm;
	struct list_head vm_list;
	u32 guestid;
	u64 pfn_limit;
	u64 start_kernel_map;
	u64 page_offset;
	u64 noirq_start, noirq_end;
	unsigned hv_pgd_idx; /* pgd entry index that holds hv */
	unsigned hv_pud_idx; /* pud entry index that holds hv */
	unsigned hv_pmd_idx; /* pmd entry index that holds hv */

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
	int dma_is_pending;
	unsigned long pending_dma; /* struct lguest_dma */
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

	struct lguest_dma_info dma[LGUEST_MAX_DMA];
	struct lguest_vcpu *vcpus[LGUEST_NR_CPUS];
	atomic_t num_vcpus;

	/* statistics */
	unsigned long stat_mappings;
	unsigned long stat_guest_faults;

	/* need to map lguest_data too */
	int irq0_vector;

	unsigned long start_secondary;
	unsigned long init_rsp;
};

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
 * The lguest_vcpu struct is mapped into the guest address space
 * as read only. This stores the information needed to get back to
 * the host, and perhaps any thing else that is unique to a VCPU.
 */
struct lguest_vcpu {
	/* keep vcpu guest data (RW portion) as first element (HV then Host) */
	unsigned long vcpu_data_hv; /* pointer to guest data (RW) in HV land */
	struct lguest_vcpu_data *vcpu_data; /* pointer in Host for RW data */

	unsigned long vcpu_hv; /* pointer to guest vcpu (RO) in HV land */
	struct lguest_vcpu *vcpu; /* pointer to itself */

	unsigned long host_syscall;

	struct task_struct *tsk;

	unsigned long debug;
	unsigned long magic;
	unsigned int  id;
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
	
	struct lguest_vcpu_data __user *lguest_vcpu_data;

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
	struct gate_struct idt_table[IDT_ENTRIES];

	unsigned long rsp; /* saved rsp for iret */

	u64 tss_ist[7]; /* guests ist's */
	u64 page_fault_handler;
	u64 page_fault_clear_if;

	/* stat stuff */
	u64 stat_pf;
	u64 stat_time;
	long stat_cause;

	struct lguest *guest;

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
	 * If this vcpu is given the job to create another one, this is
	 * its number
	 */
	unsigned long new_vcpu;
	/* those are general. We catch every possible interrupt */
	DECLARE_BITMAP(interrupt_disabled, LGUEST_IRQS + FIRST_EXTERNAL_VECTOR);
	unsigned long interrupt[LGUEST_IRQS + FIRST_EXTERNAL_VECTOR];

	/* only for those above FIRST_EXTERNAL_VECTOR */
	DECLARE_BITMAP(irqs_pending, LGUEST_IRQS);
};


extern void switch_to_guest(struct lguest_vcpu *);
extern unsigned long lguest_hv_addr;
extern int lguest_hv_pages;
extern unsigned long lguest_hv_offset;
extern unsigned long lguest_vcpu_addr;
extern int lguest_vcpu_pages;
extern int lguest_vcpu_order;
extern unsigned long lguest_vcpu_data_addr;
extern int lguest_vcpu_data_pages;
extern int lguest_vcpu_data_order;
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

#define kill_guest(guest, fmt...)				\
do {								\
	lguest_debug = 0;					\
	if (!(guest)->dead) {					\
		(guest)->dead = kasprintf(GFP_ATOMIC, fmt);	\
		if (!(guest)->dead)				\
			(guest)->dead = (void *)-1;		\
	}							\
} while (0)

#define kill_guest_dump(vcpu, fmt...)		\
do {						\
	lguest_debug = 0;			\
	if (!(vcpu)->guest->dead) {		\
		kill_guest((vcpu)->guest, fmt);	\
		lguest_dump_vcpu_regs(vcpu);	\
	}					\
}  while(0)

static inline void _lguest_set_gate(struct gate_struct *s, unsigned type, unsigned long func,
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

int demand_page(struct lguest_vcpu *, u64, int);

void write_timestamp(struct lguest *lg);

int lguest_device_init(void);
void lguest_device_remove(void);

int run_guest(struct lguest_vcpu *vcpu, char *__user user);
#ifdef CONFIG_SMP
struct lguest_vcpu *lguest_get_vcpu(struct lguest *lg,
				    unsigned long __user *arg);
#else
#define lguest_get_vcpu(lg, arg) ({ (void)arg; (lg)->vcpus[0];})
#endif /* CONFIG_SMP */

/* page_tables.h */
int lguest_check_hv_pages(struct lguest_vcpu *vcpu);
void lguest_free_all_cr3(u64 *cr3);
int lguest_map_guest_vcpu(struct lguest_vcpu *vcpu);
int lguest_map_guest_page(struct lguest *lguest,
			  unsigned long vaddr, unsigned long paddr,
			  pgprot_t prot);
void lguest_unmap_guest_pages(struct lguest *lguest,
			      unsigned long vaddr, int pages);
void lguest_free_guest_pages(struct lguest *lguest);

void *lguest_mem_addr(struct lguest_vcpu *vcpu, u64 vaddr);

u64 lguest_find_guest_paddr(struct lguest_vcpu *vcpu, u64 addr);

void guest_release_pgd(struct lguest_vcpu *vcpu, u64 cr3);
void guest_set_pte(struct lguest_vcpu *vcpu,
		   unsigned long gaddr,
		   unsigned long val);
void guest_set_pmd(struct lguest_vcpu *vcpu,
		   unsigned long gaddr,
		   unsigned long val);
void guest_set_pud(struct lguest_vcpu *vcpu,
		   unsigned long gaddr,
		   unsigned long val);
void guest_set_pgd(struct lguest_vcpu *vcpu,
		   unsigned long base, unsigned long val);
void guest_flush_tlb_single(struct lguest_vcpu *vcpu, u64 gaddr);
void guest_pagetable_clear_all(struct lguest_vcpu *vcpu);
void guest_pagetable_flush_user(struct lguest_vcpu *vcpu);
void guest_new_pagetable(struct lguest_vcpu *vcpu, u64 cr3);

int init_guest_pagetable(struct lguest *lg, u64 pgtable);
int lguest_init_vcpu_pagetable(struct lguest_vcpu *vcpu);
int lguest_setup_guest_pages(struct lguest_vcpu *vcpu);
void lguest_add_vm_shrinker(void);
void lguest_remove_vm_shrinker(void);
int lguest_update_page_tables(struct lguest_vcpu *vcpu);
void lguest_free_host_hv_pages(void);
unsigned long lguest_get_actual_phys(void *vaddr, pgprot_t *prot);

/* hypercall.c */
int hypercall(struct lguest_vcpu *vcpu);

/* core.c */
int lguest_address_ok(const struct lguest *lg,
		      unsigned long addr, unsigned long len);
void lguest_swapgs(struct lguest_vcpu *vcpu);
u8 lgread_u8(struct lguest *lg, u64 addr);
u16 lgread_u16(struct lguest *lg, u64 addr);
u64 lgread_u32(struct lguest *lg, u64 addr);
u64 lgread_u64(struct lguest *lg, u64 addr);
void lgwrite_u32(struct lguest *lg, u64 addr, u64 val);
void lgwrite_u64(struct lguest *lg, u64 addr, u64 val);

void lgread(struct lguest *, void *, u64, unsigned);
void lgwrite(struct lguest *, u64, const void *, unsigned);

/* interrupts_and_traps.c */

void load_guest_idt_entry(struct lguest_vcpu *, unsigned int,
						struct gate_struct *);
void lguest_disable_interrupts(struct lguest_vcpu *vcpu);
void maybe_do_interrupt(struct lguest_vcpu *);
void guest_iret(struct lguest_vcpu *vcpu);
int reflect_trap(struct lguest_vcpu *, int, int);
void lguest_force_trap(struct lguest_vcpu *vcpu);

/* lguest_stat.c */
extern void lguest_stat_return_to_host(struct lguest_vcpu *vcpu);
extern void lguest_stat_init(void);
extern void lguest_stat_cleanup(void);
extern void lguest_stat_add_guest(struct lguest *lg);
extern void lguest_stat_remove_guest(struct lguest *lg);
extern void lguest_stat_start_pagefault(struct lguest_vcpu *vcpu);
extern void lguest_stat_end_pagefault(struct lguest_vcpu *vcpu);
extern void lguest_stat_start_time(struct lguest_vcpu *vcpu);
extern void lguest_stat_end_time(struct lguest_vcpu *vcpu);

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
void lguest_dump_vcpu_regs(struct lguest_vcpu *vcpu);
void lguest_dump_trace(struct lguest_vcpu *vcpu, struct lguest_regs *regs);
void lguest_print_address(struct lguest_vcpu *vcpu, unsigned long address);
void lguest_free_vcpu_mappings(struct lguest_vcpu *vcpu);
void lguest_print_guest_page_tables(struct lguest_vcpu *vcpu, u64 cr3);
void lguest_paranoid_page_check(struct lguest_vcpu *vcpu, int check);
void lguest_print_page_tables(u64 *cr3);

#endif /* !__ASSEMBLY__ */

#endif
