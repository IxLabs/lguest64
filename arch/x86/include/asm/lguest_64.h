#ifndef _LGUEST_H_
#define _LGUEST_H_

#define LGUEST_PGDS_PER_VCPU 8
#define LGUEST_PGDIRS (LGUEST_MAX_VCPUS * LGUEST_PGDS_PER_VCPU)


/* Used with lg_cpu_data flags */
 /* generic bit to let guest know there's an irq pending. */
#define LG_CPU_IRQPEND_FL	(1<<0)
  /* test for HV page faulting */
#define LG_CPU_PGFAULT_FL	(1<<1)
  /* test for HV fault other than page */
#define LG_CPU_IRQFAULT_FL	(1<<2)
#define LG_CPU_ANYFAULT_FL (LG_CPU_IRQFAULT_FL | LG_CPU_PGFAULT_FL)
 /* Used to notify guest that a page table entry was updated */
#define LG_CPU_PGSET_FL	(1<<3)
 /* Used to tell the HV that we are a hypercall */
#define LG_CPU_HC_FL	(1<<4)
 /* do swapgs on syscall */
#define LG_CPU_SWAPGS_FL	(1<<5)
 /* debug time me! */
#define LG_CPU_TIME_FL	(1<<6)

#define lguest_data_set_bit(bit, data)			\
	do { (data)->flags |= LG_CPU_##bit##_FL ; } while(0)
#define lguest_data_clear_bit(bit, data)		\
	do { (data)->flags &= ~LG_CPU_##bit##_FL ; } while(0)
#define lguest_data_test_bit(bit, data)			\
	((data)->flags & LG_CPU_##bit##_FL)

#ifndef __ASSEMBLY__
#include <asm/desc.h>
#include <asm/hw_irq.h>
#include <linux/futex.h>
#include <linux/lguest_launcher.h>

/* Every guest maps the core switcher code. */
#define SHARED_SWITCHER_PAGES \
	DIV_ROUND_UP(end_switcher_text - start_switcher_text, PAGE_SIZE)
/* Pages for switcher itself, then two pages per cpu */
#define TOTAL_SWITCHER_PAGES (SHARED_SWITCHER_PAGES + 2 * nr_cpu_ids)

/* We map at -4M (-2M for PAE) for ease of mapping (one PTE page). */
#ifdef CONFIG_X86_PAE
#define SWITCHER_ADDR 0xFFE00000
#else
#define SWITCHER_ADDR 0xFFC00000
#endif

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

/**
 * TODO - Stefan
 * This is just a copy of x86_32 struct
 * See what you have to change for x86_64
 */
struct lg_cpu_arch {
	/* The GDT entries copied into lguest_ro_state when running. */
	struct desc_struct gdt[GDT_ENTRIES];

	/* The IDT entries: some copied into lguest_ro_state when running. */
	struct desc_struct idt[IDT_ENTRIES];

	/* The address of the last guest-visible pagefault (ie. cr2). */
	unsigned long last_pagefault;
};

extern struct lguest_data lguest_data;
extern struct lguest_device_desc *lguest_devices; /* Just past max_pfn */
extern struct list_head lguests;

#endif /* ! __ASSEMBLY__ */
#endif
