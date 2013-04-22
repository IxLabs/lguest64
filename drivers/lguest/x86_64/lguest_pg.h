#ifndef _LGUEST_PG_H
#define _LGUEST_PG_H
#include <asm/pgtable.h>

struct lg_cpu;

/*
 * We now use the shrinker to handle memory pressure,
 * but we keep these around to put constraints on
 * for debugging purposes.
 */
#define LGUEST_MAX_PUDS -1UL
#define LGUEST_MAX_PMDS -1UL
#define LGUEST_MAX_PTES -1UL

/* these must be powers of two */
#define LGUEST_MAP_SIZE		(4096)
#define LGUEST_2MMAP_SIZE	(512)

/* Total number of pgds */
#define LGUEST_PGD_SIZE		16

#define LGUEST_PGD_BUSY_FL	(1<<0)
#define LGUEST_PGD_MASTER_FL	(1<<1)
#define LGUEST_PGD_LINK_FL	(1<<2)

#define LGUEST_PUD_KERNEL_FL	(1<<1)
#define LGUEST_PUD_HV_FL	(1<<2)
#define LGUEST_PMD_KERNEL_FL	(1<<1)
#define LGUEST_PMD_HV_FL	(1<<2)
#define LGUEST_PMD_2M_FL	(1<<3)
#define LGUEST_PTE_KERNEL_FL	(1<<1)
#define LGUEST_PTE_HV_FL	(1<<2)

#define LGUEST_PGD_MAGIC	0x78787878
#define LGUEST_PUD_MAGIC	0x56565656
#define LGUEST_PMD_MAGIC	0x34343434
#define LGUEST_PTE_MAGIC	0x12121212

enum lguest_pg_type {
	LGUEST_PG_NONE,
	LGUEST_PG_PGD,
	LGUEST_PG_PUD,
	LGUEST_PG_PMD,
	LGUEST_PG_PTE
};

struct lguest_pgd {
	struct list_head lru;
	struct list_head copies;
	struct lg_cpu *cpu;
	u64 gcr3;
	u64 *hcr3;
	unsigned flags;
	int magic;
};

/* 
 * This structure represents a generic page table, i.e., it is a fit for
 * a pud, pmd, etc. Do not confuse it with lguest_pgd, which just have the
 * pointer to cr3, and represents the whole tree
 */
struct lguest_pg {
	u64 *haddr;
	u64 gaddr;
	struct list_head list;
	struct list_head hlist;
	struct list_head lru;
	struct list_head copies;
	enum lguest_pg_type type;
	struct lguest_pgd *pgd;
	int count;
};


#endif /* _LGUEST_PG_H */
