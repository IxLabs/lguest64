/*
 * Shadow page table operations.
 * Copyright (C) Steven Rostedt, Red Hat Inc, 2007
 * GPL v2
 */
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/percpu.h>
#include <asm/tlbflush.h>
#include "lg.h"

/**********************************************************************/
/*
 * This file needs a bit of explaning.  Here's my bit to do so.
 *
 * The x86_64 has 4 levels of paging. CR3->PGD->PUD->PMD->PTE->page
 * The guest may need to access any of the levels of paging and it
 * may only tell the HV about the paddr that it thinks the page
 * is at. But the problem is that it does not exist at the real paddr.
 * So instead of scanning all the page tables of the guest, we
 * keep a hash in the lguest struct of mappings between
 * guest pages and host shadow pages and label them to what they
 * are (PUD, PMD, or PTE). There is also a mapping between host and
 * guests pages.
 *
 * The way the x86_64 pages work, is that we can protect a page for
 * supervisor or user mode. The problem is that if we say supervisor
 * mode it means rings 0, 1 and 2. Ring 3 only has access to user mode.
 * But if we run the guest kernel in ring 1 (or anything other than ring 3)
 * then the guest will have access to the same pages as the host, with
 * the same permissions.
 *
 * The way around this, and still use ring 1 for the guest kernel, is that
 * we make the HV unique for the guest, and keep it read only. We split it
 * up like so:
 *
 *     +------------------+
 *     |                  |
 *     |                  |
 *     |                  |
 *     +------------------+
 *     |                  |
 *     | VCPU Guest data  |
 *     | (unique to VCPU) |
 *     |    RW by guest.  |
 *     |                  |
 *     +------------------+
 *     |                  |
 *     |    VCPU Data     |
 *     | (unique to VCPU) |
 *     |    RO by guest.  |
 *     |                  |
 *     +------------------+
 *     |                  |
 *     |    HV Text       |
 *     |                  |
 *     +------------------+
 *     |                  |
 *
 *
 *  Where the Guest Data is a writable section for both the host and
 *  the guest. But that Guest Data is not used by the host besides
 *  using it as a stack on faults and interrupts.  So even if the guest
 *  writes to it, it will not cause any harm to the host or other guests
 *  since the only data that is placed there that the host uses is the
 *  interrupt stack that is placed there by the hardware, as well as data
 *  that it uses for that guest, but nothing that will harm the host
 *  or any other guest.
 *
 *  The CPU Data is read only by both the guest and the host, and that
 *  holds the data to switch back to the host.  The host *can* write to
 *  this data when it's using the host cr3. But after we switch to the
 *  guest shadow cr3, none of the ring's can write to it.
 *
 *
 * Now back to managing the shadow pages:
 *
 *  The CPU points to a unique page descriptor (pgd) that represents some
 *  cr3 by the guest. Unfortunately, we can't keep a 1 to 1 mapping between
 *  cr3's of the guest to the pg descriptor. But we do have a 1 to 1 mapping
 *  of the host page tables with the descriptor.  The reason that we can't have
 *  the guest 1 to 1 mapping is that we must have a unique Guest Data and
 *  vcpu data area for every vcpu. Two threads might use the same cr3 on two
 *  different VCPUs.  So to handle this, we also manage "copies". For both the
 *  pgds as well as the page table pages (pgs).
 *
 *  The only pgds and pgs that have copies are those that contain the
 *  HV pages.   All other page tables that don't contain the HV have a 1
 *  to 1 mapping with shadow pages.  This means that all mappings in the
 *  hash have a unique host (shadow) page address.
 *
 *  To make it easier to know if a shadow page contains the HV, we use bit
 *  (LGUEST_PAGE_HV) 10 of the available bits in the page for use by the
 *  operating system. We set this bit when the page contains a HV and we
 *  know that it must be copied if we have more than one reference to it.
 *  But we also need to be aware if the page has been mapped. We use bit 9
 *  (LGUEST_PAGE_PRESENT) to tell us that.  So looking to see if a shadow
 *  page has already been mapped for the guest, we look at the
 *  LGUEST_PAGE_PRESENT bit instead of the _PAGE_PRESENT bit.
 *  
 *  Here's the layout.
 *
 *  VCPU(A)-->pgd-->+---------------+
 *            |     |               |
 *            |     | HV bit 10 set |---> Own copy
 *            |     |               |
 *            |     |               |--------->+-----------+
 *            |     +---------------+      ^   |           |
 *            |                            |   |           |
 *            |(copy pointer)              |   +-----------+
 *            V                            |
 *  VCPU(B)-->pgd-->+---------------+      +--------+ (shared)
 *                  |               |               |
 *                  | HV bit 10 set |---> Own copy  |
 *                  |               |               |
 *                  |               |---------------+
 *                  +---------------+          
 *
 *
 *  The above shows two shared pg descriptors that would have
 *  the same guest cr3.  They both have their own PGD table, and their
 *  own HV pages (although PMDS in the HV PUD that don't hold the 
 *  HV are also shared).
 *
 *  All shadow page tables are referenced in the lguest
 *  hash. Both guest to host lookup (g2h) and host to guest (h2g).
 *
 *  When a shadow page is freed, so are its hash descriptors.
 *
 *  If two page table entries reference the same address, then the mapped
 *  page will have a reference count of two.  This is a different aspect
 *  than of copies. Copies are where you have the same guest page shadowed
 *  by two different host pages.  A reference count is the number of
 *  higher level page tables entries referencing the page.
 *
 *  For example:
 *   Two PMDs might for some reason reference the same PTE.
 *   The mapped PTE will have a reference count of 2.
 *   If two copied PMDs reference the same PTE, then the PTE
 *   will still have a reference count of 2 but the above
 *   PMDs really represent the same guest PMD.
 *
 *  The way to remember what a copy is, is that all copies point to
 *  the same guest page, but have different host pages.  Anything
 *  else has one host page and one guest page.
 *
 *  Note: More than one hash entry can exist for a given guest page
 *    but they all must be a copy of each other.
 *   Only one hash entry can exist for a given host addr.
 *
 * 
 * 2 Meg Pages!
 *
 *  Unfortunately, a PMD entry may point to either a PTE table,
 *  or to a 2 Meg page.  The host only maps 4K pages, so we must
 *  split up the 2 Meg guest page into 512 4K host pages.
 *  The index into the address of the guest 2 Meg page is used
 *  to create a PTE host reference hash.
 *
 * IT GETS EVEN NASTIER!!!!
 *
 *  The kernel usually maps in all of memory. To do this it uses
 *  2M pages (which are shadowed as 4K pages).  So the PTE's that
 *  represent these pages may also be PGDs, PUDs, PMDs or other
 *  PTEs.
 *
 *  So we need to hold the 2M pages in a separate hash.
 *  This way we don't mix them up.  We still have a unque host
 *  shadow pages for all these address, but the guest address
 *  may be the same for a 2M PMD page, as well as a PTE, 4K PMD
 *  or PUD.
 *
 *  Note: When a pgd is attached to a VCPU that is running on CPU
 *   it has the "busy" flag set. This means that the pgd can not
 *   be destroyed, or reused. But any pgds that are not currently
 *   active, are fair game to be cleaned up, which takes us to...
 *
 * LRU: Least Recently Used page tables.
 *
 *  To keep the guest from DOSing the host by filling up all
 *  the page tables with new pages, we keep a cap on the amount
 *  of pages the guest is allowed to have. Otherwise the guest
 *  for every CR3 could have 512 pages for the PUDs, and each of
 *  them could have 512 pages of PMDs and each of them could have
 *  512 pages of ptes. So each PGD can have a total of 512*512*512
 *  pages or 134,217,728 pages. And this is for a single page
 *  table!!
 *
 *  We define a max number of pages the guest is allowed, and the
 *  least recently used pages are discarded. All PUDs, PMDs, and
 *  PTEs are up for grabs. If a PUD is discarded, so is all of
 *  its PMDs, and if a PMD is discarded, so is all of its PTEs.
 *
 *  A pg toplevel descriptor (pgd) can only be discarded if
 *  it is reused (or the guest is killed). Since the topleve pgds
 *  are not dynamically allocated but are actually part of the
 *  lguest descriptor.
 *
 *  If the guest then accesses a released page, it will simply fault and
 *  the HV will put it back in as a most recently used page.
 *
 * Caveat:
 *  Since we always need to map in the HV, it's not true that we
 *  have a mapping for all shadow page tables. If a guest did not
 *  reference a page shared by the HV PUD or PMD, then the shadow
 *  pages for the HV will not have a reference in the hash. But we need
 *  to differentiate a page that is in the hash and one that is not.
 *  To do this, we use bit 9 (LGUEST_PAGE_PRESENT) of the descriptor
 *  to flag that the page is indeed in the hash.  This way we know
 *  that we need to add it when a guest does reference the page.
 *  This last note is somewhat of a duplicate of what was stated above.
 *  If you notice this, then good for you. You have read all of this
 *  and you achieved the rank of minor puppy.
 */
/**********************************************************************/

static LIST_HEAD(lguest_infos);
static DEFINE_MUTEX(lguest_vm_lock);

/* set to one to use the available bits in the page tables for debugging */
#define DEBUG_PAGES 1
#define REALLY_DEBUG_PAGES 0
#define EXPENSIVE_TESTS 0


#define HASH_PG(x) (((u64)(x)>>PAGE_SHIFT) & (LGUEST_MAP_SIZE-1))
#define HASH_PG2M(x) (((u64)(x)>>PAGE_SHIFT) & (LGUEST_2MMAP_SIZE-1))

#define LGUEST_WARN_ON(lg, cond, exp)				   \
	do {							   \
		if (unlikely(cond)) {				   \
			kill_guest(lg, "bad paging?? %s:%d",	   \
				   __FUNCTION__, __LINE__);	   \
			WARN_ON(1);				   \
			exp;					   \
		}						   \
	} while(0)
#define LGUEST_WARN_ON_DUMP(vcpu, cond, exp)				\
	do {								\
		if (unlikely(cond)) {					\
			kill_guest_dump(vcpu, "bad paging?? %s:%d",	\
					__FUNCTION__, __LINE__);	\
			WARN_ON(1);					\
			exp;						\
		}							\
	} while(0)

/*
 * Yes, we have _PAGE_USER. Some shared tables will need user access.
 * We handle the HV protection at the lowest level.
 */
#define LGUEST_HV_PG_PROT	\
	(_PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_RW | _PAGE_USER | LGUEST_PAGE_HV)
#define LGUEST_HV_EXEC_PROT	(_PAGE_PRESENT | _PAGE_ACCESSED | LGUEST_PAGE_HV)
/* FIXME: can we get the data and guest data to use _PAGE_NX? */
#define LGUEST_HV_DATA_PROT	\
	(_PAGE_PRESENT | _PAGE_ACCESSED | LGUEST_PAGE_HV)
#define LGUEST_HV_VCPU_DATA_PROT	\
	(_PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_RW | LGUEST_PAGE_HV)

#define LGUEST_MAPPED_PG_PROT \
	(_PAGE_PRESENT | _PAGE_ACCESSED | LGUEST_PAGE_PRESENT)

/*
 * We always map in the HV, but the HV may share page tables with
 * non HV pages, so for PGD and PUD and PMD, we use bit 9 as an available
 * bit as whether we shadow mapped the page.
 */
#define LGUEST_PAGE_PRESENT	(1ULL<<9)
/* HV page tables are flagged with bit 10 */
#define LGUEST_PAGE_HV		(1ULL<<10)
/* host pages that represent 2M pages. */
#define LGUEST_PAGE_2M		(1ULL<<11)

#define str_pg_type(type) ({					  \
			(type) == LGUEST_PG_PTE ? "pte" :	  \
				(type) == LGUEST_PG_PMD ? "pmd" : \
				(type) == LGUEST_PG_PUD ? "pud" : \
				"unknown??";			  \
		})

#if DEBUG_PAGES
/* Upper available bit is used for debugging */
#  define LGUEST_PAGE_DEBUG (1ULL<<52)
#  define debug_pages_put(x) do {					\
		get_pages--;						\
		put_page(pfn_to_page(((unsigned long)(x) & PTE_MASK) >> PAGE_SHIFT)); \
	 } while(0)
#  define debug_pages_get() do { get_pages++; } while(0)
#  define __clear_pt(pt) do { (pt) &= LGUEST_PAGE_DEBUG; } while(0)
/* The following keep the DEBUG bit around */
#  define lset_pte(pte, val) \
	set_pte(pte, __pte(pte_val(val)|(pte_val(*pte) & LGUEST_PAGE_DEBUG)))
#  define lset_pmd(pmd, val) \
	set_pmd(pmd, __pmd(pmd_val(val)|(pmd_val(*pmd) & LGUEST_PAGE_DEBUG)))
#  define lset_pud(pud, val) \
	set_pud(pud, __pud(pud_val(val)|(pud_val(*pud) & LGUEST_PAGE_DEBUG)))
#  define lset_pgd(pgd, val) \
	set_pgd(pgd, __pgd(pgd_val(val)|(pgd_val(*pgd) & LGUEST_PAGE_DEBUG)))
#  define set_pt(pt, val) \
	do { pt = (val) | ((pt) & LGUEST_PAGE_DEBUG); } while(0)
#  define debug_pt_page_dec() pages_used--
static unsigned long pages_used;
static unsigned long get_pages;

#  if REALLY_DEBUG_PAGES
#    define get_pt_page() __get_pt_page(__FUNCTION__, __LINE__)
#    define __DEBUG_PAGES_PARAMS__ const char *func, int line
struct really_debug_pages {
	struct list_head list;
	const char *func;
	int line;
	u64 *page;
};
static LIST_HEAD(debugged_pages);
#endif /* REALLY_DEBUG_PAGES */

#else /* DEBUG_PAGES */
#  define debug_pages_get() do { } while(0)
#  define debug_pages_put(x) do {					\
		put_page(pfn_to_page(((unsigned long)(x) & PTE_MASK) >> PAGE_SHIFT)); \
	} while(0)
#  define __clear_pt(pt) do { (pt) = 0; } while(0)
#  define set_pt(pt, val) do { pt = val; } while(0)
#  define lset_pte(pte, val) set_pte(pte, val)
#  define lset_pmd(pmd, val) set_pmd(pmd, val)
#  define lset_pud(pud, val) set_pud(pud, val)
#  define lset_pgd(pgd, val) set_pgd(pgd, val)
#  define debug_pt_page_dec() do { } while(0)
#endif

#define clear_pt(pt) do {			    \
		if ((pt) & LGUEST_PAGE_HV)	    \
			pt &= ~LGUEST_PAGE_PRESENT; \
		else				    \
			__clear_pt(pt);		    \
	} while(0)

#if !REALLY_DEBUG_PAGES
#  define __get_pt_page get_pt_page
#  define __DEBUG_PAGES_PARAMS__ void
#endif

static u64 *__get_pt_page(__DEBUG_PAGES_PARAMS__)
{
	u64 *page;

	page = (u64 *)get_zeroed_page(GFP_KERNEL);

#if DEBUG_PAGES
	if (!page)
		return NULL;
	pages_used++;
	page[4] = LGUEST_PAGE_DEBUG;
	page[14] = LGUEST_PAGE_DEBUG;
	page[24] = LGUEST_PAGE_DEBUG;
	page[34] = LGUEST_PAGE_DEBUG;
#  if REALLY_DEBUG_PAGES
	{
		struct really_debug_pages *rdp;

		rdp = kmalloc(sizeof(*rdp), GFP_KERNEL);
		if (!rdp)
			/* AAAAAHHHHH!!! */
			return NULL;
		rdp->func = func;
		rdp->line = line;
		rdp->page = page;
		list_add(&rdp->list, &debugged_pages);
	}
#  endif
#endif
	return page;
}

static void free_pt_page(u64 *page)
{
	lgdebug_lprint(LGD_PG_FL, "free_pt_page %p\n", page);
#if DEBUG_PAGES
	if (!page)
		return;
#  if REALLY_DEBUG_PAGES
	{
		struct really_debug_pages *rdp;

		/* Really really freak'n slow! */
		list_for_each_entry(rdp, &debugged_pages, list) {
			if (rdp->page)
				break;
		}
		/* Check if not found */
		if (rdp == list_entry(&debugged_pages, struct really_debug_pages, list)) {
			WARN_ON(1);
			return;
		}
		list_del(&rdp->list);
		kfree(rdp);
	}
#  endif
	pages_used--;
//	printk("free page %p\n", page);
	if (!(((page[4] & LGUEST_PAGE_DEBUG) == LGUEST_PAGE_DEBUG) &&
	      ((page[14] & LGUEST_PAGE_DEBUG) == LGUEST_PAGE_DEBUG) &&
	      ((page[24] & LGUEST_PAGE_DEBUG) == LGUEST_PAGE_DEBUG) &&
	      ((page[34] & LGUEST_PAGE_DEBUG) == LGUEST_PAGE_DEBUG) &&
	      /* Also make sure that LGUEST_PAGE_DEBUG isn't set everywhere */
	      ((page[2] & LGUEST_PAGE_DEBUG) != LGUEST_PAGE_DEBUG) &&
	      ((page[12] & LGUEST_PAGE_DEBUG) != LGUEST_PAGE_DEBUG) &&
	      ((page[22] & LGUEST_PAGE_DEBUG) != LGUEST_PAGE_DEBUG) &&
	      ((page[32] & LGUEST_PAGE_DEBUG) != LGUEST_PAGE_DEBUG))) {
		printk("Bad lguest page table page %p\n", page);
		printk("  4: %llx\n", page[4]);
		printk(" 14: %llx\n", page[14]);
		printk(" 24: %llx\n", page[24]);
		printk(" 34: %llx\n", page[34]);
		printk("  2: %llx\n", page[2]);
		printk(" 12: %llx\n", page[12]);
		printk(" 22: %llx\n", page[22]);
		printk(" 32: %llx\n", page[32]);
		WARN_ON(1);
		return;
	}
	page[4] = page[14] = page[24] = page[34] = 0;
#endif
	free_page((long)page);
}

#define is_canonical(vaddr) ((vaddr <= 0x00007fffffffffff) || (vaddr >= PAGE_OFFSET))

static int contains_hv_page(u64 addr, u64 size)
{
	return (addr+size >= lguest_hv_start) &&
		(addr < (lguest_hv_start + lguest_hv_size));
}

/*
 * Find the actual physical mapping for the user page.
 * This increments the page count
 */
static unsigned long get_pfn(unsigned long virtpfn, int write)
{
	struct vm_area_struct *vma;
	struct page *page;
	unsigned long ret = -1UL;

	down_read(&current->mm->mmap_sem);
	if (get_user_pages(current, current->mm, virtpfn << PAGE_SHIFT,
			   1, write, 1, &page, &vma) == 1) {
		debug_pages_get();
		ret = page_to_pfn(page);
	}
	up_read(&current->mm->mmap_sem);
	return ret;
}

static inline int lguest_set_pgprot(u64 val)
{
	int pgprot;

	pgprot = LGUEST_MAPPED_PG_PROT |
		(val & (_PAGE_USER | _PAGE_RW));

	return pgprot;
}

/*
 * Find pg via guest address.
 */
static struct lguest_pg *find_pg(struct lguest *lg, u64 gaddr)
{
	struct lguest_pg *pg;
	int hash;

	/* if this is a 2M PTE, then we need to check that hash */
	if (gaddr & _PAGE_PSE) {
		/* gaddr has protection bits */
		gaddr &= PTE_MASK;

		hash = HASH_PG2M(gaddr);
	
		list_for_each_entry(pg, &lg->g2h2M[hash], list)
			if ((pg->gaddr & PTE_MASK) == gaddr)
				break;
		if (pg == list_entry(&lg->g2h2M[hash], struct lguest_pg, list))
			return NULL;
	} else {
		/* 4K page */

		/* gaddr has protection bits */
		gaddr &= PTE_MASK;

		hash = HASH_PG(gaddr);
	
		list_for_each_entry(pg, &lg->g2h[hash], list)
			if ((pg->gaddr & PTE_MASK) == gaddr)
				break;
		if (pg == list_entry(&lg->g2h[hash], struct lguest_pg, list))
			return NULL;
	}

	/* update lru */
	list_del(&pg->lru);
	list_add(&pg->lru, &lg->pg_lru);

	return pg;
}

/*
 * Find pg via host address.
 */
static struct lguest_pg *find_hpg(struct lguest *lg, u64 *haddr)
{
	struct lguest_pg *pg;
	int hash = HASH_PG((u64)haddr);
	
	list_for_each_entry(pg, &lg->h2g[hash], hlist) {
		if (pg->haddr == haddr)
			break;
	}
	if (pg == list_entry(&lg->h2g[hash], struct lguest_pg, hlist))
		return NULL;

	return pg;
}

/*
 * Free the pg as well as all of it's references.
 */
static void lguest_free_pg(struct lguest *lg,
			   struct lguest_pgd *pgd,
			   struct lguest_pg *pg)
{
	struct lguest_pg *lpg;
	u64 *ptr;
	int cnt;
	int i;
	int free_me = 1;

	lgdebug_lprint(LGD_PG_FL, "free_pg %p pgd=%p count=%d haddr=%p gaddr=%llx type=%s\n",
		       pg, pgd, pg->count, pg->haddr, pg->gaddr,
		       str_pg_type(pg->type));
	
	LGUEST_WARN_ON(lg, !pg->haddr, return);

	/* free all the lower copies */
	switch (pg->type) {
	case LGUEST_PG_PUD:
		cnt = PTRS_PER_PUD;
		break;
	case LGUEST_PG_PMD:
		cnt = PTRS_PER_PMD;
		break;
	case LGUEST_PG_PTE:
		cnt = PTRS_PER_PTE;
		break;
	default:
		BUG(); /* ?? */
	}
	ptr = pg->haddr;
	for (i=0; i < cnt; i++) {
		/* This ignores HV PTE pages */
		if (ptr[i] & LGUEST_PAGE_PRESENT) {

			if (pg->type == LGUEST_PG_PTE) {
				/* We should never get to the HV PTE */
				LGUEST_WARN_ON(lg, ptr[i] & LGUEST_PAGE_HV, return);
				/* release the page */
#if 0
				lgdebug_lprint(LGD_PG_FL, "%s:%d clear ptr %p\n",
					       __FUNCTION__, __LINE__, &ptr[i]);
#endif
				debug_pages_put(ptr[i]);
				clear_pt(ptr[i]);
			} else {
				lpg = find_hpg(lg, __va(ptr[i] & PTE_MASK));
				LGUEST_WARN_ON(lg, !lpg, continue);

				/* This had better be the next page level */
				
				LGUEST_WARN_ON(lg, lpg->type != (pg->type + 1), continue);
#if 0 /* host lookup should be unique */
				/*
				 * If this holds copies, make sure that we
				 * get the one that points to us.
				 */
				if (!list_empty(&pg->copies) && lpg->pgd != pgd) {
					struct lguest_pg *p;
					list_for_each_entry(p, &lpg->copies, copies) {
						if (p->pgd == pgd)
							break;
					}
					lpg = p;

				}
				if (lpg->pgd != pgd) {
					printk("haddr=%llx pg=%p lpg=%p pgd=%p lpgd=%p\n",
					       ptr[i], pg, lpg, pgd, lpg->pgd);
					printk(" type = %d\n", pg->type);
					WARN_ON(1);
					kill_guest(lg, "bad paging??");
					continue;
				}
#endif

				/* this should not recurse deep */
				lguest_free_pg(lg, pgd, lpg);
				lgdebug_lprint(LGD_PG_FL, "%s:%d clear ptr %p\n",
					       __FUNCTION__,  __LINE__, &ptr[i]);
				clear_pt(ptr[i]);
			}
		} else
			LGUEST_WARN_ON(lg, (ptr[i] & _PAGE_PRESENT) &&
				       !(ptr[i] & LGUEST_PAGE_HV), return);

		if (ptr[i] & LGUEST_PAGE_HV)
			free_me = 0;
	}
	/*
	 * We need to keep this pg around since other VCPUS might
	 * be referencing it.
	 * Although it is pretty much empty.
	 */
	if (!(--pg->count)) {
		lgdebug_lprint(LGD_PG_FL, "actually freeing pg %p\n", pg);
		list_del(&pg->list);
		list_del(&pg->hlist);
		list_del(&pg->lru);
		list_del(&pg->copies);
		if (free_me)
			free_pt_page(pg->haddr);
		lg->nr_pgs--;
		kfree(pg);
	}
}

static void set_haddr(u64 *haddr, u64 val, u64 prot)
{
	int tm = prot & _PAGE_PSE;

	prot = lguest_set_pgprot(prot);
		
	if (tm)
		prot |= LGUEST_PAGE_2M;

	lgdebug_lprint(LGD_PG_FL, "set ptr %p to %llx\n", haddr, val);
	set_pt(*haddr, (val & PTE_MASK) | prot);
}

static struct lguest_pg * lguest_alloc_pg(struct lg_cpu *cpu,
					  u64 *haddr, u64 *ptr,
					  unsigned long val)
{
	struct lguest *lg = cpu->lg;
	unsigned long ghash;
	unsigned long hhash;
	struct lguest_pg *pg;

	/* FIXME: make a cache for this */
	pg = kzalloc(sizeof(*pg), GFP_KERNEL);
	if (!pg)
		return NULL;

	pg->count = 1;

	if (!haddr) {
		haddr = get_pt_page();
		if (!haddr)
			goto out;
		set_haddr(ptr, __pa(haddr), val);
	} else {
#if EXPENSIVE_TESTS
		LGUEST_WARN_ON_DUMP(cpu, find_hpg(lg, __va(*ptr & PTE_MASK)), goto out);
#endif
		/* Flag it as mapped */
		*ptr |= LGUEST_PAGE_PRESENT;
	}

	LGUEST_WARN_ON_DUMP(cpu, (u64)haddr & (PAGE_SIZE-1), goto out);

	pg->haddr = haddr;
	pg->gaddr = val; /* ok to keep flags */
	pg->pgd = cpu->pgd;

#if EXPENSIVE_TESTS
	/* only one haddr is allowed per pg */
	LGUEST_WARN_ON_DUMP(cpu, find_hpg(lg, pg->haddr), return NULL);
#endif

	/* Now add the mapping between the host page and the guest */
	if (val & _PAGE_PSE) {
		ghash = HASH_PG2M(val & PTE_MASK);
		list_add(&pg->list, &lg->g2h2M[ghash]);
	} else {
		ghash = HASH_PG(val & PTE_MASK);
		list_add(&pg->list, &lg->g2h[ghash]);
	}
	hhash = HASH_PG((u64)haddr);

	lgdebug_lprint(LGD_PG_FL, "new pg %p pgd: %p haddr %p hash %ld\n",
		       pg, cpu->pgd, haddr, hhash);

	list_add(&pg->hlist, &lg->h2g[hhash]);
	list_add(&pg->lru, &lg->pg_lru);
	INIT_LIST_HEAD(&pg->copies);
	lg->nr_pgs++;

	return pg;
out:
	kfree(pg);
	return NULL;
}

static u64* lguest_map_pud(struct lg_cpu *cpu,
			   u64 *pgd,
			   unsigned long val)
{
	struct lguest_pg *pg;
	u64 *haddr = NULL;

	/*
	 * Tricky! We always map in the PUD and PMD of the HV but
	 * that may also be used by the guest, which it was not
	 * mapped in for, and thus, we have no page tables for
	 * it. So we need to check for that.
	 */
	if (*pgd & _PAGE_PRESENT) {
		/* Aha! this is paged in, but not mapped yet. */
		LGUEST_WARN_ON_DUMP(cpu, !(*pgd & LGUEST_PAGE_HV), );
		haddr = __va(*pgd & PTE_MASK);
	}

	pg = lguest_alloc_pg(cpu, haddr, pgd, val);
	if (!pg)
		return NULL;

	pg->type = LGUEST_PG_PUD;

	return pg->haddr;
}

static u64* lguest_map_pmd(struct lg_cpu *cpu,
			   u64 *pud,
			   unsigned long val)
{
	struct lguest_pg *pg;
	u64 *haddr = NULL;

	if (*pud & _PAGE_PRESENT) {
		/* Better be a HV page */
		LGUEST_WARN_ON_DUMP(cpu, !(*pud & LGUEST_PAGE_HV), );
		/* Aha! this is paged in, but not mapped yet. */
		haddr = __va(*pud & PTE_MASK);
	}

	pg = lguest_alloc_pg(cpu, haddr, pud, val);
	if (!pg)
		return NULL;

	pg->type = LGUEST_PG_PMD;

	return pg->haddr;
}

static u64* lguest_map_pte(struct lg_cpu *cpu,
			   u64 *pmd,
			   unsigned long val)
{
	struct lguest_pg *pg;

	/* The HV does not share pte's */
	if (unlikely(*pmd & _PAGE_PRESENT)) {
		printk("PMD present not expected pmd=%p *pmd=%llx\n",
		       pmd, *pmd);
		pg = find_hpg(cpu->lg, __va(*pmd & PTE_MASK));
		if (pg) {
			printk("*pmd pg found?? %p haddr=%p gaddr=%llx pgd=%p\n",
			       pg, pg->haddr, pg->gaddr, pg->pgd);
		}
		kill_guest_dump(cpu, "bad pmd?");
		return NULL;
	}

	pg = lguest_alloc_pg(cpu, NULL, pmd, val);
	if (!pg)
		return NULL;

	pg->type = LGUEST_PG_PTE;

	/* Mark it if this is a 2M representation */
	if (val & _PAGE_PSE)
		*pmd |= LGUEST_PAGE_2M;

	return pg->haddr;
}

static struct lguest_pg *dup_pg(struct lg_cpu *cpu,
				struct lguest_pg *pg,
				u64 *ptr)
{
	struct lguest_pg *dpg;
	
	lgdebug_lprint(1|LGD_PG_FL, "DUPPING!!!!!! pg=%p ptr=%p\n", pg, ptr);
	LGUEST_WARN_ON_DUMP(cpu, pg->count > 1, return NULL);

	dpg = lguest_alloc_pg(cpu, __va(*ptr & PTE_MASK), ptr, pg->gaddr);
	if (!dpg)
		return NULL;

	*ptr |= LGUEST_PAGE_PRESENT;

	dpg->type = pg->type;
	
	list_add(&dpg->copies, &pg->copies);

	return dpg;
}

static u64 *map_pg_to_haddr(struct lg_cpu *cpu,
			    struct lguest_pg *pg,
			    u64 *ptr,
			    u64 val)
{
	if (!(*ptr & LGUEST_PAGE_PRESENT)) {
		/*
		 * The page mapping already exists under another
		 * vcpu. But it is not mapped here. If this page
		 * also contains the HV, then we make a copy
		 * to the page.
		 */
		if (*ptr & _PAGE_PRESENT) {
			LGUEST_WARN_ON_DUMP(cpu, !(*ptr & LGUEST_PAGE_HV), return NULL);
			pg = dup_pg(cpu, pg, ptr);
		} else {
			/* just set it to what the host address was mapped to */
			set_haddr(ptr, __pa(pg->haddr), val);
			pg->count++;
			lgdebug_lprint(LGD_PG_FL,
				       "pg=%p count=%d ptr=%p *ptr=%llx\n",
				       pg, pg->count, ptr, *ptr);
		}
	} else if (*ptr & LGUEST_PAGE_HV) {
#if EXPENSIVE_TESTS
		struct lguest_pg *lpg;

		/* make sure that all the copies make sense. */
		list_for_each_entry(lpg, &pg->copies, copies)
			LGUEST_WARN_ON_DUMP(cpu, pg->gaddr != lpg->gaddr, return NULL);
#endif
		   /* The pointers had better be the same. */
	} else if (unlikely(__pa(pg->haddr) != (*ptr & PTE_MASK))) {
		lgdebug_lprint(LGD_PG_FL, "pg->haddr=%lx  *ptr=%llx\n",__pa(pg->haddr), *ptr);
		LGUEST_WARN_ON_DUMP(cpu, 1, return NULL);
	}

	return __va(*ptr & PTE_MASK);
}

#if 0
static int lguest_map_pg(struct lg_cpu *cpu,
			 u64 *ptr,
			 u64 gaddr,
			 u64 val,
			 enum lguest_pg_type type)
{
	struct lguest *lg = cpu->lg;
	struct lguest_pg *pg;
	u64 *p = NULL;
	u64 gud = val & PTE_MASK;

	lgwrite_u64(cpu, gaddr, val);

	pg = find_pg(lg, gud);
	if (pg) {
		LGUEST_WARN_ON_DUMP(cpu, pg->type != type, return -1);
		p = map_pg_to_haddr(cpu, pg, ptr, val);
	} else {
		switch (type) {
		case LGUEST_PG_PUD:
			p = lguest_map_pud(cpu, ptr, val);
			break;
		case LGUEST_PG_PMD:
			p = lguest_map_pmd(cpu, ptr, val);
			break;
		case LGUEST_PG_PTE:
			p = lguest_map_pte(cpu, ptr, val);
			break;
		default:
			kill_guest_dump(cpu, "Unknow type??");
			return -1;
		}
		LGUEST_WARN_ON_DUMP(cpu, !p, return -1);
	}

	cpu->lg_cpu_data->page_set = 1;

	return 0;
}
#endif

/* FIXME: We hold reference to pages, which prevents them from being
   swapped.  It'd be nice to have a callback when Linux wants to swap out. */

/* We fault pages in, which allows us to update accessed/dirty bits.
 * Return 0 if failed, 1 if good */

static int page_in(struct lg_cpu *cpu, u64 vaddr, int flags)
{
	struct lguest *lg = cpu->lg;
	u64 pgprot;
	u64 val;
	u64 paddr;
	int write;
	int ret = 0;
	struct lguest_pgd *pgd;
	struct lguest_pg *pg;
	u64 *gcr3, *hcr3;
	u64 *gpgd, *hpgd;
	u64 *gpud, *hpud;
	u64 *gpmd, *hpmd;
	u64 *gpte, *hpte;
	unsigned idx;

	lgdebug_lprint(LGD_PG_FL, "\nvaddr=%llx pgd=%p rip=%llx\n",
		       vaddr, cpu->pgd, cpu->regs->rip);
	/* If vaddr is a HV page, then kill the guest */
	if (contains_hv_page(vaddr, 1)) {
		printk("hv start: %lx  end: %lx rip=%llx\n",
		       lguest_hv_start, lguest_hv_start + lguest_hv_size, cpu->regs->rip);
		printk("vaddr=%llx  flags=%d (%s)\n",
		       vaddr, flags, flags & _PAGE_DIRTY ? "write":"read");
		if (0) /* don't kill it, just send a fault */
			kill_guest_dump(cpu, "Guest mapping HV page %llx\n",vaddr);
		return 0;
	}

	LGUEST_WARN_ON_DUMP(cpu, !is_canonical(vaddr), return 0);

	mutex_lock(&lg->page_lock);

	pgd = cpu->pgd;

	idx = pgd_index(vaddr);

	gcr3 = (u64*)pgd->gcr3;
	hcr3 = pgd->hcr3;
	lgdebug_lprint(LGD_PG_FL, "gcr3=%p  hcr3=%p\n", gcr3, hcr3);

	gpgd = gcr3 + idx;
	hpgd = hcr3 + idx;
	lgdebug_lprint(LGD_PG_FL, "gpgd=%p  hpgd=%p\n", gpgd, hpgd);

	/* look into the guest and find the pgd index */
	val = lgread_u64(lg, (u64)gpgd);
	lgdebug_lprint(LGD_PG_FL, "val=%llx\n", val);

	/* if the pgd is not present then we are done (fault to guest) */
	if (!(val & _PAGE_PRESENT))
		goto out;

	/* Mark accessed */
	if (!(val & _PAGE_ACCESSED)) {
		val |= _PAGE_ACCESSED;
		lgwrite_u64(lg, (u64)gpgd, val);
	}
	
	/* See if a shadow page already exists for the PUD */
	pg = find_pg(lg, val);
	lgdebug_lprint(LGD_PG_FL, "pg=%p\n",pg);

	LGUEST_WARN_ON_DUMP(cpu, (*hpgd & LGUEST_PAGE_PRESENT) && !pg, goto out);

	if (pg) {
		LGUEST_WARN_ON_DUMP(cpu, pg->type != LGUEST_PG_PUD, goto out);
		hpud = map_pg_to_haddr(cpu, pg, hpgd, val);
	} else
		hpud = lguest_map_pud(cpu, hpgd, val);
	lgdebug_lprint(LGD_PG_FL, "hpud=%p *hpgd=%llx\n", hpud, *hpgd);

	LGUEST_WARN_ON_DUMP(cpu, !hpud, goto out);

	/* do the same for the PUD */
	gpud = (u64*)(val & PTE_MASK);

	gpud += pud_index(vaddr);
	hpud += pud_index(vaddr);
	lgdebug_lprint(LGD_PG_FL, "gpud=%p  hpud=%p\n", gpud, hpud);

	/* Next see if the gpud exists */
	val = lgread_u64(lg, (u64)gpud);
	lgdebug_lprint(LGD_PG_FL, "val=%llx\n", val);

	if (!(val & _PAGE_PRESENT))
		goto out;

	/* Mark accessed */
	if (!(val & _PAGE_ACCESSED)) {
		val |= _PAGE_ACCESSED;
		lgwrite_u64(lg, (u64)gpud, val);
	}
	
	pg = find_pg(lg, val);
	lgdebug_lprint(LGD_PG_FL, "pg=%p\n",pg);

	LGUEST_WARN_ON_DUMP(cpu, (*hpud & LGUEST_PAGE_PRESENT) && !pg, goto out);

	if (pg) {
		LGUEST_WARN_ON_DUMP(cpu, pg->type != LGUEST_PG_PMD, goto out);
		hpmd = map_pg_to_haddr(cpu, pg, hpud, val);
	} else
		hpmd = lguest_map_pmd(cpu, hpud, val);
	lgdebug_lprint(LGD_PG_FL, "hpmd=%p *hpud=%llx\n", hpmd, *hpud);

	gpmd = (u64*)(val & PTE_MASK);

	gpmd += pmd_index(vaddr);
	hpmd += pmd_index(vaddr);
	lgdebug_lprint(LGD_PG_FL, "gpmd=%p  hpmd=%p\n", gpmd, hpmd);

	val = lgread_u64(lg, (u64)gpmd);
	lgdebug_lprint(LGD_PG_FL, "val=%llx\n", val);

	if (!(val & _PAGE_PRESENT))
		goto out;

	/* Mark accessed */
	if (!(val & _PAGE_ACCESSED)) {
		val |= _PAGE_ACCESSED;
		lgwrite_u64(lg, (u64)gpmd, val);
	}
	
	/*
	 * This is the tricky part! The guest can have 2M pages
	 * mapped here, but the host will only map 4K pages.
	 * But we still need to handle this through the hashes.
	 */
	if (val & _PAGE_PSE) {
		/* 2M pages */
		lgdebug_lprint(LGD_PG_FL, "2Megs\n");

		/* The HV region is 2 Megs itself. */
		LGUEST_WARN_ON_DUMP(cpu, *hpmd & LGUEST_PAGE_HV, goto out);
		/*
		 * Now calculate the address for the physical page of the guest
		 * within the 2 Megs.
		 */
		paddr = val + (pte_index(vaddr) << PAGE_SHIFT);

		/* no need to handle gpte */
	} else {
		/* 4K pages */

		/* keep val around, but get the gte page */
		gpte = (u64*)(val & PTE_MASK);
		lgdebug_lprint(LGD_PG_FL, "gpte=%p\n", gpte);

		gpte += pte_index(vaddr);

		paddr = lgread_u64(lg, (u64)gpte);

		if (!(paddr & _PAGE_PRESENT))
			goto out;

		/* Mark accessed */
		if (!(paddr & _PAGE_ACCESSED)) {
			paddr |= _PAGE_ACCESSED;
			lgwrite_u64(lg, (u64)gpte, paddr);
		}

	}
	if (((paddr & PTE_MASK)>>PAGE_SHIFT) > lg->pfn_limit) {
		kill_guest_dump(cpu, "accessing page %lld over limit %lld\n",
				(paddr&PTE_MASK)>>PAGE_SHIFT, lg->pfn_limit);
		goto out;
	}

	lgdebug_lprint(LGD_PG_FL, "val=%llx paddr=%llx\n", val, paddr);

	/* check read write permissions */
	if ((flags & _PAGE_DIRTY) && !(paddr & _PAGE_RW))
		goto out;

	pg = find_pg(lg, val);
	lgdebug_lprint(LGD_PG_FL, "pg=%p *hpmd=%llx\n", pg, *hpmd);

	if (pg) {
		LGUEST_WARN_ON_DUMP(cpu, pg->type != LGUEST_PG_PTE, goto out);
		if (!(*hpmd & _PAGE_PRESENT)) {
			set_haddr(hpmd, __pa(pg->haddr), val);
			pg->count++;
			lgdebug_lprint(LGD_PG_FL,
				       "pg=%p count=%d hpmd=%p *hpmd=%llx\n",
				       pg, pg->count, hpmd, *hpmd);
		} else
			LGUEST_WARN_ON_DUMP(cpu,
					    __va(*hpmd & PTE_MASK) != pg->haddr,
					    goto out);
		/*
		 * Just get it from the pmd.
		 */
		hpte = __va(*hpmd & PTE_MASK);
	} else
		hpte = lguest_map_pte(cpu, hpmd, val);

	/*
	 * At this point, hpte points to the bottom of
	 * the host PTE table, and paddr is the value of
	 * the guest page (with pgprot bits) to map.
	 */

	hpte += pte_index(vaddr);
	lgdebug_lprint(LGD_PG_FL, "hpte=%p *hpmd=%llx\n", hpte, *hpmd);

	lgdebug_lprint(LGD_PG_FL, "paddr=%llx\n", paddr);

	pgprot = lguest_set_pgprot(paddr);

	paddr &= PTE_MASK;

	/*
	 * FIXME: if this isn't write, we lose the lguest_data when we do
	 *  a put_user in the hypercall init.
	 */
	write = 1; // val & _PAGE_DIRTY ? 1 : 0;

	/* get the real physical mapping of the guest page */
	val = get_pfn(paddr >> PAGE_SHIFT, write);
	if (val == (unsigned long)-1UL) {
		printk("bad 1\n");
		kill_guest_dump(cpu, "page %llx not mapped", paddr);
		goto out;
	}

	/* now we have the actual paddr */
	val <<= PAGE_SHIFT;

	/* if we already have a page in, then free it */
	if (*hpte & _PAGE_PRESENT)
		debug_pages_put(*hpte);

	/*
	 * We have the host pte and the actual address.
	 * Now we just point the host pte to the paddr with the
	 * proper permissions.
	 *
	 * (easier said than done)
	 */
	set_pt(*hpte, val | pgprot);
	lgdebug_lprint(LGD_PG_FL, "set pte %p set to %llx\n", hpte, *hpte);

	/* let the caller know, we mapped the page */
	ret = 1;

out:
	lgdebug_lprint(LGD_PG_FL, "%s\n", ret ? "handled" : "FAULT");

	/*
	 * If this is a fault to the kernel, test to see if we
	 * are not in an infinite loop of faulting!
	 */
	if (ret || (cpu->regs->cs & 3) == 3)
		/* All is ok, we handled it or it's user space */
		cpu->lg_cpu_data->last_pgd = NULL;
	else {
		if ((cpu->lg_cpu_data->last_pgd == cpu->pgd) &&
		    (cpu->lg_cpu_data->last_rip == cpu->regs->rip) &&
		    (cpu->lg_cpu_data->last_vaddr == vaddr))
			/* FIXME: send double fault to guest instead */
			kill_guest_dump(cpu, "double fault at %llx RIP: %llx",
					vaddr, cpu->lg_cpu_data->last_rip);
		else {
			cpu->lg_cpu_data->last_pgd = cpu->pgd;
			cpu->lg_cpu_data->last_rip = cpu->regs->rip;
			cpu->lg_cpu_data->last_vaddr = vaddr;
		}
	}

	if (ret)
		lg->stat_mappings++;
	else
		lg->stat_guest_faults++;

	mutex_unlock(&lg->page_lock);

	return ret;
}

int demand_page(struct lg_cpu *cpu, u64 vaddr, int write)
{
	int ret;
	lguest_stat_start_pagefault(cpu);
	ret = page_in(cpu, vaddr, (write ? _PAGE_DIRTY : 0)|_PAGE_ACCESSED);
	lguest_stat_end_pagefault(cpu);
	return ret;
}


static void clear_pg(struct lguest *lg,
		     u64 *ptr, enum lguest_pg_type type)
{
	struct lguest_pg *pg;

	if (*ptr & LGUEST_PAGE_PRESENT) {
		lgdebug_lprint(LGD_PG_FL, "clear_pg ptr=%p *ptr=%llx\n",
			       ptr, *ptr);
		pg = find_hpg(lg, __va(*ptr & PTE_MASK));
		LGUEST_WARN_ON(lg, !pg, return);
		LGUEST_WARN_ON(lg, pg->type != type, return);
		if (lguest_debug & LGD_PG_FL)
			printk("   pg type = %s  pgd: %p\n",
			       str_pg_type(pg->type), pg->pgd);
		lguest_free_pg(lg, pg->pgd, pg);
		clear_pt(*ptr);
	}
}

void guest_set_pgd(struct lg_cpu *cpu,
		   unsigned long gaddr,
		   unsigned long val)
{
	struct lguest *lg = cpu->lg;
	struct lguest_pgd *pgd;
	u64 gcr3 = gaddr & PTE_MASK;
	unsigned long idx = (gaddr & (PAGE_SIZE-1)) / 8;
	int i;

	mutex_lock(&lg->page_lock);

	lgdebug_lprint(LGD_PG_FL, "%s: addr=%lx val=%lx idx=%ld\n",
		       __FUNCTION__, gaddr, val, idx);

	for (i=0; i < lg->nr_pgds; i++) {
		pgd = &lg->pgds[i];

		if (pgd->hcr3 &&
		    (pgd->gcr3 == gcr3 || idx >= pgd_index(lg->page_offset)))
			clear_pg(lg, pgd->hcr3 + idx,
				LGUEST_PG_PUD);
	}

	/*
	 * To avoid race conditions with setting of the pgd,
	 * set it here for the guest.
	 */
	lgwrite_u64(lg, gaddr, val);
	/* Let the guest know we did so */
	lguest_data_set_bit(PGSET, cpu->lg_cpu_data);

	mutex_unlock(&lg->page_lock);
}

#define cmp_gaddr(a, b) (((a)->gaddr & PTE_MASK) == ((b)->gaddr & PTE_MASK))

void guest_set_pud(struct lg_cpu *cpu,
		   unsigned long gaddr,
		   unsigned long val)
{
	struct lguest *lg = cpu->lg;
	struct lguest_pg *pg;
	struct lguest_pg *lpg;
	u64 gpud = gaddr & PTE_MASK;
	unsigned long idx = (gaddr & (PAGE_SIZE-1)) / 8;
	u64 *hpud;

	mutex_lock(&lg->page_lock);

	pg = find_pg(lg, gpud);
	if (!pg)
		goto out;

	lgdebug_lprint(LGD_PG_FL, "%s: addr=%lx val=%lx\n",
		       __FUNCTION__, gaddr, val);

	if (unlikely(pg->type != LGUEST_PG_PUD)) {
		u64 paddr;
		int i;
		printk("PUD pg->type=%d idx=%ld\n", pg->type, idx);
		printk("pg->haddr=%p gaddr=%llx\n", pg->haddr, pg->gaddr);
		lpg = find_hpg(lg, pg->haddr);
		if (lpg != pg)
			printk("lpg=%p pg=%p!!!\n", lpg, pg);
		paddr = lgread_u64(lg, gaddr);
		printk("old val=%llx\n", paddr);
		for (i=0; i < lg->nr_pgds; i++) {
			if (pg->pgd == &lg->pgds[i]) {
				printk("found pgd %p for pg\n",
				       pg->pgd);
				printk("Shadow page tables of %p\n", pg->pgd);
				lguest_print_page_tables(pg->pgd->hcr3);
				printk("\nGuest page tables of %p\n", pg->pgd);
				lguest_print_guest_page_tables(cpu, pg->pgd->gcr3);
				break;
			}
		}
		if (i==lg->nr_pgds)
			printk("could not find pgd %p for pg\n",
			       pg->pgd);
	}
	LGUEST_WARN_ON_DUMP(cpu, pg->type != LGUEST_PG_PUD, goto out);

	hpud = pg->haddr;
	hpud += idx;

	/* Always handle the copies. */
	list_for_each_entry(lpg, &pg->copies, copies) {
		LGUEST_WARN_ON_DUMP(cpu, !cmp_gaddr(pg, lpg), goto out);
		clear_pg(lg, lpg->haddr + idx, LGUEST_PG_PMD);
	}

	if (!(*hpud & _PAGE_PRESENT))
		goto out;

	clear_pg(lg, hpud, LGUEST_PG_PMD);

	/*
	 * To avoid race conditions with setting of the pud,
	 * set it here for the guest.
	 */
	lgwrite_u64(lg, gaddr, val);
	/* Let the guest know we did so */
	lguest_data_set_bit(PGSET, cpu->lg_cpu_data);

out:
	mutex_unlock(&lg->page_lock);
}

void guest_set_pmd(struct lg_cpu *cpu,
		   unsigned long gaddr,
		   unsigned long val)
{
	struct lguest *lg = cpu->lg;
	struct lguest_pg *pg;
	struct lguest_pg *lpg;
	u64 gpmd = gaddr & PTE_MASK;
	unsigned long idx = (gaddr & (PAGE_SIZE-1)) / 8;
	u64 *hpmd;

	mutex_lock(&lg->page_lock);

	pg = find_pg(lg, gpmd | (val & _PAGE_PSE));
	if (!pg)
		goto out;

	lgdebug_lprint(LGD_PG_FL, "%s: addr=%lx val=%lx\n",
		       __FUNCTION__, gaddr, val);

	if (unlikely(pg->type != LGUEST_PG_PMD)) {
		u64 paddr;
		int i;
		printk("PMD pg->type=%d idx=%ld\n", pg->type, idx);
		printk("pg->haddr=%p gaddr=%llx\n", pg->haddr, pg->gaddr);
		lpg = find_hpg(lg, pg->haddr);
		if (lpg != pg)
			printk("lpg=%p pg=%p!!!\n", lpg, pg);
		paddr = lgread_u64(lg, gaddr);
		printk("old val=%llx\n", paddr);
		for (i=0; i < lg->nr_pgds; i++) {
			if (pg->pgd == &lg->pgds[i]) {
				printk("found pgd %p for pg\n",
				       pg->pgd);
				printk("Shadow page tables of %p\n", pg->pgd);
				lguest_print_page_tables(pg->pgd->hcr3);
				printk("\nGuest page tables of %p\n", pg->pgd);
				lguest_print_guest_page_tables(cpu, pg->pgd->gcr3);
				break;
			}
		}
		if (i==lg->nr_pgds)
			printk("could not find pgd %p for pg\n",
			       pg->pgd);
	}
	LGUEST_WARN_ON_DUMP(cpu, pg->type != LGUEST_PG_PMD, goto out);

	hpmd = pg->haddr;
	hpmd += idx;

	/* Always handle the copies. */
	list_for_each_entry(lpg, &pg->copies, copies) {
		LGUEST_WARN_ON_DUMP(cpu, !cmp_gaddr(pg, lpg), goto out);
		clear_pg(lg, lpg->haddr + idx, LGUEST_PG_PTE);
	}

	if (!(*hpmd & _PAGE_PRESENT))
		goto out;

	clear_pg(lg, hpmd, LGUEST_PG_PTE);

	/*
	 * To avoid race conditions with setting of the pmd,
	 * set it here for the guest.
	 */
	lgwrite_u64(lg, gaddr, val);
	/* Let the guest know we did so */
	lguest_data_set_bit(PGSET, cpu->lg_cpu_data);

out:
	mutex_unlock(&lg->page_lock);
}

static void __guest_set_pte(struct lg_cpu *cpu,
			    unsigned long gaddr,
			    unsigned long val)
{
	struct lguest *lg = cpu->lg;
	struct lguest_pg *pg;
	u64 gpte = gaddr & PTE_MASK;
	unsigned long idx = (gaddr & (PAGE_SIZE-1)) / 8;
	u64 *hpte;
	u64 paddr;
	int pgprot;
	int write;

	mutex_lock(&lg->page_lock);

	pg = find_pg(lg, gpte);
	if (!pg)
		goto out;

	lgdebug_lprint(LGD_PG_FL, "%s: addr=%lx val=%lx\n",
		       __FUNCTION__, gaddr, val);

	/* This might be a PMD */
	if (pg->type == LGUEST_PG_PMD) {
		mutex_unlock(&lg->page_lock);
		guest_set_pmd(cpu, gaddr, val);
		return;
	}

	LGUEST_WARN_ON_DUMP(cpu, pg->type != LGUEST_PG_PTE, goto out);

	hpte= pg->haddr;
	hpte += idx;

	if (!(*hpte & _PAGE_PRESENT))
		goto out;

	if (unlikely(*hpte & LGUEST_PAGE_HV)) {
		kill_guest_dump(cpu, "guest freeing HV page??");
		goto out;
	}

	lgdebug_lprint(LGD_PG_FL, "%s: %d clear pte %p\n", __FUNCTION__, __LINE__, hpte);
	debug_pages_put(*hpte);
	clear_pt(*hpte);

	/* Need a way to set accessed and dirty pages, must fault in */
	goto out;

	/* Now find the actual physical addr for this page */

	/* FIXME: Do something about this WRITE!!! (could just be legacy) */
	write = 1; // val & _PAGE_DIRTY ? 1 : 0;

	pgprot = lguest_set_pgprot(val);
	paddr = val & PTE_MASK;

	/* get the real physical mapping of the guest page */
	paddr = get_pfn(paddr >> PAGE_SHIFT, write);
	if (paddr == (unsigned long)-1UL) {
		kill_guest_dump(cpu, "page %lx not mapped", val);
		goto out;
	}

	/* now we have the actual paddr */
	paddr <<= PAGE_SHIFT;

	set_pt(*hpte, paddr | pgprot);

	lgdebug_lprint(LGD_PG_FL, "set pte %p set to %llx\n", hpte, *hpte);

	/*
	 * To avoid race conditions with setting of the pte,
	 * set it here for the guest.
	 */
	lgwrite_u64(lg, gaddr, val);
	/* Let the guest know we did so */
	lguest_data_set_bit(PGSET, cpu->lg_cpu_data);

out:
	mutex_unlock(&lg->page_lock);
}

void guest_set_pte(struct lg_cpu *cpu,
		   unsigned long gaddr,
		   unsigned long val)
{
	__guest_set_pte(cpu, gaddr, val);
}

void guest_flush_tlb_single(struct lg_cpu *cpu, u64 gaddr)
{
	/*
	 * This is currently broken. The address passed in is
	 * _not_ the pointer to the pte, but it is a pointer to
	 * the address the pte points to.
	 *
	 * Since all paravirt writes to the pte should go through
	 * to the HV, then we really don't need the single flush
	 * (I hope). -SDR
	 */
	return;
	/* set_pte just clears the table, use it instead */
	__guest_set_pte(cpu, gaddr, 0);
}

/*
 * release_pgd - release all mapped pages.
 */
static void release_pgd(struct lguest *lg, struct lguest_pgd *pgd)
{
	u64 *pud;
	int i;

	if (!pgd->hcr3)
		return;

	lgdebug_lprint(LGD_PG_FL, "release_pgd %p vcpu=%p hcr3=%p gcr3=%llx\n",
		       pgd, pgd->cpu, pgd->hcr3, pgd->gcr3);
	pud = pgd->hcr3;

	for (i=0; i < PTRS_PER_PGD; i++)
		clear_pg(lg, pud + i, LGUEST_PG_PUD);
}

/*
 * destroy_pgd - like release_pgd, but frees even the HV pages!
 */
static void destroy_pgd(struct lguest *lg, struct lguest_pgd *pgd)
{
	u64 *pud;
	u64 *pmd;
	int i;

	if (!pgd->hcr3)
		return;

	lgdebug_lprint(LGD_PG_FL, "destroy_pgd %p vcpu=%p hcr3=%p gcr3=%llx\n",
		       pgd, pgd->cpu, pgd->hcr3, pgd->gcr3);
	pud = pgd->hcr3;

	for (i=0; i < PTRS_PER_PGD; i++)
		clear_pg(lg, pud + i, LGUEST_PG_PUD);

	/* Now blow away the HV pages */
	pud = __va(pgd->hcr3[pgd_index(lguest_hv_addr)] & PTE_MASK);
	pmd = __va(pud[pud_index(lguest_hv_addr)] & PTE_MASK);
	/* The PTE points to the VCPU PTE so ignore it */

	free_pt_page(pmd);
	free_pt_page(pud);
	free_pt_page(pgd->hcr3);

	pgd->hcr3 = NULL;
	pgd->gcr3 = 0;
}

void guest_release_pgd(struct lg_cpu *cpu, u64 gaddr)
{
	struct lguest *lg = cpu->lg;
	struct lguest_pgd *pgd;
	u64 gcr3 = gaddr & PTE_MASK;
	int i;

	mutex_lock(&lg->page_lock);

	for (i=0; i < lg->nr_pgds; i++) {
		pgd = &lg->pgds[i];

		if (pgd->hcr3 && pgd->gcr3 == gcr3)
			release_pgd(lg, pgd);
	}
	mutex_unlock(&lg->page_lock);
}

static void __free_user_pages(struct lguest *lg,
			      struct lguest_pgd *pgd)
{
	u64 *pud;
	int i;

	pud = pgd->hcr3;

	for (i=0; i < pgd_index(lg->page_offset); i++)
		clear_pg(lg, pud + i, LGUEST_PG_PUD);
}

void guest_pagetable_flush_user(struct lg_cpu *cpu)
{
	struct lguest *lg = cpu->lg;

	mutex_lock(&lg->page_lock);
	/* FIXME: do we need to worry about copies here? */
	__free_user_pages(lg, cpu->pgd);
	mutex_unlock(&lg->page_lock);
}


static void __guest_pagetable_clear_all(struct lguest *lg)
{
	struct lguest_pgd *pgd;
	int i;

	mutex_lock(&lg->page_lock);

	for (i=0; i < lg->nr_pgds; i++) {
		pgd = &lg->pgds[i];
		release_pgd(lg, pgd);
	}
	mutex_unlock(&lg->page_lock);
}

void guest_pagetable_clear_all(struct lg_cpu *cpu)
{
	__guest_pagetable_clear_all(cpu->lg);
}

static void assign_pgd_vcpu(struct lg_cpu *cpu,
			    struct lguest_pgd *pgd)
{
	struct lguest *lg = cpu->lg;
	u64 *pud;
	u64 *pmd;
	int idx;

	pgd->cpu = cpu;

	/* update the HV for this VCPU. */
	idx = pgd_index(lguest_hv_addr);
	pud = __va(pgd->hcr3[idx] & PTE_MASK);
	idx = pud_index(lguest_hv_addr);
	pmd = __va(pud[idx] & PTE_MASK);
	idx = pmd_index(lguest_hv_addr);
	set_pt(pmd[idx], __pa(cpu->hv_pte) | LGUEST_HV_PG_PROT);
	lgdebug_lprint(LGD_PG_FL, "%s: set pmd %p to %llx\n",
		       __FUNCTION__, &pmd[idx], pmd[idx]);

	/* now a resently used pgd */

	if (likely(cpu->pgd)) {
		cpu->pgd->flags &= ~LGUEST_PGD_BUSY_FL;
		list_add(&cpu->pgd->lru, &lg->pgd_lru);
	}
	list_del_init(&pgd->lru);
	cpu->pgd = pgd;
	cpu->pgd->flags |= LGUEST_PGD_BUSY_FL;
}

static struct lguest_pgd *allocate_new_pgd(struct lg_cpu *cpu, u64 gcr3)
{
	struct lguest *lg = cpu->lg;
	struct lguest_pgd *pgd;
	int idx;
	u64 *pud;
	u64 *pmd;

	lgdebug_lprint(LGD_PG_FL, "allocate new pgd vcpu=%p oldpgd=%p cr3=%llx\n",
		       cpu, cpu->pgd, gcr3);

	/* if there's still free pgds, use them */
	if (lg->nr_pgds < LGUEST_PGD_SIZE) {
		pgd = &lg->pgds[lg->nr_pgds++];
		LGUEST_WARN_ON_DUMP(cpu, pgd->hcr3, return NULL);

		lgdebug_lprint(LGD_PG_FL, "  new pgd=%p nr_pgds=%d\n",
			       pgd, lg->nr_pgds);

		pgd->hcr3 = get_pt_page();
		if (!pgd->hcr3)
			return NULL;

		/* Initialize the HV pages */
		pud = get_pt_page();
		if (!pud)
			return NULL;
		idx = pgd_index(lguest_hv_addr);
		lgdebug_lprint(LGD_PG_FL, "%s: set pgd %p to %llx\n",
			       __FUNCTION__, &pgd->hcr3[idx], pgd->hcr3[idx]);
		set_pt(pgd->hcr3[idx], __pa(pud) | LGUEST_HV_PG_PROT);

		pmd = get_pt_page();
		if (!pmd)
			return NULL;
		idx = pud_index(lguest_hv_addr);
		set_pt(pud[idx], __pa(pmd) | LGUEST_HV_PG_PROT);
		lgdebug_lprint(LGD_PG_FL, "%s: set pud %p to %llx\n",
			       __FUNCTION__, &pud[idx], pud[idx]);

		INIT_LIST_HEAD(&pgd->lru);
		INIT_LIST_HEAD(&pgd->copies);
		pgd->flags = 0;
		pgd->magic = LGUEST_PGD_MAGIC;

	} else {
		/* take the least resently used */
		pgd = list_entry(lg->pgd_lru.prev, struct lguest_pgd, lru);
		LGUEST_WARN_ON_DUMP(cpu, pgd->flags & LGUEST_PGD_BUSY_FL, return NULL);

		lgdebug_lprint(LGD_PG_FL, "  reuse pgd=%p\n", pgd);

		/* zap all pages */
		release_pgd(lg, pgd);

		/* remove from copies list */
		list_del_init(&pgd->copies);
	}

	assign_pgd_vcpu(cpu, pgd);
	pgd->gcr3 = gcr3;

	return pgd;
}

void guest_new_pagetable(struct lg_cpu *cpu, u64 cr3)
{
	struct lguest *lg = cpu->lg;
	struct lguest_pgd *pgd;
	struct lguest_pgd *lpgd;
	int i;

	/* loading the cr3 with a new page table */

	mutex_lock(&lg->page_lock);

	lgdebug_lprint(LGD_PG_FL, "assign new pgd vcpu=%p oldpgd=%p cr3=%llx\n",
		       cpu, cpu->pgd, cr3);

	/* see if the cr3 already exists. */
	for (i=0; i < lg->nr_pgds; i++) {
		pgd = &lg->pgds[i];
		if (pgd->gcr3 == cr3)
			break;
	}
	if (i == lg->nr_pgds) {
		pgd = allocate_new_pgd(cpu, cr3);
		/* all done */
		goto out;
	}

	if (pgd->cpu != cpu) {
		/* look for the copy */
		list_for_each_entry(lpgd, &pgd->copies, copies) {
			if (lpgd->cpu == cpu)
				break;
		}
		if (lpgd == pgd) {
			/* If the pgd is not busy, then steal it */
			if (!(pgd->flags & LGUEST_PGD_BUSY_FL)) {
				assign_pgd_vcpu(cpu, pgd);
				goto out;
			}
			printk("WHAT THE F*CK!!!\n"); /* UP for now */
			/* Make a new copy */
			lpgd = allocate_new_pgd(cpu, cr3);
			list_add(&lpgd->copies, &pgd->copies);
			goto out;
		}
	}

	/* This pgd already belongs to this vcpu */
	cpu->pgd->flags &= ~LGUEST_PGD_BUSY_FL;
	/* 
	 * Only pgds that are not busy go into the lru list. Otherwise, we
	 * could reuse busy pgds resulting in Bad Things (tm). So, as we can
	 * be loading the same pgd again here, (vcpu->pgd == pgd), we must
	 * be careful to take it out of the list _after_ the addition.
	 * Otherwise, it will still sit in the list.
	 */
	list_add(&cpu->pgd->lru, &lg->pgd_lru);
	list_del_init(&pgd->lru);

	cpu->pgd = pgd;
	cpu->pgd->flags |= LGUEST_PGD_BUSY_FL;

	lgdebug_lprint(LGD_PG_FL, "new pgd=%p\n", pgd);

out:
	mutex_unlock(&lg->page_lock);
}

void lguest_free_guest_pages(struct lguest *lg)
{
	int i;
	struct lguest_pgd *pgd;

	mutex_lock(&lg->page_lock);

	for (i=0; i < lg->nr_pgds; i++) {
		pgd = &lg->pgds[i];
		destroy_pgd(lg, pgd);
	}
	mutex_unlock(&lg->page_lock);

#if DEBUG_PAGES
	{
		int dump = 0;
		printk("checking page use\n");
		if (pages_used) {
			dump = 1;
			printk("LGUEST MEMORY LEAK!!!! (%ld pages not freed)\n",
			       pages_used);
		}
		if (get_pages) {
			printk("LGUEST DID NOT RELEASE ENOUGH PAGES (%ld pages left)\n",
			       get_pages);
			dump = 1;
		}
#if REALLY_DEBUG_PAGES
		{
			struct really_debug_pages *rdp, *t;

			list_for_each_entry_safe(rdp, t, &debugged_pages, list) {
				printk("page %p  from %s:%d\n",
				       rdp->page, rdp->func, rdp->line);
				list_del(&rdp->list);
				kfree(rdp);
			}
		}
#endif /* REALLY_DEBUG_PAGES */
		for (i=0; i < LGUEST_MAP_SIZE; i++) {
			if (!list_empty(&lg->g2h[i])) {
				printk("g2h entry %d not empty!\n", i);
				dump = 1;
			}
			if (!list_empty(&lg->h2g[i])) {
				printk("h2g entry %d not empty!\n", i);
				dump = 1;
			}
		}
		for (i=0; i < LGUEST_2MMAP_SIZE; i++) {
			if (!list_empty(&lg->g2h[i])) {
				printk("g2h2M entry %d not empty!\n", i);
				dump = 1;
			}
		}
		if (dump)
			dump_stack();
	}
#endif /* DEBUG_PAGES */
	mutex_lock(&lguest_vm_lock);
	list_del(&lg->vm_list);
	mutex_unlock(&lguest_vm_lock);

}

int lguest_init_vcpu_pagetable(struct lg_cpu *cpu)
{
	guest_new_pagetable(cpu, cpu->lg->cr3);

	return 0;
}

/**
 * lguest_find_guest_paddr - locate the paddr from the guest virtual tables.
 *  @vcpu - vcpu descriptor.
 *  @addr - the guest vaddr to find the guest paddr from.
 *
 * Searches the guest page tables looking for the paddr that
 * the addr is mapped to.  The paddr that is returned is not
 * a real physical address, but a physical address that the guest
 * thinks.  That is, a return from this can be used for lgread.
 *
 * Returns (u64)-1 if the page can't be found.
 */
u64 lguest_find_guest_paddr(struct lg_cpu *cpu, u64 vaddr)
{
	struct lguest *lg = cpu->lg;
	u64 *gcr3;
	u64 *gpgd;
	u64 *gpud;
	u64 *gpmd;
	u64 *gpte;
	u64 paddr = (u64)-1;
	u64 val;

	mutex_lock(&lg->page_lock);

	gcr3 = (u64*)cpu->pgd->gcr3;
	gpgd = gcr3 + pgd_index(vaddr);

	val = lgread_u64(lg, (u64)gpgd);
	if (!(val & _PAGE_PRESENT))
		goto out;
	
	gpud = (u64*)(val & PTE_MASK);
	gpud += pud_index(vaddr);

	val = lgread_u64(lg, (u64)gpud);
	if (!(val & _PAGE_PRESENT))
		goto out;

	gpmd = (u64*)(val & PTE_MASK);
	gpmd += pmd_index(vaddr);

	val = lgread_u64(lg, (u64)gpmd);
	if (!(val & _PAGE_PRESENT))
		goto out;

	/* The guest might have set up a 2M page */
	if (val & _PAGE_PSE) {
		/* 2M pages */

		/* can still have the NX bit set */
		paddr = val & PMD_MASK & PTE_MASK;
		/* Get the 4k offset */

		paddr += pte_index(vaddr) << PAGE_SHIFT;

	} else {
		/* 4K pages */
		gpte = (u64*)(val & PTE_MASK);
		gpte += pte_index(vaddr);

		val = lgread_u64(lg, (u64)gpte);
		if (!(val & _PAGE_PRESENT))
			goto out;

		/* this is the guest's paddr */
		paddr = val & PTE_MASK;
	}
	paddr += (vaddr & (PAGE_SIZE-1));

out:
	mutex_unlock(&lg->page_lock);

	return paddr;
}

static unsigned long *get_vaddr(unsigned long paddr)
{
	paddr &= PTE_MASK;
	return __va(paddr);
}

unsigned long lguest_get_actual_phys(void *addr, pgprot_t *prot)
{
	unsigned long vaddr;
	unsigned long offset;
	unsigned long cr3;
	unsigned long pgd;
	unsigned long pud;
	unsigned long pmd;
	unsigned long pte;
	unsigned long mask;

	unsigned long *p;

	/*
	 * Travers the page tables to get the actual
	 * physical address. I want this to work for
	 * all addresses, regardless of where they are mapped.
	 */

	/* FIXME: Do this better!! */

	/* grab the start of the page tables */
	asm ("movq %%cr3, %0" : "=r"(cr3));

	p = get_vaddr(cr3);

	offset = pgd_index((unsigned long)addr);

	pgd = p[offset];

	if (!(pgd & _PAGE_PRESENT))
		return 0;

	p = get_vaddr(pgd);

	offset = pud_index((unsigned long)addr);

	pud = p[offset];

	if (!(pud & _PAGE_PRESENT))
		return 0;

	p = get_vaddr(pud);

	offset = pmd_index((unsigned long)addr);

	pmd = p[offset];

	if (!(pmd & _PAGE_PRESENT))
		return 0;

	/* Now check to see if we are 2M pages or 4K pages */
	if (pmd & _PAGE_PSE) {
		/* stop here, we are 2M pages */
		pte = pmd;
		mask = PMD_SIZE-1;
		goto calc;
	}

	p = get_vaddr(pmd);

	offset = pte_index((unsigned long)addr);

	pte = p[offset];
	mask = PAGE_SIZE-1;

 calc:

	if (!(pte & _PAGE_PRESENT))
		return 0;

	vaddr = pte & PTE_MASK;

	if (prot)
		pgprot_val(*prot) = pte & 0xfff;

	offset = (unsigned long)addr & mask;

	vaddr += offset;

	return vaddr;
}


/**** HV MAPPINGS ****/

static inline pud_t *pud_from_vaddr(pgd_t *pgd, unsigned long vaddr)
{
	unsigned long addr = pgd_page_vaddr(*pgd);
	pud_t *pud = (pud_t*)addr;

	return &pud[pud_index(vaddr)];
}

static inline pmd_t *pmd_from_vaddr(pud_t *pud, unsigned long vaddr)
{
	unsigned long addr = pud_page_vaddr(*pud);
	pmd_t *pmd = (pmd_t*)addr;

	return &pmd[pmd_index(vaddr)];
}

static inline pte_t *pte_from_vaddr(pmd_t *pmd, unsigned long vaddr)
{
	unsigned long addr = pmd_page_vaddr(*pmd);
	pte_t *pte = (pte_t*)addr;

	return &pte[pte_index(vaddr)];
}

static void __free_all_pmd(u64 *pmd)
{
	int i;

	for (i=0; i < PTRS_PER_PMD; i++) {
		if (pmd[i] & _PAGE_PRESENT) {
			/* shadow pages never use 2M pages */
			BUG_ON(pmd[i] & _PAGE_PSE);
			pmd[i] &= ~_PAGE_PRESENT;
			free_pt_page(__va(pmd[i] & PTE_MASK));
		}
	}
	free_pt_page(pmd);
}

static void __free_all_pud(u64 *pud)
{
	int i;

	for (i=0; i < PTRS_PER_PUD; i++) {
		if (pud[i] & _PAGE_PRESENT) {
			__free_all_pmd(__va(pud[i] & PTE_MASK));
			pud[i] &= ~_PAGE_PRESENT;
		}
	}
	free_pt_page(pud);
}

/*
 * Does not release mappings, just frees shadow page tables.
 * Nor does this release pages via put_pages.
 */
void lguest_free_all_cr3(u64 *cr3)
{
	int i;
	u64 *pgd = cr3;

	for (i=0; i < PTRS_PER_PGD; i++) {
		if (pgd[i] & _PAGE_PRESENT) {
			__free_all_pud(__va(pgd[i] & PTE_MASK));
			pgd[i] &= ~_PAGE_PRESENT;
		}
	}
	free_pt_page(cr3);
}

static void lguest_pte_map_hv_text(u64 *ptr, int prot)
{
	unsigned long page;
	unsigned long vaddr;
	int idx;
	int i;

	vaddr = lguest_hv_addr;
	for (i=0; i < lguest_hv_pages; i++) {
		page = lguest_get_actual_phys((void*)vaddr+PAGE_SIZE*i, NULL);
		BUG_ON(!page);

		/* Map it in as read only and execute. */
		idx = pte_index(vaddr+PAGE_SIZE*i);
		set_pt(ptr[idx], page | prot);
		lgdebug_lprint(LGD_PG_FL, "%s: map ptr %p to %llx\n",
			       __FUNCTION__, &ptr[idx], ptr[idx]);
	}
}

static void lguest_pte_map_vcpu_data(struct lg_cpu *cpu, u64 *ptr, int prot)
{
	unsigned long page;
	unsigned long vaddr;
	unsigned long daddr;
	int idx;
	int i;

	vaddr = (unsigned long)cpu;
	daddr = lg_cpu_addr;
	for (i=0; i < lg_cpu_pages; i++) {
		/* vcpu is mapped via get_free_pages */
		page = __pa(vaddr + PAGE_SIZE*i);

		/* Map it in as read only and no execute. */
		idx = pte_index(daddr+PAGE_SIZE*i);
		set_pt(ptr[idx], page | prot);
	}
}

static void lguest_pte_map_vcpu_guest_data(struct lg_cpu *cpu, u64 *ptr, int prot)
{
	unsigned long page;
	unsigned long vaddr;
	unsigned long daddr;
	int idx;
	int i;

	vaddr = (unsigned long)cpu->lg_cpu_data;
	daddr = lg_cpu_data_addr;
	for (i=0; i < lg_cpu_data_pages; i++) {
		/* vcpu guest data is mapped via get_free_pages */
		page = __pa(vaddr + PAGE_SIZE*i);

		/* Map it in as read/write and no execute. */
		idx = pte_index(daddr+PAGE_SIZE*i);
		set_pt(ptr[idx], page | prot);
	}

    /*
     * And don't forget about the stack - it will point to
     * regs page
     */
    vaddr = (unsigned long) cpu->regs_page;
    daddr = lg_cpu_regs_addr;
	for (i=0; i < lg_cpu_regs_pages; i++) {
		/* vcpu guest regs is mapped via get_free_pages */
		page = __pa(vaddr + PAGE_SIZE*i);

		/* Map it in as read/write and no execute. */
		idx = pte_index(daddr+PAGE_SIZE*i);
		set_pt(ptr[idx], page | prot);
	}
}

/*
 * Set up the vcpu HV pages. This is interesting. We map three types of pages.
 * The first is the HV text.
 * The next is the HV host data (readable by guest but can't write)
 * Then finally the HV guest data. This is writable by the guest
 *  and is used for the guest stack.
 *
 * When we are using the guest CR3, then we can't write to the HV Data either
 * even in ring 0. But once we switch to the host CR3 then we can.
 *
 * Since all the above HV pages fit inside one PTE table, we only need to
 * allocate that. And when we switch CR3s, we just point it to the VCPU
 * HV cr3.
 */
int lguest_map_guest_vcpu(struct lg_cpu *cpu)
{
	u64 *ptr;

	/*
	 * Here's where the fun begins.  The VCPU will take care
	 * of its own HV page tables. This means that the HV must
	 * fit in the 2 megs of a PMD. Each VCPU will have it's own
	 * PMD that holds the VCPU data, guest data and the HV text.
	 */

	cpu->hv_pte = get_pt_page();
	if (!cpu->hv_pte)
		return -ENOMEM;

	ptr = cpu->hv_pte;

	/* first map the HV text */
	lguest_pte_map_hv_text(ptr, LGUEST_HV_EXEC_PROT);

	/* Next map the vcpu struct into its pages */
	lguest_pte_map_vcpu_data(cpu, ptr, LGUEST_HV_DATA_PROT);

	/* Last, make a guest data that the guest can write in */
	lguest_pte_map_vcpu_guest_data(cpu, ptr, LGUEST_HV_VCPU_DATA_PROT);

	return 0;
}

/*
 * Reverse the above allocation.
 */
void lguest_free_vcpu_mappings(struct lg_cpu *cpu)
{
	free_pt_page(cpu->hv_pte);
}

/**
 * lguest_update_page_tables - update both the host and guest CR3
 */
int lguest_update_page_tables(struct lg_cpu *cpu)
{
	u64 cr3;
	u64 *pgd;
	u64 *pud;
	u64 *pmd;
	u64 *pte;
	u64 *page;
	int idx;

	/* Always load the proper cr3 here */
	cpu->guest_cr3 = __pa(cpu->pgd->hcr3);
	cpu->gcr3 = cpu->pgd->gcr3;

	return 0;

	/*
	 * More fun here. We match the CR3 of the host to the guest.
	 * Since this is only used in switch_to_guest the TLB should
	 * not have these pages in. (they will be flushed on writing
	 * to cr3 anyway).
	 */

	/* grab the current cr3 */
	asm volatile ("movq %%cr3, %0" : "=r"(cr3));

	/*
	 * FIXME: only do this when updating the VCPU.
	 */
	pgd = __va(cr3);

	pgd += pgd_index(lguest_hv_addr);
	if (!(*pgd & _PAGE_PRESENT)) {
		page = get_pt_page();
		if (!page)
			return -ENOMEM;
		set_pt(*pgd, __pa(page) | _PAGE_TABLE);
	}

	pud = __va(*pgd & PTE_MASK);
	pud += pud_index(lguest_hv_addr);
	if (!(*pud & _PAGE_PRESENT)) {
		page = get_pt_page();
		if (!page)
			return -ENOMEM;
		set_pt(*pud, __pa(page) | _PAGE_TABLE);
	}

	pmd = __va(*pud & PTE_MASK);
	pmd += pmd_index(lguest_hv_addr);
	if (!(*pmd & _PAGE_PRESENT)) {
		page = get_pt_page();
		if (!page)
			return -ENOMEM;
		set_pt(*pmd, __pa(page) | _PAGE_TABLE);

		/* Only need to do this once */
		lguest_pte_map_hv_text(page, LGUEST_HV_EXEC_PROT);
	}

	pte = __va(*pmd & PTE_MASK);

	/*
	 * If this is already mapped to the current CPU
	 * than we are done.
	 */
	idx = pte_index(lg_cpu_addr);
	if (pte[idx] == cpu->hv_pte[idx])
		return 0;

	/*
	 * Map both the VCPU Data and Guest Data R/W.
	 * Remember, this is the host page tables.
	 */
	lguest_pte_map_vcpu_data(cpu, pte, LGUEST_HV_VCPU_DATA_PROT);
	lguest_pte_map_vcpu_guest_data(cpu, pte, LGUEST_HV_VCPU_DATA_PROT);

	if (cpu->id)
		printk("Before flushing\n");
	flush_tlb();
	if (cpu->id)
		printk("After flushing\n");
#if 0
	/* test me */
	{
		long dummy;
		long ret;

#if 0 
		int idx;
		int g,u,m;
		
		pgd = __va(cr3);
		idx = pgd_index(lguest_hv_addr);
		g=idx;
		printk("  %8d: %llx\n", idx, pgd[idx]);
		pud = __va(pgd[idx] & PTE_MASK);
		idx = pud_index(lguest_hv_addr);
		u = idx;
		printk("    %8d: %llx\n", idx, pud[idx]);
		pmd = __va(pud[idx] & PTE_MASK);
		idx = pmd_index(lguest_hv_addr);
		m = idx;
		printk("      %8d: %llx\n", idx, pmd[idx]);
		pte = __va(pmd[idx] & PTE_MASK);
		for (idx=0; idx < PTRS_PER_PTE; idx++) {
			if (!(pte[idx] & _PAGE_PRESENT))
				continue;
			printk("        %8d: %llx\n", idx, pte[idx]);
			printk("           (%llx)\n",
			       convert_idx_to_addr(g,u,m,idx));
		}
		printk("trying %p\n", cpu->cpu);
#endif

		asm volatile (
			"	xorq %0,%0\n"
			"1:	movq 0(%2),%1\n"
			"2:	movq %1,0(%2)\n"
			"3:\n"
			".section .fixup,\"ax\"\n"
			"4:	movq $1,%0\n"
			"	jmp 3b\n"
			"5:	movq $2,%0\n"
			"	jmp 3b\n"
			".previous\n"
			".section __ex_table,\"a\"\n"
			"	.align 8\n"
			"	.quad 1b,4b\n"
			"	.quad 2b,5b\n"
			".previous"
			: "=r"(ret), "=r"(dummy)
			: "r"(cpu->cpu));
		return ret;
	}
#endif
	return 0;
}

/****** Lguest Memory Pressure Functions ******/

static int
lguest_mem_pressure(struct lguest *lg, int nr)
{
	struct lguest_pgd *pgd;
	struct list_head *p;
	long pgs;
	int ret;

	mutex_lock(&lg->page_lock);
#if 0
	printk("RELEASING MEMORY!!!! nr=%d\n", nr);
#endif
	/* FIXME: pick individual pages. */
	pgs = lg->nr_pgs;
	if (pgs) {
		list_for_each_prev(p, &lg->pgd_lru) {
			pgd = list_entry(p, struct lguest_pgd, lru);
			release_pgd(lg, pgd);
			if (pgs > lg->nr_pgs)
				break;
		}
	}
	ret = pgs - lg->nr_pgs;
#if 0
	printk("lguest memory released %d pages (%ld -> %ld)\n",
	       ret, pgs, lg->nr_pgs);
#endif
	mutex_unlock(&lg->page_lock);
	
	if (ret < 0)
		ret = 0; /* ?? */
	return ret;
}

void lguest_add_vm_shrinker(void)
{
	/*
	 * FIXME: Need to get this working.
	 * Currently, this will lock up the box, because the
	 * shrinker thinks we can, for some reason, free up more.
	 * So it keeps calling this without freeing anything.
	 * So we lock up the box whlie the shrinker keeps calling
	 * this function.
	 */
	return;
	lguest_mem_pressure(NULL, 0);
}

void lguest_remove_vm_shrinker(void)
{
}

//FIXME
//Cred ca asta era chiar functia de mai jos, dar nu sunt sigur!
/*H:510
 * At boot or module load time, init_pagetables() allocates and populates
 * the Switcher PTE page for each CPU.
 */
__init int init_pagetables(struct page **switcher_page, unsigned int pages)
{
    //TODO
	return 0;
}
/*:*/

int init_guest_pagetable(struct lguest *lg, u64 pgtable)
{
	lg->cr3 = pgtable;

	mutex_lock(&lguest_vm_lock);
	list_add(&lg->vm_list, &lguest_infos);
	mutex_unlock(&lguest_vm_lock);

	return 0;
}

void free_pagetables(void)
{
}


void free_guest_pagetable(struct lguest *lg)
{
}
