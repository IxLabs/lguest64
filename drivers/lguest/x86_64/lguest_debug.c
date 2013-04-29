/*
    lguest debug utils. Modified from various other parts of Linux.
    What was modified is Copyright 2007 Steven Rostedt, Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
*/
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/freezer.h>
#include <linux/kallsyms.h>
#include <linux/lguest.h>
#include <linux/slab.h>
#include <asm/paravirt.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include "lg.h"

#if 1
#define DEBUG_DUMP_STACK() dump_stack()
#else
#define DEBUG_DUMP_STACK() do { } while(0)
#endif

int lguest_debug = 0;

static DEFINE_SPINLOCK(lgdebug_print_lock);
#define LGDEBUG_BUF_SIZ 1024
static char lgdebug_print_buf[LGDEBUG_BUF_SIZ];

void lgdebug_vprint(const char *fmt, va_list ap)
{
	unsigned long flags;

	if (!lguest_debug)
		return;

	spin_lock_irqsave(&lgdebug_print_lock, flags);
	vsnprintf(lgdebug_print_buf, LGDEBUG_BUF_SIZ-1, fmt, ap);
	printk("%s", lgdebug_print_buf);
	spin_unlock_irqrestore(&lgdebug_print_lock, flags);
}

void lgdebug_print(const char *fmt, ...)
{
	va_list ap;

	if (!lguest_debug)
		return;

	/* irq save? */
	va_start(ap, fmt);
	lgdebug_vprint(fmt, ap);
	va_end(ap);
}

void lgdebug_lprint(unsigned flags, const char *fmt, ...)
{
	va_list ap;

	if (!(lguest_debug & flags))
		return;

	va_start(ap, fmt);
	lgdebug_vprint(fmt, ap);
	va_end(ap);
}

void lgdebug_lvprint(unsigned flags, const char *fmt, va_list ap)
{
	if (!(lguest_debug & flags))
		return;

	lgdebug_vprint(fmt, ap);
}

#define SAVE_CR2(cr2)	asm volatile ("movq %%cr2, %0" : "=r" (cr2))

void lguest_dump_vcpu_regs(struct lg_cpu *cpu)
{
	struct lguest_regs *regs = cpu->regs;
	unsigned long gs, shadow_gs;
	unsigned long cr2, data_cr2;
	unsigned long stack;
	unsigned long rsp = guest_pa(cpu->lg, regs->rsp);
	int i;
	static DEFINE_MUTEX(mutex);

	mutex_lock(&mutex);
	printk("called from ");
	DEBUG_DUMP_STACK();
	print_ip_sym((unsigned long)__builtin_return_address(0));
	printk("Printing CPU %d regs cr3: %016llx\n",
	       cpu->id, regs->cr3);
	printk("RIP: %04llx: ", regs->cs & 0xffff);
	lguest_print_address(cpu, regs->rip);
	printk("RSP: %04llx:%016llx  EFLAGS: %08llx irqs %s\n", regs->ss, regs->rsp,
	       regs->rflags,
	       cpu->lg_cpu_data->irq_enabled?"enabled":"disabled");
	printk("RAX: %016llx RBX: %016llx RCX: %016llx\n",
	       regs->rax, regs->rbx, regs->rcx);
	printk("RDX: %016llx RSI: %016llx RDI: %016llx\n",
	       regs->rdx, regs->rsi, regs->rdi);
	printk("RBP: %016llx R08: %016llx R09: %016llx\n",
	       regs->rbp, regs->r8, regs->r9);
	printk("R10: %016llx R11: %016llx R12: %016llx\n",
	       regs->r10, regs->r11, regs->r12);
	printk("R13: %016llx R14: %016llx R15: %016llx\n",
	       regs->r13, regs->r14, regs->r15);
	printk("FS %04llx: Base: %016lx  Desc: %08lx\n",
	       regs->fs,(cpu->lg_cpu_data->guest_fs_a |
			(cpu->lg_cpu_data->guest_fs_d << 32)), 
			(cpu->lg_cpu_data->guest_fs_desc_a |
			(cpu->lg_cpu_data->guest_fs_desc_d << 32)));

	data_cr2 = cpu->lg_cpu_data->cr2;

	SAVE_CR2(cr2);
	printk(" CR2: %lx  lg_cpu_data->cr2: %lx\n", cr2, data_cr2);
	
	gs = (u32)cpu->lg_cpu_data->guest_gs_a | (cpu->lg_cpu_data->guest_gs_d << 32);
	shadow_gs = (u32)cpu->lg_cpu_data->guest_gs_shadow_a |
		(cpu->lg_cpu_data->guest_gs_shadow_d << 32);
	printk(" GS Base: %016lx  Shadow: %016lx\n",
	       gs, shadow_gs);

	printk("errcode: %llx   trapnum: %llx\n",
	       regs->errcode, regs->trapnum);

	printk("Stack Dump:");
	for (i=0; i < 16; i++) {
		if (!(i % 4))
			printk("\n    ");
		else
			printk("  ");
		if (get_user(stack, (long*)(rsp + i * sizeof(long))))
			break;
		printk("%016lx", stack);
	}
	printk("\n");
		
	lguest_dump_trace(cpu, regs);
	mutex_unlock(&mutex);
}

struct guest_ksym_stuff {
	unsigned long *addresses;
	unsigned long num_syms;
	u8 *names;
	u8 *token_table;
	u16 *token_index;
	unsigned long *markers;
};

static struct lguest_text_ptr *get_text_segs(struct lg_cpu *cpu)
{
	struct lguest *lg = cpu->lg;
	struct lguest_text_ptr *segs, **p;
	struct lguest_text_ptr *g;
	unsigned long addr;
	int i;

	if (!lg->lguest_data)
		return NULL;

	addr = lgread_u64(lg, (u64)&lg->lguest_data->text);
	if (!addr)
		return NULL;

	g = (struct lguest_text_ptr*)addr;

	p = &segs;

	/* only allow for 10 segs */
	for (i=0; i < 10; i++) {
		*p = kmalloc(sizeof(*segs), GFP_KERNEL);
		if (!*p)
			goto free_me;
		(*p)->start = lgread_u64(lg, (u64)&g->start);
		(*p)->end = lgread_u64(lg, (u64)&g->end);
		addr = lgread_u64(lg, (u64)&g->next);
		p = (struct lguest_text_ptr**)&((*p)->next);
		if (!addr)
			break;
		g = (struct lguest_text_ptr*)addr;
	}
	*p = NULL;

	return segs;

free_me:
	while (segs) {
		g = (struct lguest_text_ptr*)segs->next;
		kfree(segs);
		segs = g;
	}
	return NULL;
}

static int is_text_seg(struct lguest_text_ptr *segs, unsigned long addr)
{
	while (segs) {
		if (addr >= segs->start &&
		    addr <= segs->end)
			return 1;
		segs = (struct lguest_text_ptr*)segs->next;
	}
	return 0;
}

static void put_text_segs(struct lguest_text_ptr *segs)
{
	struct lguest_text_ptr *p;

	while (segs) {
		p = (struct lguest_text_ptr*)segs->next;
		kfree(segs);
		segs = p;
	}
}

static unsigned int expand_symbol(struct lg_cpu *cpu,
				  struct guest_ksym_stuff *kstuff,
				  unsigned int off, char *result)
{
	struct lguest *lg = cpu->lg;
	int len, skipped_first = 0;
	const u8 *tptr, *data;

	/* get the compressed symbol length from the first symbol byte */
	data = &kstuff->names[off];

	len = lgread_u8(lg, (u64)data);

	data++;

	/* update the offset to return the offset for the next symbol on
	 * the compressed stream */
	off += len + 1;

	/* for every byte on the compressed symbol data, copy the table
	   entry for that byte */
	while(len) {
		u8 idx;
		u16 tok;
		idx = lgread_u8(lg, (u64)data);
		tok = lgread_u16(lg, (u64)(&kstuff->token_index[idx]));
		tptr = &kstuff->token_table[ tok ];
		data++;
		len--;

		idx = lgread_u8(lg, (u64)tptr);
		while (idx) {
			if(skipped_first) {
				*result = idx;
				result++;
			} else
				skipped_first = 1;
			tptr++;
			idx = lgread_u8(lg, (u64)tptr);
		}
	}

	*result = '\0';

	/* return to offset to the next symbol */
	return off;
}

static unsigned long get_symbol_pos(struct lg_cpu *cpu,
				    struct guest_ksym_stuff *kstuff,
				    unsigned long addr,
				    unsigned long *symbolsize,
				    unsigned long *offset)
{
	unsigned long symbol_start = 0, symbol_end = 0;
	unsigned long i, low, high, mid;

	/* do a binary search on the sorted kallsyms_addresses array */
	low = 0;
	high = kstuff->num_syms;

	while (high - low > 1) {
		mid = (low + high) / 2;
		if (kstuff->addresses[mid] <= addr)
			low = mid;
		else
			high = mid;
	}

	/*
	 * search for the first aliased symbol. Aliased
	 * symbols are symbols with the same address
	 */
	while (low && kstuff->addresses[low-1] == kstuff->addresses[low])
		--low;

	symbol_start = kstuff->addresses[low];

	/* Search for next non-aliased symbol */
	for (i = low + 1; i < kstuff->num_syms; i++) {
		if (kstuff->addresses[i] > symbol_start) {
			symbol_end = kstuff->addresses[i];
			break;
		}
	}

	/* if we found no next symbol, we use the end of the section */
	if (!symbol_end) {
		return (unsigned long)(-1UL);
#if 0
		if (is_kernel_inittext(addr))
			symbol_end = (unsigned long)_einittext;
		else if (all_var)
			symbol_end = (unsigned long)_end;
		else
			symbol_end = (unsigned long)_etext;
#endif
	}

	*symbolsize = symbol_end - symbol_start;
	*offset = addr - symbol_start;

	return low;
}

static int is_ksym_addr(struct lguest *lg,
			unsigned long addr)
{
	/* need to look up the segs */
	return 1;
}

static unsigned int get_symbol_offset(struct lg_cpu *cpu,
				      struct guest_ksym_stuff *kstuff,
				      unsigned long pos)
{
	struct lguest *lg = cpu->lg;
	const u8 *name;
	int i;
	unsigned long idx;

	idx = lgread_u64(lg, (u64)&kstuff->markers[pos>>8]);

	/* use the closest marker we have. We have markers every 256 positions,
	 * so that should be close enough */
	name = &kstuff->names[ idx ];

	/* sequentially scan all the symbols up to the point we're searching for.
	 * Every symbol is stored in a [<len>][<len> bytes of data] format, so we
	 * just need to add the len to the current pointer for every symbol we
	 * wish to skip */
	for(i = 0; i < (pos&0xFF); i++) {
		u8 c;
		c = lgread_u8(lg, (u64)name);
		name = name + c + 1;
	}

	return name - kstuff->names;
}

static const char *lguest_syms_lookup(struct lg_cpu *cpu,
				      unsigned long addr,
				      unsigned long *symbolsize,
				      unsigned long *offset,
				      char **modname, char *namebuf)
{
	struct lguest *lg = cpu->lg;
	struct lguest_data *data = lg->lguest_data;
	struct guest_ksym_stuff kstuff;
	const char *msym;
	unsigned long *ptr;
	int i;

	kstuff.addresses = (unsigned long*)lgread_u64(lg, (u64)&data->kallsyms_addresses);
	kstuff.num_syms = lgread_u64(lg, (u64)&data->kallsyms_num_syms);
	kstuff.names = (u8*)lgread_u64(lg, (u64)&data->kallsyms_names);
	kstuff.token_table = (u8*)lgread_u64(lg, (u64)&data->kallsyms_token_table);
	kstuff.token_index = (u16*)lgread_u64(lg, (u64)&data->kallsyms_token_index);
	kstuff.markers = (unsigned long*)lgread_u64(lg, (u64)&data->kallsyms_markers);

	if (!kstuff.addresses || !kstuff.num_syms || !kstuff.names ||
	    !kstuff.token_table || !kstuff.token_index || !kstuff.markers) {
		static int once = 1;
		if (once) {
			once = 0;
			if (!kstuff.addresses)
				printk("kstuff.addresses is null\n");
			if (!kstuff.num_syms)
				printk("kstuff.num_syms is null\n");
			if (!kstuff.names)
				printk("kstuff.names is null\n");
			if (!kstuff.token_table)
				printk("kstuff.token_table is null\n");
			if (!kstuff.token_index)
				printk("kstuff.token_index is null\n");
			if (!kstuff.markers)
				printk("kstuff.markers is null\n");
		}

		return NULL;
	}

	/* FIXME: Validate all the kstuff here!! */

	ptr = kmalloc(sizeof(unsigned long)*kstuff.num_syms, GFP_KERNEL);
	if (!ptr)
		return NULL;

	for (i=0; i < kstuff.num_syms; i++) {
		/* FIXME: do this better! */
		ptr[i] = lgread_u64(lg, (u64)&kstuff.addresses[i]);
		if (i && ptr[i] < ptr[i-1]) {
			kill_guest(lg, "bad kallsyms table\n");
			kstuff.addresses = ptr;
			goto out;
		}
	}
	kstuff.addresses = ptr;

	namebuf[KSYM_NAME_LEN] = 0;
	namebuf[0] = 0;

	if (is_ksym_addr(lg, addr)) {
		unsigned long pos;

		pos = get_symbol_pos(cpu, &kstuff, addr, symbolsize, offset);
		if (pos == (unsigned long)(-1UL))
			goto out;

		/* Grab name */
		expand_symbol(cpu, &kstuff,
			      get_symbol_offset(cpu, &kstuff, pos), namebuf);
		*modname = NULL;
		kfree(kstuff.addresses);
		return namebuf;
	}

	/* see if it's in a module */
	msym = module_address_lookup(addr, symbolsize, offset, modname, namebuf);
	if (msym) {
		kfree(kstuff.addresses);
		return strncpy(namebuf, msym, KSYM_NAME_LEN);
	}

out:
	kfree(kstuff.addresses);
	return NULL;
}

void lguest_print_address(struct lg_cpu *cpu, unsigned long address)
{
	unsigned long offset = 0, symsize;
	const char *symname;
	char *modname;
	char *delim = ":";
	char namebuf[KSYM_NAME_LEN+1];

	symname = lguest_syms_lookup(cpu, address, &symsize, &offset,
				     &modname, namebuf);
	if (!symname) {
		printk(" [<%016lx>]\n", address);
		return;
	}
	if (!modname)
		modname = delim = "";
	printk(" [<%016lx>] %s%s%s%s+0x%lx/0x%lx\n",
	       address, delim, modname, delim, symname, offset, symsize);

}

void lguest_dump_trace(struct lg_cpu *cpu, struct lguest_regs *regs)
{
	struct lguest *lg = cpu->lg;
	unsigned long stack = regs->rsp;
	unsigned long stack_end = (regs->rsp & PAGE_MASK) + PAGE_SIZE;
	unsigned long start_kernel_map;
	unsigned long page_offset;
	unsigned long addr;
	struct lguest_text_ptr *segs;

	printk("Stack Trace:\n");
	if (stack < cpu->lg->page_offset) {
		printk("  <USER STACK>\n");
		goto out;
	}

	start_kernel_map = cpu->lg->start_kernel_map;
	page_offset = cpu->lg->page_offset;

	segs = get_text_segs(cpu);
	if (!segs)
		return;

	for (; stack < stack_end; stack += sizeof(stack)) {
		addr = lgread_u64(lg, guest_pa(cpu->lg, stack));
		if (is_text_seg(segs, addr)) {
			lguest_print_address(cpu, addr);
		}
	}

	put_text_segs(segs);

out:
	printk("=======\n");
}

static u64 read_page(struct lg_cpu *cpu, u64 page, u64 idx)
{
	struct lguest *lg = cpu->lg;
	u64 *ptr;

	if (!cpu) {
		ptr = __va(page);
		return ptr[idx];
	}

	return lgread_u64(lg, page+idx*sizeof(u64));
}

static void print_pte(u64 pte, u64 pgd_idx, u64 pud_idx, u64 pmd_idx, u64 pte_idx)
{
	printk("           %3llx: %llx\n", pte_idx, pte);
	printk ("               (%llx)\n",
		convert_idx_to_addr(pgd_idx, pud_idx, pmd_idx, pte_idx));

#if 0
		((pgd_idx&(1<<8)?(-1ULL):0ULL)<<48) |
		(pgd_idx<<PGDIR_SHIFT) |
		(pud_idx<<PUD_SHIFT) |
		(pmd_idx<<PMD_SHIFT) |
		(pte_idx<<PAGE_SHIFT));
#endif
}

static void print_pmd(struct lg_cpu *cpu,
		      u64 pmd, u64 pgd_idx, u64 pud_idx, u64 pmd_idx)
{
	u64 pte;
	u64 ptr;
	u64 i;

	printk("        %3llx: %llx\n", pmd_idx, pmd);

	/* 2M page? */
	if (pmd & (1<<7)) {
		printk ("            (%llx)\n",
			convert_idx_to_addr(pgd_idx, pud_idx, pmd_idx, 0));
	} else {
		pte = pmd & PTE_MASK;
		for (i=0; i < PTRS_PER_PTE; i++) {
			ptr = read_page(cpu, pte, i);
			if (ptr & _PAGE_PRESENT)
				print_pte(ptr, pgd_idx, pud_idx, pmd_idx, i);
		}
	}
}

static void print_pud(struct lg_cpu *cpu,
		      u64 pud, u64 pgd_idx, u64 pud_idx)
{
	u64 pmd;
	u64 ptr;
	u64 i;

	printk("     %3llx: %llx\n", pud_idx, pud);

	pmd = pud & PTE_MASK;
	for (i=0; i < PTRS_PER_PMD; i++) {
		ptr = read_page(cpu, pmd, i);
		if (ptr & _PAGE_PRESENT)
			print_pmd(cpu, ptr, pgd_idx, pud_idx, i);
	}
}

static void print_pgd(struct lg_cpu *cpu,
		      u64 pgd, u64 pgd_idx)
{
	u64 pud;
	u64 ptr;
	u64 i;

	printk(" %3llx:  %llx\n", pgd_idx, pgd);
	pud = pgd & PTE_MASK;
	for (i=0; i < PTRS_PER_PUD; i++) {
		ptr = read_page(cpu, pud, i);
		if (ptr & _PAGE_PRESENT)
			print_pud(cpu, ptr, pgd_idx, i);
	}

}

static void print_page_tables(struct lg_cpu *cpu,
			      u64 cr3)
{
	u64 pgd;
	u64 ptr;
	u64 i;

	printk("cr3: %016llx\n", cr3);
	pgd = cr3;

	for (i=0; i < PTRS_PER_PGD; i++) {
		ptr = read_page(cpu, pgd, i);
		if (ptr & _PAGE_PRESENT)
			print_pgd(cpu, ptr, i);
	}
}

void lguest_print_page_tables(u64 *cr3)
{
	if (!cr3) {
		printk("NULL cr3 pointer????\n");
		return;
	}
	print_page_tables(NULL, __pa(cr3));
}

void lguest_print_guest_page_tables(struct lg_cpu *cpu, u64 cr3)
{
	print_page_tables(cpu, cr3);
}

#if 0
void lguest_check_hv_pages(struct lg_cpu *cpu)
{
	u64 start = lguest_hv_addr;
	u64 end = start + lguest_hv_pages * PAGE_SIZE;
	u64 *pgd, *pud, *pmd, *pte;
	int g, u, m, p;

	/* make sure that the HV pages are mapped in */
	BUG_ON(!cpu->regs.cr3);
	pgd = __va(cpu->regs.cr3 & PAGE_MASK);
	BUG_ON(!pgd);

	for (g=pgd_index(start); g < pgd_index(end); g++) {
		BUG_ON(!(pgd[g] & _PAGE_PRESENT));
		pud = __va(pgd[g] & PTE_MASK);
		for (u=pud_index(start); u < pud_index(end); u++) {
			BUG_ON(!(pud[u] & _PAGE_PRESENT));
			pmd = __va(pud[u] & PTE_MASK);
			for (m=pmd_index(start); m < pmd_index(end); m++) {
				BUG_ON(!(pmd[m] & _PAGE_PRESENT));
				pte = __va(pmd[u] & PTE_MASK);
				for (p=pte_index(start); p < pte_index(end); p++)
					BUG_ON(!(pte[p] & _PAGE_PRESENT));
			}
		}
	}
}
#endif

static void lguest_dump_page_tables(struct lg_cpu *cpu)
{
	printk("Host page tables:\n");
	lguest_print_page_tables(cpu->pgd->hcr3);

	printk("\n\nGuest page tables:\n");
	lguest_print_guest_page_tables(cpu, cpu->pgd->gcr3);
}

static int lguest_test_pte(struct lg_cpu *cpu, int pgd_idx, int pud_idx,
			   int pmd_idx, u64 *pte, int check)
{
	int p;
	u64 vaddr;
	u64 gpaddr;
	u64 paddr;
	pgprot_t prot;

	if (cpu->lg->dead)
		return -1;

	for (p=0; p < PTRS_PER_PTE; p++) {
		if (pte[p] & _PAGE_PRESENT) {
			if (is_hv_page(pgd_idx, pud_idx, pmd_idx, p))
				continue;
			vaddr = convert_idx_to_addr(pgd_idx, pud_idx, pmd_idx, p);
			gpaddr = lguest_find_guest_paddr(cpu, vaddr);
			if (gpaddr == (u64)-1) {
				if (!check)
					return 1;
				/* 
				 * Don't kill, just warn. It could simply be
				 * that we are flushing page tables.
				 */
				printk("WARNING! cr3: %llx pgd: %p page %llx is mapped\n"
				       "    in host  but is not mapped to guest\n",
				       cpu->pgd->gcr3,
				       cpu->pgd->hcr3,
				       vaddr);
				printk("rip=");
				lguest_print_address(cpu, cpu->regs->rip);
				printk(" (%lx) pte[%x] = %llx\n",
				       __pa(pte), p, pte[p]);
				check = 0;
				continue;
			}
			/* now get the actual page */
			paddr = lguest_get_actual_phys((void*)gpaddr, &prot);
			if (paddr != (pte[p] & PTE_MASK)) {
				printk("WARNING! cr3: %llx pgd: %p page %llx is mapped\n"
				       "   to host as %llx but the guest has it as\n"
				       "   paddr %llx => %llx guest prot=%lx host prot=%llx\n",
				       cpu->pgd->gcr3,
				       cpu->pgd->hcr3,
				       vaddr, pte[p] & PTE_MASK,
				       gpaddr, paddr,
				       pgprot_val(prot), pte[p] & ~PTE_MASK);
				printk("rip=");
				lguest_print_address(cpu, cpu->regs->rip);
				printk(" (%lx) pte[%x] = %llx\n",
				       __pa(pte), p, pte[p]);
				return -1;
			}
		}
	}
	return !check;
}

static int lguest_test_pmd(struct lg_cpu *cpu, int pgd_idx, int pud_idx,
			   u64 *pmd, int check)
{
	int m;
	int ret;

	if (cpu->lg->dead)
		return -1;

	for (m=0; m < PTRS_PER_PMD; m++) {
		if (pmd[m] & _PAGE_PRESENT) {
			ret = lguest_test_pte(cpu, pgd_idx, pud_idx,
					      m, __va(pmd[m] & PTE_MASK), check);
			if (!ret)
				continue;
			if (ret == 1) {
				check = 0;
				continue;
			}
			if (ret < 0) {
				printk(" (%lx) pmd[%x] = %llx\n",
				       __pa(pmd), m, pmd[m]);
				return -1;
			}
		}
	}
	return !check;
}

static int lguest_test_pud(struct lg_cpu *cpu, int pgd_idx, u64 *pud, int check)
{
	int u;
	int ret;

	if (cpu->lg->dead)
		return -1;

	for (u=0; u < PTRS_PER_PUD; u++) {
		if (pud[u] & _PAGE_PRESENT) {
			ret = lguest_test_pmd(cpu, pgd_idx,
					      u, __va(pud[u] & PTE_MASK), check);
			if (!ret)
				continue;
			if (ret == 1) {
				check = 0;
				continue;
			}
			if (ret < 0) {
				printk(" (%lx) pud[%x] = %llx\n",
				       __pa(pud), u, pud[u]);
				return -1;
			}
		}
	}
	return !check;
}

static int lguest_test_pages(struct lg_cpu *cpu, u64 *pgd, int check)
{
	int g;
	int ret;
	int ignore = 0;

	/* passing in -1 doesn't kill the guest */
	if (check == -1) {
		ignore = 1;
		check = 0;
	}

	if (cpu->lg->dead)
		return 1;

	if (!pgd) {
		printk("NULL pgd??\n");
		return -1;
	}

	for (g=0; g < PTRS_PER_PGD; g++) {
		if (pgd[g] & _PAGE_PRESENT) {
			ret = lguest_test_pud(cpu, g, __va(pgd[g] & PTE_MASK), check);
			if (!ret)
				continue;
			if (ret == 1) {
				check = 0;
				continue;
			}
			if (ret < 0) {
				printk(" (%lx) pgd[%x] = %llx\n",
				       __pa(pgd), g, pgd[g]);
				if (!ignore) {
					lguest_dump_page_tables(cpu);
					kill_guest_dump(cpu, "bad page mapping\n");
				}
				return -1;
			}
		}
	}
	return 0;
}

/**
 * lguest_paranoid_page_check - nasty full check of page tables
 *  @cpu - cpu struct to test.
 * 
 *  Look at all the actually map pages of the current pgdir
 *  to see if they are also mapped correctly by the guest.
 */
void lguest_paranoid_page_check(struct lg_cpu *cpu, int check)
{
	lguest_test_pages(cpu, cpu->pgd->hcr3, check);
}
