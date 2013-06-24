/*P:600
 * The x86 architecture has segments, which involve a table of descriptors
 * which can be used to do funky things with virtual address interpretation.
 * We originally used to use segments so the Guest couldn't alter the
 * Guest<->Host Switcher, and then we had to trim Guest segments, and restore
 * for userspace per-thread segments, but trim again for on userspace->kernel
 * transitions...  This nightmarish creation was contained within this file,
 * where we knew not to tread without heavy armament and a change of underwear.
 *
 * In these modern times, the segment handling code consists of simple sanity
 * checks, and the worst you'll experience reading this code is butterfly-rash
 * from frolicking through its parklike serenity.
:*/
#include "lg.h"

/*H:600
 * Segments & The Global Descriptor Table
 *
 * (That title sounds like a bad Nerdcore group.  Not to suggest that there are
 * any good Nerdcore groups, but in high school a friend of mine had a band
 * called Joe Fish and the Chips, so there are definitely worse band names).
 *
 * To refresh: the GDT is a table of 8-byte values describing segments.  Once
 * set up, these segments can be loaded into one of the 6 "segment registers".
 *
 * GDT entries are passed around as "struct desc_struct"s, which like IDT
 * entries are split into two 32-bit members, "a" and "b".  One day, someone
 * will clean that up, and be declared a Hero.  (No pressure, I'm just saying).
 *
 * Anyway, the GDT entry contains a base (the start address of the segment), a
 * limit (the size of the segment - 1), and some flags.  Sounds simple, and it
 * would be, except those zany Intel engineers decided that it was too boring
 * to put the base at one end, the limit at the other, and the flags in
 * between.  They decided to shotgun the bits at random throughout the 8 bytes,
 * like so:
 *
 * 0               16                     40       48  52  56     63
 * [ limit part 1 ][     base part 1     ][ flags ][li][fl][base ]
 *                                                  mit ags part 2
 *                                                part 2
 *
 * As a result, this file contains a certain amount of magic numeracy.  Let's
 * begin.
 */

/*
 * There are several entries we don't let the Guest set.  The TSS entry is the
 * "Task State Segment" which controls all kinds of delicate things.  The
 * LGUEST_CS and LGUEST_DS entries are reserved for the Switcher, and the
 * the Guest can't be trusted to deal with double faults.
 */
static bool ignored_gdt(unsigned int num)
{
	return (num == GDT_ENTRY_TSS
		|| num == GDT_ENTRY_LGUEST_HV_CS
		|| num == GDT_ENTRY_LGUEST_HV_DS
        );
}

/*H:610
 * Like the IDT, we never simply use the GDT the Guest gives us.  We keep
 * a GDT for each CPU, and copy across the Guest's entries each time we want to
 * run the Guest on that CPU.
 *
 * This routine is called at boot or modprobe time for each CPU to set up the
 * constant GDT entries: the ones which are the same no matter what Guest we're
 * running.
 */
void setup_default_gdt_entries(struct lguest_ro_state *state)
{
}

/*
 * This routine sets up the initial Guest GDT for booting.  All entries start
 * as 0 (unusable).
 */
void setup_guest_gdt(struct lg_cpu *cpu)
{
}

/*H:650
 * An optimization of copy_gdt(), for just the three "thead-local storage"
 * entries.
 */
void copy_gdt_tls(const struct lg_cpu *cpu, struct desc_struct *gdt)
{
}

/*H:640
 * When the Guest is run on a different CPU, or the GDT entries have changed,
 * copy_gdt() is called to copy the Guest's GDT entries across to this CPU's
 * GDT.
 */
void copy_gdt(const struct lg_cpu *cpu, struct desc_struct *gdt)
{
	unsigned int i;

	/*
	 * The default entries from setup_default_gdt_entries() are not
	 * replaced.  See ignored_gdt() above.
	 */
	for (i = 0; i < GDT_ENTRIES; i++)
		if (!ignored_gdt(i))
			gdt[i] = cpu->arch.gdt[i];
}

/*H:620
 * This is where the Guest asks us to load a new GDT entry
 * (LHCALL_LOAD_GDT_ENTRY).  We tweak the entry and copy it in.
 */
void load_guest_gdt_entry(struct lg_cpu *cpu, u32 num, u32 lo, u32 hi)
{
	/*
	 * We assume the Guest has the same number of GDT entries as the
	 * Host, otherwise we'd have to dynamically allocate the Guest GDT.
	 */
	if (num >= ARRAY_SIZE(cpu->arch.gdt)) {
		//kill_guest(cpu, "too many gdt entries %i", num);
		return;
	}

	/* Set it up, then fix it. */
	cpu->arch.gdt[num].a = lo;
	cpu->arch.gdt[num].b = hi;
	//fixup_gdt_table(cpu, num, num+1);
	/*
	 * Mark that the GDT changed so the core knows it has to copy it again,
	 * even if the Guest is run on the same CPU.
	 */
	//cpu->changed |= CHANGED_GDT;
}

/*
 * This is the fast-track version for just changing the three TLS entries.
 * Remember that this happens on every context switch, so it's worth
 * optimizing.  But wouldn't it be neater to have a single hypercall to cover
 * both cases?
 */
void guest_load_tls(struct lg_cpu *cpu, unsigned long gtls)
{
	//struct desc_struct *tls = &cpu->arch.gdt[GDT_ENTRY_TLS_MIN];

	//__lgread(cpu, tls, gtls, sizeof(*tls)*GDT_ENTRY_TLS_ENTRIES);
	//fixup_gdt_table(cpu, GDT_ENTRY_TLS_MIN, GDT_ENTRY_TLS_MAX+1);
	/* Note that just the TLS entries have changed. */
	//cpu->changed |= CHANGED_GDT_TLS;
}

/*H:660
 * With this, we have finished the Host.
 *
 * Five of the seven parts of our task are complete.  You have made it through
 * the Bit of Despair (I think that's somewhere in the page table code,
 * myself).
 *
 * Next, we examine "make Switcher".  It's short, but intense.
 */
