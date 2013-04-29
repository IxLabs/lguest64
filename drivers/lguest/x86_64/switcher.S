#include <linux/threads.h>
#include <asm/asm-offsets.h>
#include <asm/page.h>
#include <asm/msr.h>
#include <asm/segment.h>
#include "lg.h"
#include "debug_switcher.h"

//FIXME - definitii facute de mine dupa
//cum erau in kernelul 2.6
#define __HV_CS 0x80
#define __HV_DS 0x88

.text
.align PAGE_SIZE
ENTRY(start_switcher_text)

.global start_hyper_text
	.type start_hyper_text, @function
start_hyper_text:

/* Save registers on the current stack. Both for
 * switch_to_guest and switch_to_host usage */
#define SAVE_REGS				\
	/* Save old guest/host state */		\
	pushq	%fs;				\
	pushq	%rax;				\
	pushq	%r15;				\
	pushq	%r14;				\
	pushq	%r13;				\
	pushq	%r12;				\
	pushq	%r11;				\
	pushq	%r10;				\
	pushq	%r9;				\
	pushq	%r8;				\
	pushq	%rbp;				\
	pushq	%rdi;				\
	pushq	%rsi;				\
	pushq	%rdx;				\
	pushq	%rcx;				\
	pushq	%rbx;				\

#define RESTORE_REGS				\
	/* Save old guest/host state */		\
	popq	%rbx;				\
	popq	%rcx;				\
	popq	%rdx;				\
	popq	%rsi;				\
	popq	%rdi;				\
	popq	%rbp;				\
	popq	%r8;				\
	popq	%r9;				\
	popq	%r10;				\
	popq	%r11;				\
	popq	%r12;				\
	popq	%r13;				\
	popq	%r14;				\
	popq	%r15;				\
	popq	%rax;				\
/*
 * Don't restore fs, since that has side effects.
 * Only do it on a case per case basis.
 */

.macro dump_stack_regs PREFIX
	movq	$LGUEST_REGS_size, %r10
	xorq	%r11, %r11
1:	PRINT_L(\PREFIX);
	movq	%r11, %rbx;
	PRINT_NUM_BX;
	PRINT_L(':'); PRINT_L(' ');
	movq	%rsp, %r9
	addq	%r11, %r9
	PRINT_QUAD((%r9))
	addq	$8, %r11
	cmp	%r11, %r10
	ja	1b
.endm

.macro debugme VCPU C
	testb	$1,LG_CPU_debug(\VCPU)
	jz	23f
	PRINT_L(\C)
23:
.endm

/* Get the VCPU structure from HV text end. */
.macro get_vcpu R T
	/* Get the current RIP */
	call 67f
67:	popq \R
	/*
	 * Now subtract the RIP from the address at label 67 
	 * and that will give us the delta from where we
	 * really are, and where we are linked. Then we add
	 * the end of the HV text + (PAGE_SIZE-1) & PAGE_SIZE-1
	 * to get the location of the VCPU ptr.
	 */
	leaq 67b, \T
	subq \T, \R
	leaq end_hyper_text, \T
	addq \T, \R
	addq $(PAGE_SIZE-1), \R
	movq $(PAGE_SIZE-1), \T
	notq \T
	andq \T, \R
	/* R should have our VCPU data */
.endm

/* Get the guest data from VCPU data */
.macro get_vcpu_data R V
	movq (\V), \R
.endm

/* The host vcpu date is always right after the HV vcpu data */
.macro get_host_vcpu_data R V
	movq 8(\V), \R
.endm

/**
 * DECODE_IDT  parse a IDT descriptor to find the target.
 *  @IDT     - The register that holds the IDT descriptor location
 *  @IDTWORD - The word version of the IDT register
 *	        (ie. IDT is %rax, then IDTWORD must be %ax)
 *  @RESULT  - The regsiter to place the result.
 *
 * This clobbers both IDT and RESULT regs.
 */
.macro DECODE_IDT IDT IDTWORD RESULT
	movzwq	(\IDT), \RESULT
	movq	4(\IDT), \IDT
	xorw	\IDTWORD, \IDTWORD
	orq	\IDT, \RESULT
.endm

/**
 * DECODE_SSEG  parse a System Segment descriptor to find the target.
 *  @SEG       - The register that holds the Sys Seg descriptor location
 *  @RESULT    - The regsiter to place the result.
 *  @RW	       - The word version of the RESULT register
 *  @RH	       - The high byte version of the RESULT register
 *
 * (ie. RESULT is %rax, then RW must be %ax and RH must be %ah)
 *
 * This clobbers both SEG and RESULT regs.
 */
/* Why does Intel need to make everything so darn complex! */
.macro DECODE_SSEG SEG RESULT RW RH
	movzbq	7(\SEG), \RESULT
	shl	$16, \RESULT
	movb	4(\SEG), \RH
	shl	$8, \RESULT
	movw	2(\SEG), \RW
	movq	8(\SEG), \SEG
	shlq	$32, \SEG
	orq	\SEG, \RESULT
.endm

/**
 * DO_SWAPGS  Performe a swapgs for the guest.
 *  @S - register that holds the guest data.
 *
 * Note: this also uses registers A,B,C and D, so
 *  the must be saved before calling this macro.
 */
.macro DO_SWAPGS S
	movq	LG_CPU_DATA_guest_gs_shadow_a(\S), %rax
	movq	LG_CPU_DATA_guest_gs_shadow_d(\S), %rdx
	movq	LG_CPU_DATA_guest_gs_a(\S), %rcx
	movq	LG_CPU_DATA_guest_gs_d(\S), %rbx

	movq	%rcx, LG_CPU_DATA_guest_gs_shadow_a(\S)
	movq	%rbx, LG_CPU_DATA_guest_gs_shadow_d(\S)
	movq	%rax, LG_CPU_DATA_guest_gs_a(\S)
	movq	%rdx, LG_CPU_DATA_guest_gs_d(\S)

	/* Load the guest gs pointer */
	movl	$MSR_GS_BASE, %ecx
	wrmsr
.endm

.macro DO_SWAPGS_USE_STACK
	pushq	%rax
	pushq	%rbx
	pushq	%rcx
	pushq	%rdx
	pushq	%rdi
	pushq	%r11
	get_vcpu  %rdi, %rax
	get_vcpu_data %r11, %rdi
	DO_SWAPGS  %r11
	popq	%r11
	popq	%rdi
	popq	%rdx
	popq	%rcx
	popq	%rbx
	popq	%rax
.endm

.global switch_to_guest
	.type switch_to_guest, @function
/*
 * rdi holds the pointer to vcpu.
 * rsi holds the guest data (stack) pointer.
 * Interrupts are off on entry
 *
 * NOTE:
 *  On entry to switch_to_guest, we have write access to
 *  the vcpu RO data. But once we switch to the guest CR3
 *  we do not. To make matters even worse, the vcpu RO data
 *  struct is located in a different location with the guest
 *  CR3.
 */
switch_to_guest:
	SAVE_REGS
	PRINT_OUT($65)
	/* save host stack */
	movq	%rsp, LG_CPU_host_stack(%rdi)

	/* FIXME: Optimize this, by removing it from here! */
	/* save this host's gdt and idt */
	sgdt LG_CPU_host_gdt(%rdi)
	sidt LG_CPU_host_idt(%rdi)

	/* Save the gs base of the host */
	movl	$MSR_GS_BASE, %ecx
	rdmsr
	movq	%rax, LG_CPU_host_gs_a(%rdi)
	movq	%rdx, LG_CPU_host_gs_d(%rdi)

	/* Save the host process gs pointer */
	movl	$MSR_KERNEL_GS_BASE, %ecx
	rdmsr
	movq	%rax, LG_CPU_host_proc_gs_a(%rdi)
	movq	%rdx, LG_CPU_host_proc_gs_d(%rdi)

	/* save the hosts page tables */
	movq %cr3, %rax
	movq %rax, LG_CPU_host_cr3(%rdi)

	/*
	 * The NMI does weird things if we take an NMI after
	 * loading the IDT and we are still in __KERNEL_CS.
	 * So switch over to __HV_CS and __HV_DS.  But in
	 * x86_64, there's really no good way to do that.
	 * So we set up a interrupt stack frame and iret
	 * here. But becareful, the iret goes back so we
	 * need to test for switching after the label.
	 * We also need to test to see if we need to bother
	 * at all in doing any of this.
	 */

	/* Are we already at the proper CS */
	mov	%cs, %rax
	cmp	$__HV_CS, %rax
	je	3f

	/* Nope, so we set up a stack frame to change our CS and DS */
	pushq	$__HV_DS
	pushq	%rsp
	pushfq
	pushq	$__HV_CS
	/* We don't know our RIP so make a call to put it on the stack */
	call	1f
1:
	/* The iret will go back to the 1 label, so skip if we already
	 * did the iret */
	mov	%cs, %rax
	cmp	$__HV_CS, %rax
	je	2f
	iretq

2:
	/* Adjust rsp for push of DS */
	addq	$8, %rsp
3:

	/*
	 * The NMI is a big PITA. There's no way to atomically load the
	 * TSS and IDT, so we can't just switch to the guest TSS without
	 * causing a race condition with  the NMI.
	 * So we set up the host NMI stack in the guest TSS IST so that
	 * in case we take an NMI after loading the IDT and before the TR
	 * and still have a valid stack here.
	 */
	/* load the guest idt */
	lidt LG_CPU_idt(%rdi)
	/* If we take an NMI now, we will be using the host GDT */

	/* Load the guest gdt (still points to host memory ) */
	lgdt LG_CPU_gdt(%rdi)

	/* If we take an NMI now, we will be using the host stack */

	/* Switch to guest's TSS */
	movl	$(GDT_ENTRY_TSS*8), %ebx
	ltr	%bx

	/*
	 * OK, now the NMI will also use the guest stack. This is a problem!
	 * We haven't switched to the guest CR3 yet. So this means that
	 * we can take an NMI that will use a "shared" stack with other
	 * CPUs.  Well that's not too much of a bother, since the NMI
	 * will detect this, and will not write much to the stack, our rdi
	 * and rax is safe.  But we can't trust the RSP or any other regs
	 * that the NMI will need to use.
	 */

	/* Set host's TSS to available (clear byte 5 bit 2). */
	movq	LG_CPU_host_gdt_ptr(%rdi), %rax
	andb	$0xFD, (GDT_ENTRY_TSS*8+5)(%rax)

	/*
	 * We need to use the guest CR3 as quick as possible now,
	 * due to the NMI situation, described above.
	 *
	 * But this gets even trickier!
	 *
	 * When we switch to the CR3 to the guest, the GDT would
	 * still point to the host memory version of the guest GDT.
	 * This means that no GDT exists!, so what to do??
	 *
	 * We now map the GDT to the address of the guest RO
	 * VCPU data. In the host side we have this mapped in
	 * with a "generic" GDT that the NMI could use. **
	 * So if we take an NMI after we load the GDT table,
	 * the NMI would use this generic GDT table of the guest.
	 * All should be well (we hope!)
	 *
	 *   ** - still TBD!!!!
	 */

	/* Load guest memory version of the GDT */
	lgdt LG_CPU_hv_gdt(%rdi)

	/* Load the pointer to the vcpu data when in the guest cr3 to r12 */
	movq	LG_CPU_cpu_hv(%rdi), %r12;

	/* switch to the guests page tables */
	movq	LG_CPU_guest_cr3(%rdi), %rax
	movq	%rax, %cr3

	/* NOTE! We now do *not* have write access to the VCPU Data */
	/*
	 * Now the NMI should be safe since it is using the correct
	 * stack.
	 */
	/* Now point the rdi to the vcpu data for the guest cr3 */
	movq	%r12, %rdi

	/* Set r11 to the guest RW data */
	get_vcpu_data	%r11, %rdi
	
	/* Load the guest gs pointer */
	movl	$MSR_KERNEL_GS_BASE, %ecx
	movq	LG_CPU_DATA_guest_gs_a(%r11), %rax
	movq	LG_CPU_DATA_guest_gs_d(%r11), %rdx
	wrmsr

	/* load the VCPU RO Data into the gs base */
	movl	$MSR_GS_BASE, %ecx
	movq	%rdi, %rax;
	movq	%rax, %rdx
	shr	$32, %rdx
	wrmsr

	/* Flush the TLB */
	movq	%cr4, %rax
	movq	%rax, %rbx
	andb	$~(1<<7), %al
	movq	%rax, %cr4
	movq	%rbx, %cr4

	/* put the guest's stack in */
	movq	%r11, %rsp

	/* move the stack to point to guest regs */
	addq	$LG_CPU_regs, %rsp

	/* skip the cr3 (we already loaded it) */
	addq	$8, %rsp

	/* Now we swap gs to the guest gs base */
	swapgs

	/* restore guest registers */
	RESTORE_REGS
	addq	$8, %rsp  /* skip %fs */
	/* skip trapnum and errorcode */
	addq	$0x10, %rsp;
	iretq

#define SWITCH_TO_HOST_NO_REGS						\
	/* Save old pgdir */						\
	movq	%cr3, %rax;						\
	pushq	%rax;							\
	/* Point rdi to the vcpu struct */				\
	get_vcpu %rdi %rax;						\
	/* Load the host page tables since that's where the gdt is */	\
	movq    LG_CPU_host_cr3(%rdi), %rax;			\
	/* Make the rdi point to the hosts version of the vcpu struct */ \
	movq	LG_CPU_cpu(%rdi), %rdi ;				\
	movq    %rax, %cr3;						\
	/* Put back the host process gs */				\
	movl  	$MSR_KERNEL_GS_BASE,%ecx;				\
	movq    LG_CPU_host_proc_gs_a(%rdi), %rax;			\
	movq    LG_CPU_host_proc_gs_d(%rdi), %rdx;			\
	wrmsr;								\
	/* Swap back to the host PDA */					\
	movl  	$MSR_GS_BASE,%ecx;					\
	movq    LG_CPU_host_gs_a(%rdi), %rax;			\
	movq    LG_CPU_host_gs_d(%rdi), %rdx;			\
	wrmsr;								\
	/* Switch to hosts gdt */					\
	lgdt    LG_CPU_host_gdt(%rdi);				\
	/* Switch to host's TSS. */					\
	movl	$(GDT_ENTRY_TSS*8), %eax;				\
	ltr	%ax;							\
	/* With PDA back now switch to host idt */			\
	lidt    LG_CPU_host_idt(%rdi);				\
	/* Set guest's TSS to available (clear byte 5 bit 2). */	\
	movq    LG_CPU_cpu(%rdi), %rax;				\
	andb	$0xFD, (LG_CPU_gdt_table+GDT_ENTRY_TSS*8+5)(%rax);	\
	movq	LG_CPU_host_stack(%rdi), %rsp;			\
	RESTORE_REGS;							\
	popq	%fs;

#define SWITCH_TO_HOST							\
	SAVE_REGS;							\
	SWITCH_TO_HOST_NO_REGS

/* Return to run_guest_once. */
return_to_host:
	SWITCH_TO_HOST
	iretq

#define PTE_MASK ~((0x3fff<<52)|0xfff)

#define DEBUG_PF_LEVEL 0

/*
 * Walk the guest page tables and see if we should just do
 * the guest page fault handler, without needing to switch to host.
 */
do_page_fault:
	cli
	SAVE_REGS

	/* r10 = cr2 */
	/* r11 = guest data */
	/* Save the cr2 since we might fault again */
	movq	%cr2, %r10
	pushq	%r10

	/* find our vcpu struct */
	get_vcpu  %rdi, %rax
	/* get the guest data */
	get_vcpu_data %r11, %rdi

#if 0	/* force to go to host */
	orq	$LG_CPU_IRQFAULT_FL, LG_CPU_DATA_flags(%r11)
#endif

	/*
	 * If we already faulted, then we need to do
	 * the switch to host anyways.
	 */
	testq	$LG_CPU_ANYFAULT_FL, LG_CPU_DATA_flags(%r11)
	jz	2f

fault_back_to_host:

#if 0	/* someone else is using this */
	testq	$LG_CPU_IRQFAULT_FL, LG_CPU_DATA_flags(%r11)
	jz	9f
	PRINT_STR_7('g','f','p',' ','f','l','t')
	PRINT_NL
9:
#endif

	/* we faulted already, must switch to host */
	/* but first put back the stack. */
	leaq	LG_CPU_regs(%r11), %rsp
	/* clear the faulted flag */
    movq    $LG_CPU_ANYFAULT_FL, %r10
    notq    %r10
	andq	%r10, LG_CPU_DATA_flags(%r11)

	 /*
	  * We haven't stored the cr3 yet
	  * And we need to restore the cr2 reg
	  * which so happens to be located at the cr3 part :-)
	  */
	popq	%r10
	movq	%r10, %cr2
	SWITCH_TO_HOST_NO_REGS
	iretq
2:
	/* set the faulted flag so we know if we fault again */
	orq	$LG_CPU_PGFAULT_FL, LG_CPU_DATA_flags(%r11)

	/* Read the guest page tables */
	movq	LG_CPU_gcr3(%rdi), %r14

#if DEBUG_PF_LEVEL > 6
	PRINT_STR_VADDR
	PRINT_QUAD(%r10)

	PRINT_STR_CR('3')
	PRINT_QUAD(%r14)
#endif

	/* r10 has the fault address */
	/* r12 is the PTE_MASK */
	/* r13 is the index */
	/* r14 will read the next page level */
	/* r15 will be the va convert. */

	/* FIXME: Have the guest set this value! */
	/*          0xffff810000000000  */
	movq	$0xffff81, %r15 
	shl	$40, %r15 
	/*          0xffffffff80000000 */
	/*	movq	$((1<<31)-1), %r15 */
	/*	notq	%r15 */

	movq	$PTE_MASK, %r12

#if DEBUG_PF_LEVEL > 20
	PRINT_STR_3('v','a',':')
	PRINT_QUAD(%r15)
#endif

	movq	%r10, %r13
	shr	$39, %r13
	andq	$((1<<9)-1), %r13
	shl	$3, %r13
	addq	%r13, %r14
	addq	%r15, %r14

#if DEBUG_PF_LEVEL > 4
	PRINT_STR_PGD
	PRINT_QUAD(%r14)
#endif
	movq	(%r14), %r14

#if DEBUG_PF_LEVEL > 3
	PRINT_STR_PUD
	PRINT_QUAD(%r14)
#endif

	/* r14 now points to the PUD table */
	testq	$1, %r14
	/* is it present? */
	jz	3f
	/* mask off the flag bits */
	andq	%r12, %r14
	movq	%r10, %r13
	shr	$30, %r13
	andq	$((1<<9)-1), %r13
	shl	$3, %r13
	addq	%r13, %r14
	addq	%r15, %r14
	movq	(%r14), %r14

#if DEBUG_PF_LEVEL > 2
	PRINT_STR_PMD
	PRINT_QUAD(%r14)
#endif

	/* r14 now points to the PMD table */
	testq	$1, %r14
	/* is it present? */
	jz	3f
	/* mask off the flag bits */
	andq	%r12, %r14
	movq	%r10, %r13
	shr	$21, %r13
	andq	$((1<<9)-1), %r13
	shl	$3, %r13
	addq	%r13, %r14
	addq	%r15, %r14
	movq	(%r14), %r14

#if DEBUG_PF_LEVEL > 1
	PRINT_STR_PTE
	PRINT_QUAD(%r14)
#endif

	/* r14 now points to the PTE table */
	testq	$1, %r14
	/* is it present? */
	jz	3f
	/* is it a 2M page? */
	testq	$(1<<7), %r14
	jnz	2f

	/* here we handle 4Mpages */
	/* mask off the flag bits */
	andq	%r12, %r14
	movq	%r10, %r13
	shr	$12, %r13
	andq	$((1<<9)-1), %r13
	shl	$3, %r13
	addq	%r13, %r14
	addq	%r15, %r14
	movq	(%r14), %r14

	testq	$1, %r14
	/* is it present? */
	jz	3f

2:
	/* Found the page, perhaps it was Write on Read only? */
	/*    dirty    Page R/W			*/
	/*       0        0     =    OK		*/
	/*       0        1     =    OK		*/
	/*       1        0     =    FAULT	*/
	/*       1        1     =    OK		*/
	/*					*/
	/*  This is the same as ^dirty OR Page R/W */
	/*       1   or   0      =    1		*/
	/*       1   or   1      =    1		*/
	/*       0   or   0      =    0		*/
	/*       0   or   1      =    1		*/
	/*					*/

	movq	LG_CPU_errcode(%r11), %r12
	/* The page exists for the guest */

	/* Even if we fault, the Host doesn't look at this bit */
	orq	$1, %r12
	movq	%r12, LG_CPU_errcode(%r11)

#if DEBUG_PF_LEVEL > 1
	PRINT_STR_6('E','o','r','r','o',':')
	PRINT_QUAD(%r12);
#endif

	movq	%r12, %rbx
	notq	%rbx
	andq	$(1<<1), %rbx
	andq	$(1<<1), %r14
	or	%rbx, %r14
	testq	%r14, %r14
	/* the premissions OK? switch to host then */
	jnz	fault_back_to_host

#if DEBUG_PF_LEVEL > 0
	PRINT_STR_5('P','e','r','m',':')
	PRINT_QUAD(%r14)
#endif

3:
	/* OK it is official! */
	/* No need to switch to host. Jump to guest page fault table */
	/* Make the cr2 visible to the guest  */
	movq	%r10, LG_CPU_DATA_cr2(%r11)

	/* FIXME: perhaps do checking here too? */
	movq	$0, LG_CPU_DATA_last_pgd(%r11)

#if DEBUG_PF_LEVEL > 0
	PRINT_STR_5('F','a','u','l','t')
	PRINT_NL

	PRINT_STR_VADDR
	PRINT_QUAD(%r10)
#endif
	/*
	 * While we still have use of regs, lets
	 * update the iretq part of the stack.
	 * After all this work, we might still take a page fault
	 * updating the guest stack!
	 */
	/* were we kernel or userspace? */
	leaq	LG_CPU_regs(%r11), %r9
	movq	LGUEST_REGS_cs(%r9), %rax
	movq	%rax, %r12
	movq	LGUEST_REGS_rsp(%r9), %r10

	andq	$3, %rax
	cmp	$1, %rax
	je	1f

#if DEBUG_PF_LEVEL > 0
	PRINT_L('U')
#endif
	/* We we're in user land, so we need to update the stack */
	movq	LG_CPU_DATA_tss_rsp0(%r11), %rax
	movq	LGUEST_REGS_ss(%r9), %rdx
	
	jmp	2f
1:

#if DEBUG_PF_LEVEL > 0
	PRINT_L('K')
#endif

	/* keep the same stack */
	movq	%r10, %rax
	movq	$(__KERNEL_DS | 1), %rdx
	movq	$(__KERNEL_CS), %r12
2:
	/* r9 should still hold pointer to regs */

	/*
	 * Put guest rflags in r15 and see if we have
	 * interrupts enabled.
	 */
	movq	LGUEST_REGS_rflags(%r9), %r15

	movq	$(1<<9), %r9

	testq	%r9, LG_CPU_DATA_irq_enabled(%r11)
	jz	5f

	/* interrupts were enabled */
	orq	%r9, %r15

	jmp	6f
5:
	/* interrupts were disabled */
	notq	%r9
	andq	%r9, %r15

6:

	/* rax now holds the guest's stack pointer. */
	/* rdx = ss */
	/* r10 = rsp */
	/* r15 = rflags */
	/* r12 = cs */


	subq	$48, %rax

	movq	%rdx, 40(%rax)
	movq	%r10, 32(%rax)
	movq	%r15, 24(%rax)
	movq	%r12, 16(%rax)

	leaq	LG_CPU_regs(%r11), %r10
	/* r10 now holds a pointer to regs */

	movq	LGUEST_REGS_rip(%r10), %r9

#if DEBUG_PF_LEVEL > 0
	movq	%rax, %r15
	PRINT_STR_4('R','I','P',':')
	PRINT_QUAD(%r9)
	movq	%r15, %rax
#endif

	movq	%r9, 8(%rax)
	movq	LG_CPU_errcode(%r11), %r9
	movq	%r9, 0(%rax)

#if DEBUG_PF_LEVEL > 0
	movq	%rax, %r15
	PRINT_STR_6('G','u','e','s','t',' ')
	PRINT_STR_STACK
	PRINT_NL
	PRINT_QUAD(40(%r15))
	PRINT_QUAD(32(%r15))
	PRINT_QUAD(24(%r15))
	PRINT_QUAD(16(%r15))
	PRINT_QUAD(8(%r15))
	PRINT_QUAD(0(%r15))
	movq	%r15, %rax
#endif

	/* rsp points to our regs that we will now pop */
	/* update the iretq fields for our jmp back to guest */
	/*  rax = guest stack */
	leaq	LGUEST_REGS_rip(%rsp), %r10
	movq	$(__KERNEL_DS | 1), 32(%r10)
	movq	%rax, 24(%r10)
	/* rflags should be ok already */
	movq	$(__KERNEL_CS | 1), 8(%r10)

	/* Finally get the fault handler to jump to */
	movq	LG_CPU_page_fault_handler(%rdi), %r9
	movq	%r9, 0(%r10)
	

#if DEBUG_PF_LEVEL > 0
	PRINT_STR_5('H','o','s','t',' ')
	PRINT_STR_STACK
	PRINT_NL
	PRINT_QUAD(40(%r10))
	PRINT_QUAD(32(%r10))
	PRINT_QUAD(24(%r10))
	PRINT_QUAD(16(%r10))
	PRINT_QUAD(8(%r10))
	PRINT_QUAD(0(%r10))
#endif

	/* If we need to disable interrupts, do so */
	testq	$1, LG_CPU_page_fault_clear_if(%rdi)
	jz	1f

#if DEBUG_PF_LEVEL > 0
	PRINT_STR_8('I','F',' ','c','l','e','a','r')
	PRINT_NL
#endif

	movq	$0, LG_CPU_DATA_irq_enabled(%r11)
1:

	/* skip the cr2 */
	addq	$8, %rsp

#if DEBUG_PF_LEVEL > 0
	PRINT_STR_CR('2')
	PRINT_QUAD(%r10)

	PRINT_STR_7(' ','B','o','u','n','c','e')
	PRINT_NL
#endif

	RESTORE_REGS
	/* skip fs, trapnum and errorcode */
	addq	$24, %rsp

	/* here we go! */
	iretq


/* see if we can emulate swapgs! */
do_gfp:
	cli
	SAVE_REGS

	/* In case we take a fault, let the page
	 * fault handler push us back to the host with
	 * the gfp.
	 */
	pushq	$0	/* CR2 for do_page_fault */

	/* find our vcpu struct */
	get_vcpu  %rdi, %rax
	/* get the guest data */
	get_vcpu_data %r11, %rdi

	/* Have the do_page_fault push us to the host */
	orq	$LG_CPU_IRQFAULT_FL, LG_CPU_DATA_flags(%r11)

	/* If there's an error code, then just jump to host */
	movq	LG_CPU_errcode(%r11), %rax
	testq	%rax, %rax
	/* If not zero, than go back to host */
	jnz	fault_back_to_host

	/* lets take a look at the RIP */
	movq	LGUEST_REGS_rip(%rsp), %r12

	/* swapgs is 0f 01 f8 */
	cmpb	$0xf, 0(%r12)
	jne	fault_back_to_host

	cmpb	$0x1, 1(%r12)
	jne	fault_back_to_host

	cmpb	$0xf8, 2(%r12)
	jne	fault_back_to_host

	/* OK this is a swap gs */
	addq	$3, LGUEST_REGS_rip(%rsp)

	DO_SWAPGS %r11

#if 0
	PRINT_STR_6('S','W','A','P','G','S')
	PRINT_NL
#endif

	/* Should be safe now */
    movq    $LG_CPU_ANYFAULT_FL, %r12
    notq    %r12
	andq	%r12, LG_CPU_DATA_flags(%r11)
    /*should do something here*/

	/* Skip saved cr2 */
	addq	$8, %rsp

	RESTORE_REGS
	/* skip fs, trapnum and errorcode */
	addq	$24, %rsp

	/* here we go! */
	iretq

do_hcall:
	cli
	/*
	 * if this is just a update gs, then we don't need
	 * to save all regs or even switch to host.
	 */
	/* FIXME: Sorting them by from the most common down would
	   help a little bit */
	cmpq	$LHCALL_UPDATE_GS, %rax
	je	update_gs

	cmpq	$LHCALL_UPDATE_FS, %rax
	je	update_fs

	cmpq	$LHCALL_SWAPGS, %rax
	je	swap_gs

	cmpq	$LHCALL_SYSRET, %rax
	je	sys_ret

	SWITCH_TO_HOST
	iretq

swap_gs:
	/* Just save the minimum regs */
	DO_SWAPGS_USE_STACK

	jmp back_to_guest

update_fs:
	/* Just save the minimum regs */
	pushq	%rax
	pushq	%rdx
	pushq	%rcx
	pushq	%r11
	pushq	%rdi

	get_vcpu %rdi, %rax
	get_vcpu_data %r11, %rdi

	movq	LG_CPU_DATA_guest_fs_a(%r11), %rax
	movq	LG_CPU_DATA_guest_fs_d(%r11), %rdx

	/* Load the guest gs pointer */
	movl	$MSR_FS_BASE, %ecx
	wrmsr

	popq	%rdi
	popq	%r11
	popq	%rcx
	popq	%rdx
	popq	%rax

	jmp back_to_guest

update_gs:
	/* Just save the minimum regs */
	pushq	%rax
	pushq	%rdx
	pushq	%rcx
	pushq	%r11
	pushq	%rdi

	get_vcpu %rdi, %rax
	get_vcpu_data %r11, %rdi

	movq	LG_CPU_DATA_guest_gs_a(%r11), %rax
	movq	LG_CPU_DATA_guest_gs_d(%r11), %rdx

	/* Load the guest gs pointer */
	movl	$MSR_GS_BASE, %ecx
	wrmsr

	popq	%rdi
	popq	%r11
	popq	%rcx
	popq	%rdx
	popq	%rax

back_to_guest:

	/* skip the trapnum and errorcode */
	addq	$16, %rsp
	iretq

sys_ret:
	/* return to guest user space */
	/*
	 * We need to save all regs, since we
	 * might fault on reading guest stack.
	 */
	cli
	SAVE_REGS

	pushq	$0	/* CR2 for do_page_fault */

	/* Here rdx will hold the user stack */
	/* and rcx will hold the user rip */
	movq	%rdx, %r12

	/* find our vcpu struct */
	get_vcpu  %rdi, %r9
	/* get the guest data */
	get_vcpu_data %r11, %rdi

	/* Have the do_page_fault push us to the host */
	orq	$LG_CPU_IRQFAULT_FL, LG_CPU_DATA_flags(%r11)

	/* The guest saved the original rax and rdx on it's stack */

	leaq	LG_CPU_regs(%r11), %r10
	movq	LGUEST_REGS_rsp(%r10), %r9

	/* we may fault here, but that's ok, we'll handle it */
	movq	0(%r9), %rdx
	movq	8(%r9), %rax

	/* No more faulting here */

	/* put in the rax and rdx for the guest */
	movq	%rax, LGUEST_REGS_rax(%r10)
	movq	%rdx, LGUEST_REGS_rdx(%r10)

	/* put in the user stack and rip to go to. */
	movq	%r12, LGUEST_REGS_rsp(%r10)
	movq	%rcx, LGUEST_REGS_rip(%r10)

	/* put in __USER_DS and __USER_CS */
	movq	$__USER_DS, LGUEST_REGS_ss(%r10)
	movq	$__USER_CS, LGUEST_REGS_cs(%r10)

	/* r11 holds the flags that the guest wants set */
	movq	LGUEST_REGS_r11(%r10), %r9

	/* Check to enable or disable interrupts */
	testq	$(1<<9), %r9
	je	1f
	/* interrupts enabled */
	orq	$(1<<9), LG_CPU_DATA_irq_enabled(%r11)
	jmp	2f
1:
	/* interrupts disabled */
	movq	$(1<<9), %r8
	notq	%r8
	andq	%r8, LG_CPU_DATA_irq_enabled(%r11)
2:
	/* make sure the flags are ok to use for real */
	andq	$LGUEST_FLAGS_MASK, %r9
	orq	$LGUEST_FLAGS_SET, %r9

	movq	%r9, LGUEST_REGS_rflags(%r10)

	/* put in the USER DS for the saved SS */
	movq	$(__USER_DS), LG_CPU_DATA_old_ss(%r11)

	/* Finally, the guest expects us to do a swapgs */
	DO_SWAPGS %r11

	/* skip the $0 that was pushed */
	addq	$8, %rsp

	/* OK go back to the guest */
	RESTORE_REGS
	/* skip fs, trapnum and errorcode */
	addq	$24, %rsp

	/* here we go! */
	iretq
	

	

deliver_to_host:
	SWITCH_TO_HOST
decode_idt_and_jmp:
	/* Decode IDT and jump to hosts' irq handler.  When that does iret, it
	 * will return to run_guest_once.  This is a feature. */
	/* We told gcc we'd clobber rdi and rax... */
	/* rdi here also holds the vcpu struct (host version) */
	get_host_vcpu_data %rdi %rdi
	movq	LG_CPU_trapnum(%rdi), %rdi
	shl	$1, %rdi
	leaq	(%rax,%rdi,8), %rdi
	DECODE_IDT %rdi %di %rax
	jmp	*%rax



.global lguest_syscall_trampoline
	.type lguest_syscall_trampoline, @function
lguest_syscall_trampoline:
	/*
	 * Tricky, we don't have much to choose from here.
	 * The only way to get to our stack is with swapgs.
	 * Our kernel gs points to the vcpu RO data that holds the
	 * the stack we want. But we can't save off the guest rsp
	 * in that area. We calculated the offset from the RO data
	 * to the RSP regs in the RW area in asm-offsets.c. Using
	 * this we can save off the rsp first!
	 */

	/* we already had our swapgs done for us */

	/* now gs points to our VCPU RO Data */

	/* first save the stack! */
	movq	%rsp, %gs:LG_CPU_save_rsp;

	/* Now load the rsp to point to the RW data field */
	movq   %gs:0, %rsp;

	/* save off rax, and load the vcpu data into it */
	movq   %rax, LG_CPU_regs_rax(%rsp);
	movq   %rsp, %rax

	/* see if we need to disable interrupts */
	testq	$(1<<9),  LG_CPU_DATA_SFMASK(%rax)
	jz	1f
	movq	$0, LG_CPU_DATA_irq_enabled(%rax)
1:

	/* Is this a hypercall? */
	testq	$LG_CPU_HC_FL, LG_CPU_DATA_flags(%rax)
	jnz	handle_hcall

#if 0
	/* Debugging save regs so we can print */
	addq $LG_CPU_trapnum, %rsp
	SAVE_REGS
	movq	%rax, %r11
	
	PRINT_STR_SYSCALL
	PRINT_QUAD(%r11)

	PRINT_STR_STACK
	movq	LG_CPU_regs_rsp(%r11), %r10
	PRINT_QUAD(%r10)

	PRINT_STR_7('L','S','T','A','R',':',' ')
	movq	LG_CPU_DATA_LSTAR(%r11), %r10
	PRINT_QUAD(%r10)

	PRINT_STR_5('S','W','A','P','?')
	movq	LG_CPU_DATA_flags(%r11), %r10
	PRINT_QUAD(%r10)

	RESTORE_REGS
	/* skip fs */
	addq	$8, %rsp
	subq	$LG_CPU_trapnum, %rsp	/* skip %fs */
#endif

	/* Lets give ourselves some playing area */
	addq	$LG_CPU_regs, %rsp

	/* do the swapgs if requested */
	testq	$LG_CPU_SWAPGS_FL, LG_CPU_DATA_flags(%rax)
	je	1f
#if 0
	PUSH_PRINT
	PRINT_STR_6('S','W','A','P','G','S')
	PRINT_NL
	POP_PRINT
#endif
	/* We now have a stack to use */
	/* go back to the guest's gs */
	swapgs
	DO_SWAPGS_USE_STACK
	/* and then back to HV gs */
	swapgs
1:
	/*
	 * The stack has enough to do a jump to the guest kernel.
	 * We store the guest LSTAR register in the RW area
	 * because we don't care if the guest messes with it.
	 * If it is a bad address, we fault from the guest side
	 * and we kill the guest. No harm done to the host.
	 */
	pushq	$(__KERNEL_DS | 1)
	pushq	LG_CPU_regs_rsp(%rax)
	pushfq
	/* Make sure we have actual interrupts on */
	orq	$(1<<9), 0(%rsp)
	pushq	$(__KERNEL_CS | 1)
	pushq	LG_CPU_DATA_LSTAR(%rax)
	
	/* Restore the rax */
	movq	LG_CPU_regs_rax(%rax), %rax

	swapgs
	iretq
	

/* both rax and rsp have the vcpu RW data */
handle_hcall:
	/* Coming from syscall */
    movq    $LG_CPU_HC_FL, %r9
    notq    %r9
	andq	%r9, LG_CPU_DATA_flags(%rax)
    /*should do something here*/

	/* Update us like if we are comming from a trap. */
	addq	$LG_CPU_regs, %rsp
	addq	$LGUEST_REGS_size, %rsp
	/* Hypercalls only come from kernel */
	pushq	$(__KERNEL_DS | 1)
	/* we already saved the rsp */
	subq	$8, %rsp
	pushfq
	/* make sure interrupts are on for guest */
	orq	$(1<<9), 0(%rsp)
	pushq	$(__KERNEL_CS | 1)
	/* Syscall holds the rip in rcx */
	pushq	%rcx
	/* Now for error code and LGUEST HCALL */
	pushq	$0
	pushq	$LGUEST_TRAP_ENTRY

	/* trap hcall expects rcx to have 3rd parameter */
	movq   %rdi, %rcx

	/* put back the original rax */
	movq	LG_CPU_regs_rax(%rax), %rax

	swapgs

	/* Now we are just like if we came from the trap */
	jmp do_hcall

	
/* Used by NMI only */
/*
 * The NMI is special because it uses its own stack.
 */
nmi_trampoline:
#if 0
	addq	$0x10, %rsp
	iretq
#endif
	/* nmi has it's own stack */
	SAVE_REGS

	/* save the cr3 */
	movq     %cr3, %rax
	pushq	 %rax

	movq	LGUEST_REGS_rip(%rsp), %r8

#if 0 /* in case we want to see where the nmi hit */
	PRINT_L('R')
	PRINT_QUAD(%r8)
#endif

	/*
	 * All guest descriptors are above the HV text code (here!)
	 * If we hit the suspected NMI race, our stack will be the host
	 * kernel stack, and that is in lower address space than the HV.
	 * So test to see if we are screwed. Don't do anything, but just
	 * report it!
	 */
	call   12f
12:
	popq	%r12 /* put this RIP into r12 */

#if 0
	/* If rsp >= r12; jmp */
	cmpq	%r12, %rsp
	jge	1f

	PRINT_STR_4('H','i','t',' ')
	PRINT_STR_4('N','M','I',' ')
	PRINT_STR_4('r','a','c','e')
	PRINT_NL

1:
#endif
	/* We use r12 from above to find the end of code. */
	/* r8 has the RIP of where we took the NMI */

	/* get the vcpu and guest data structures */
	get_vcpu    %rdi, %rax
	get_vcpu_data %r11, %rdi

	/*
	 * If we take another NMI while saving, we need to start over
	 * and try again. It's OK as long as we don't overwrite
	 * the saved material.
	 * This would be a lot easier if we could just set a flag that
	 * tells us that we already saved the data, but unfortunately
	 * we can't trust any writable code (the guest can also write
	 * to it).  So instead we test the rip that we came from.
	 * If it came from within this code segment, then we have
	 * a recursive NMI.
	 */
	
	/* calculate the offset between back label 12 and r12 */
	movq	%r12, %rax
	leaq	12b, %rbx
	subq	%rbx, %rax
	/* rax now holds the delta of hypervisor offset */

	/*
	 * If r8 (RIP from where the NMI happened) is
	 * greater than label 12, and less than
	 * the end of this routine, then we took a
	 * recursive NMI.
	 */
	/* r8 < r12 */
	cmpq	%r12, %r8
	jl	1f
	leaq	nmi_trampoline_end, %r12
	addq	%rax, %r12
	/* r8 <= r12 */
	cmpq	%r12, %r8
	jle	2f

1:

	/* Copy the saved regs */
	cld
	movq	%rdi,  %rbx   /* save off vcpu struct */
	leaq	LG_CPU_DATA_nmi_regs(%r11), %rdi
	leaq	0(%rsp), %rsi
    pushq   %rax          /* NOT sure it is really necessary*/
    movq    $LGUEST_REGS_size, %rax
    divq    0x08
	movq	%rax, %rcx
    popq    %rax
	rep	movsq

	movq	%rbx, %rdi  /* put back vcpu struct */

	/* save the gs base and shadow */
	movl	$MSR_GS_BASE, %ecx
	rdmsr
	movq	%rax, LG_CPU_DATA_nmi_gs_a(%r11)
	movq	%rdx, LG_CPU_DATA_nmi_gs_d(%r11)

	movl	$MSR_KERNEL_GS_BASE, %ecx
	rdmsr
	movq	%rax, LG_CPU_DATA_nmi_gs_shadow_a(%r11)
	movq	%rdx, LG_CPU_DATA_nmi_gs_shadow_d(%r11)

	/* save the gdt */
	sgdt	LG_CPU_DATA_nmi_gdt(%r11)
	jmp 3f
2:
#if 0
	PRINT_STR_3('r','e','c')
	PRINT_NL
#endif
3:
#if 0
	PRINT_STR_4('N','M','I',' ')
	PRINT_STR_6('l','g','u','e','s','t')
	PRINT_NL
#endif
	/* NMI SWITCH TO HOST */

	/* Force switch to host, GDT, CR3, and both GS bases */
	movq    LG_CPU_host_cr3(%rdi), %rax
	movq	%rax, %cr3

	movl    $MSR_KERNEL_GS_BASE, %ecx
	movq    LG_CPU_host_proc_gs_a(%rdi), %rax
	movq    LG_CPU_host_proc_gs_d(%rdi), %rdx
	wrmsr
	movl    $MSR_GS_BASE, %ecx
	movq    LG_CPU_host_gs_a(%rdi), %rax
	movq    LG_CPU_host_gs_d(%rdi), %rdx
	wrmsr

#if 0
	/* Set host's TSS to available (clear byte 5 bit 2). */
	movq	LG_CPU_host_gdt_ptr(%rdi), %rax
	andb	$0xFD, (GDT_ENTRY_TSS*8+5)(%rax)
#endif

	/* we want to come back here on the iret */
	pushq  $__HV_DS
	/* put the vcpu guest data as our stack */
	pushq %r11
	pushfq
	pushq	$__HV_CS

	/*
	 * We wont be able to use the stack on return,
	 * so we need to save the VCPU address.
	 */
	movq	%rdi, LG_CPU_DATA_nmi_vcpu(%r11)

	movq    LG_CPU_host_idt_address(%rdi), %rax

	/* Decode the location of the host NMI handler */
	leaq   32(%rax), %rbx   /* NMI IDT entry */
	DECODE_IDT %rbx %bx %rax

	callq   *%rax

	/*
	 * Back from NMI, stack points to vcpu guest data, and we can take
	 * more NMIs at this point. That's OK, since we only
	 * want to get to the original NMI interruption. We
	 * just restart this restore process. Nested NMIs will
	 * not destroy this data.
	 */
	movq    %rsp, %r11

	/* get the VCPU that we saved before the call */
	movq	LG_CPU_DATA_nmi_vcpu(%r11), %rdi

	/* restore the gdt */
	lgdt	LG_CPU_DATA_nmi_gdt(%r11)

#if 0
	/* make both host and guest TSS available */
	movq	LG_CPU_host_gdt_ptr(%rdi), %rax
	andb	$0xFD, (GDT_ENTRY_TSS*8+5)(%rax)

	andb	$0xFD, (LG_CPU_gdt_table+GDT_ENTRY_TSS*8+5)(%rdi)

	movl	$(GDT_ENTRY_TSS*8), %ebx
	ltr	%bx
#endif

	/* restore the gs base and shadow */
	movl   $MSR_KERNEL_GS_BASE, %ecx
	movq   LG_CPU_DATA_nmi_gs_shadow_a(%r11), %rax
	movq   LG_CPU_DATA_nmi_gs_shadow_d(%r11), %rdx
	wrmsr

	movl   $MSR_GS_BASE, %ecx
	movq   LG_CPU_DATA_nmi_gs_a(%r11), %rax
	movq   LG_CPU_DATA_nmi_gs_d(%r11), %rdx
	wrmsr

#if 1
	/* Flush the TLB */
	movq	%cr4, %rax
	movq	%rax, %rbx
	andb	$~(1<<7), %al
	movq	%rax, %cr4
	movq	%rbx, %cr4
#endif

	/* Set the stack to the returning regs */
	addq   $(LG_CPU_DATA_nmi_regs), %rsp

#if 0
	/* If ss is NULL put in HV DS */
	movq	LGUEST_REGS_ss(%rsp), %r8
	testq	%r8, %r8
	jne	1f
	movq	$__HV_DS, LGUEST_REGS_ss(%rsp)
1:
#endif

	/* restore the cr3 */
	popq	%rax
	movq	%rax, %cr3

	RESTORE_REGS
	/* No need to save the %fs on an NMI */
	addq	$8, %rsp

	/* skip trapnum and errcode */
	addq	$0x10, %rsp

	 /* use iret to get back to where we were. */
	 iretq;
	 /* Whoo, all done! */
nmi_trampoline_end:

do_crash:
	SAVE_REGS
	movq	%cr3, %rax;
	pushq	%rax;
	PRINT_STR_8('C','r','a','s','h','i','n','g')
	PRINT_NL

	PRINT_STR_5('R','S','P',':',' ')
	PRINT_QUAD(%rsp);

	dump_stack_regs 'S'

	addq	$16, %rsp
	sgdt	0(%rsp)
	PRINT_STR_6('G','D','T','L',':',' ')
	xorq	%r8, %r8
	movw	(%rsp), %r8
	PRINT_QUAD(%r8)
	PRINT_STR_6('G','D','T','A',':',' ')
	movq	2(%rsp), %r8
	PRINT_QUAD(%r8)

	PRINT_STR_4('C','S',':',' ')
	movq	%cs, %rbx
	PRINT_QUAD(%rbx)
	movq	%cs, %rbx
	andb	$(~3), %bl
	addq	%rbx, %r8
	movq	0(%r8), %r9
	PRINT_STR_5('S','E','G',':',' ')
	PRINT_QUAD(%r9);
	movq	$1, %r8;
	shl	$47, %r8
	andq	%r9, %r8
	PRINT_STR_4('P',' ',':',' ')
	PRINT_QUAD(%r8);
	PRINT_STR_4('D','P',':',' ')
	movq	$3, %r8;
	shl	$45, %r8
	andq	%r9, %r8
	PRINT_QUAD(%r8);


	/* just die! */
2:
	pause
	jmp 2b


/* we may double fault in the HV, so make a safe passage back to host */
double_fault_safe:
#if 1
	PRINT_STR_STACK
	PRINT_QUAD(%rsp)
	PRINT_STR_4('S','0',' ',':'); PRINT_QUAD(0(%rsp));
	PRINT_STR_4('S','8',' ',':'); PRINT_QUAD(8(%rsp));
	PRINT_STR_4('S','1','0',':'); PRINT_QUAD(0x10(%rsp));
	PRINT_STR_4('S','1','8',':'); PRINT_QUAD(0x18(%rsp));
	PRINT_STR_4('S','2','0',':'); PRINT_QUAD(0x20(%rsp));
	PRINT_STR_4('S','2','8',':'); PRINT_QUAD(0x28(%rsp));
	PRINT_STR_4('S','3','0',':'); PRINT_QUAD(0x30(%rsp));
	PRINT_STR_4('S','3','8',':'); PRINT_QUAD(0x38(%rsp));
	PRINT_STR_4('S','4','0',':'); PRINT_QUAD(0x40(%rsp));
#endif	
	SAVE_REGS
	/*
	 * The stack is not at the location that SWITCH_TO_HOST expects.
	 * We need to copy the saved regs into the expected location
	 * and then move the rsp to where SWITCH_TO_HOST wants, and then
	 * simply call it.
	 */
	movq	%rsp, %rdi
	subq	$LG_CPU_DATA_df_stack_end, %rdi
	/* compensate for the saved regs */
	addq	$LGUEST_REGS_size, %rdi  /* compensate for saved regs */
	/* but we didn't save the cr3 */
	subq    $8, %rdi;

	/* compensate if our end pointer is not 16 bytes aligned */
	movq	 $LG_CPU_DATA_df_stack_end, %rax
	andq	 $0xf, %rax;
	addq	 %rax, %rdi;

	/* now copy the regs to the proper place */
	cld
	movq	%rdi,  %rbx   /* save off vcpu struct */
	leaq	LG_CPU_regs(%rdi), %rdi
	addq	$8, %rdi /* don't count the cr3 */
	leaq	0(%rsp), %rsi
    pushq   %rax /* NOT sure it is really necessary */
    movq    $LGUEST_REGS_size, %rax
    divq    0x8
	movq	%rax, %rcx
    popq    %rax
	subq	$1, %rcx /* don't count the cr3 */
	rep	movsq

	movq	%rbx, %rdi  /* put back vcpu struct */

	PRINT_L('X')
	PRINT_QUAD(%rdi);

	/* now mov the rsp to the copied location and we are all set */
	leaq	LG_CPU_regs(%rdi), %rbx
	addq	$8, %rbx /* don't count the cr3 */
	movq	%rbx, %rsp

	/* Save old pgdir */						\
	PRINT_L('E');
	movq	%cr3, %rax;						\
	pushq	%rax;							\
	PRINT_L('F');
	/* Point rdi to the vcpu struct */				\
	movq	%rsp, %rdi;						\
	subq	$LG_CPU_regs, %rdi;				\
	PRINT_L('G');
	PRINT_QUAD(%rdi);
	/* Load lguest ds segment for convenience. */			\
	movq	$(__HV_DS), %rax;					\
	movq	%rax, %ds;						\
	PRINT_L('H');
	/* Load the host page tables since that's where the gdt is */	\
	movq    LG_CPU_host_cr3(%rdi), %rax;			\
	movq    %rax, %cr3;						\
	PRINT_L('I');
	/* Switch to hosts gdt */					\
	lgdt    LG_CPU_host_gdt(%rdi);				\
	PRINT_L('J');
	/* Set guest's TSS to available (clear byte 5 bit 2). */	\
	movq    LG_CPU_cpu(%rdi), %rax;				\
	andb	$0xFD, (LG_CPU_gdt_table+GDT_ENTRY_TSS*8+5)(%rax);	\
	PRINT_L('K');
	movl  	$MSR_GS_BASE,%ecx;				\
	movq    LG_CPU_host_gs_a(%rdi), %rax;			\
	movq    LG_CPU_host_gs_d(%rdi), %rdx;			\
	wrmsr;								\
	/* Put back the host process gs as well */			\
	movl  	$MSR_KERNEL_GS_BASE,%ecx;				\
	movq    LG_CPU_host_proc_gs_a(%rdi), %rax;			\
	movq    LG_CPU_host_proc_gs_d(%rdi), %rdx;			\
	wrmsr;								\
	/* With PDA back now switch to host idt */			\
	lidt    LG_CPU_host_idt(%rdi);				\
	/* Switch to host's TSS. */					\
	movl	$(GDT_ENTRY_TSS*8), %eax;				\
	ltr	%ax;							\
	movq	LG_CPU_host_stack(%rdi), %rsp;			\
	RESTORE_REGS;							\
	popq	%fs;
	iretq

	SWITCH_TO_HOST_NO_REGS
	iretq	
	 
	

/* Real hardware interrupts are delivered straight to the host.  Others
   cause us to return to run_guest_once so it can decide what to do.  Note
   that some of these are overridden by the guest to deliver directly, and
   never enter here (see load_guest_idt_entry). */
.macro IRQ_STUB N TARGET
	.data; .quad 1f; .text; 1:
 /* Make an error number for most traps, which don't have one. */
/*  .if (\N <> 2) && (\N <> 8) && (\N < 10 || \N > 14) && (\N <> 17) */
  .if (\N <> 8) && (\N < 10 || \N > 14) && (\N <> 17)
	pushq	$0
 .endif
	pushq	$\N
	jmp	\TARGET
	.align 8
.endm

.macro IRQ_STUBS FIRST LAST TARGET
 irq=\FIRST
 .rept \LAST-\FIRST+1
	IRQ_STUB irq \TARGET
  irq=irq+1
 .endr
.endm

/* We intercept every interrupt, because we may need to switch back to
 * host.  Unfortunately we can't tell them apart except by entry
 * point, so we need 256 entry points.
 */
irq_stubs:
.data
.global _lguest_default_idt_entries
_lguest_default_idt_entries:
.text
	IRQ_STUBS 0 1 return_to_host		/* First two traps */
	IRQ_STUB 2 nmi_trampoline	/* NMI */
	IRQ_STUBS 3 7 return_to_host		/* Rest of traps */
	IRQ_STUB 8 double_fault_safe		/* Double fault! */
	IRQ_STUBS 9 12 return_to_host		/* Rest of traps */
#if 1
	IRQ_STUB 13 do_gfp			/* GPF! */
#else
	IRQ_STUB 13 return_to_host		/* GPF! */
#endif
#if 1
	IRQ_STUB 14 do_page_fault		/* Page Fault */
#else
	IRQ_STUB 14 return_to_host		/* Page Fault */
#endif
	IRQ_STUBS 15 30 return_to_host		/* Rest of traps */
	IRQ_STUB 31 do_hcall			/* hypercall */
	IRQ_STUBS 32 127 deliver_to_host	/* Real interrupts */
	IRQ_STUB 128 return_to_host		/* System call (overridden) */
	IRQ_STUBS 129 255 deliver_to_host	/* Other real interrupts */

/* use this part to copy for host side. */
.global _lguest_syscall_host
_lguest_syscall_host:
	swapgs
	jmp	*lguest_host_system_call
	
.macro syscall_jumps CPUS
  .rept \CPUS
	swapgs
	jmp	lguest_syscall_trampoline
	.align L1_CACHE_BYTES
  .endr
.endm

	.align L1_CACHE_BYTES
.global	_lguest_syscall_jumps
_lguest_syscall_jumps:
	syscall_jumps NR_CPUS

	.align PAGE_SIZE
.global end_hyper_text
	.type end_hyper_text, @function
end_hyper_text:
	nop
ENTRY(end_switcher_text)
