#include <linux/linkage.h>
#include <linux/lguest.h>
#include <asm/lguest_hcall.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/processor-flags.h>

/* Our story starts with the kernel booting into startup_64 in
 * arch/x86/kernel/head_64.S.  It expects a boot header, which is created by
 * the bootloader (the Launcher in our case).
 *
 * The startup_64 function does very little: it clears the uninitialized global
 * C variables which we expect to be zero (ie. BSS) and then copies the boot
 * header and kernel command line somewhere safe.  Finally it checks the
 * 'hardware_subarch' field.  This was introduced in 2.6.24 for lguest and Xen:
 * if it's set to '1' (lguest's assigned number), then it calls us here.
 *
 * WARNING: be very careful here!  We're running at addresses equal to physical
 * addesses (around 0), not above __START_KERNEL_map as most code expectes
 * (eg. 0xffffffff80000000). Jumps are relative, so they're OK, but we can't 
 * touch any data without remembering to subtract __START_KERNEL_map!
 *
 * The .section line puts this code in .init.text so it will be discarded after
 * boot.
 */
.section .init.text, "ax", @progbits
ENTRY(lguest_entry)

.ascii "GenuineLguest"
	/* Set up initial stack. */
 	movq	$(init_thread_union+THREAD_SIZE),%rsp
	movq	%rsi, %rdi
	movq	$__PAGE_OFFSET, %rax
	addq	%rax, %rdi
	jmp lguest_init

/* The templates for inline patching. */
#define LGUEST_PATCH(name, insns...)			\
	lgstart_##name:	insns; lgend_##name:;		\
	.globl lgstart_##name; .globl lgend_##name

    /*
     * We make the "initialization" hypercall now to tell the Host about
     * us, and also find out where it put our page tables.
     */
    movq $LHCALL_LGUEST_INIT, %rax
    movq $lguest_data - __START_KERNEL_map, %rbx
    int $LGUEST_TRAP_ENTRY

    /* FIXME */
    /* Set up the initial stack so we can run C code. */
    movq stack_start(%rip), %rsp

    /* Jumps are relative: we're running __PAGE_OFFSET too low. */
    jmp lguest_init + __START_KERNEL_map

.text
#define LGUEST_PATCH(name, insns...)           \
    lgstart_##name: insns; lgend_##name:;       \
.globl lgstart_##name; .globl lgend_##name
.global lguest_noirq_start
.global lguest_noirq_end

    /*FIXME Ce e cu lguest_data_vcpu???*/
    //LGUEST_PATCH(cli, movq $0, lguest_data_vcpu+LG_CPU_DATA_irq_enabled)
    //LGUEST_PATCH(sti, movq $X86_EFLAGS_IF, lguest_data_vcpu+LG_CPU_DATA_irq_enabled)
    //LGUEST_PATCH(popf, movq %rdi, lguest_data_vcpu+LG_CPU_DATA_irq_enabled)
    //LGUEST_PATCH(pushf, movq lguest_data_vcpu+LG_CPU_DATA_irq_enabled, %rax)

ENTRY(lg_irq_enable)
    movq $X86_EFLAGS_IF, lguest_data+LGUEST_DATA_irq_enabled

    testq $0, lguest_data+LGUEST_DATA_irq_pending
    jnz send_interrupts

    ret

send_interrupts:
    pushq %rax
    //FIXME Asta era de la Psomas
    //Acest apel nu este definit pe X86_64
    //movq $LHCALL_SEND_INTERRUPTS, %rax

    .byte 0x0f,0x01,0xc1 

    popq %rax
    ret

ENTRY(lg_restore_fl)
    movq %rax, lguest_data+LGUEST_DATA_irq_enabled

    testq lguest_data+LGUEST_DATA_irq_pending, %rax
    jnz send_interrupts

    ret

    .global lguest_noirq_start
    .global lguest_noirq_end

/*
 * We move eflags word to lguest_data.irq_enabled to restore interrupt state.
 * For page faults, gpfs and virtual interrupts, the hypervisor has saved
 * eflags manually, otherwise it was delivered directly and so eflags reflects
 * the real machine IF state, ie. interrupts on.  Since the kernel always dies
 * if it takes such a trap with interrupts disabled anyway, turning interrupts
 * back on unconditionally here is OK.
 */
ENTRY(lguest_iret)
	pushq	%rax
	movq	(16+8)(%rsp), %rax
	andq	$X86_EFLAGS_IF, %rax
	pushq	%rcx
	movq	lguest_data_vcpu, %rcx
lguest_noirq_start:
	//movq	%rax, LG_CPU_DATA_irq_enabled(%rcx)
	/* save the old SS */
	movq	(32+8+8)(%rsp), %rax
	//movq	%rax, LG_CPU_DATA_old_ss(%rcx)
	popq	%rcx
	movq	$X86_EFLAGS_IF, %rax
	/* always have interrupts on */
	orq	%rax, (16+8)(%rsp)
	popq	%rax
	/*
	 * Seems that the kernel creates a new process with a
	 * 0 SS segment. But only ring 0 is allowed to have that.
	 * The guest may use the SS reg for info, so we also need
	 * to save what it is. We store it into the vcpu data
	 * and that will be used to push it back on the stack when
	 * we go back to user land.
	 *
	 * If we are going into guest kernel then load SS with
	 * the kernel SS descriptor otherwise load it with
	 * the user SS descriptor.
	 *
	 */
 	testq	$0x20, 8(%rsp)
	jnz	1f
	//movq	$(__KERNEL_DS | 1), 32(%rsp)
	jmp	2f
1:
	//movq	$(__USER_DS | 1), 32(%rsp)
2:
	/* we are always going to ring 1 or 3 */
	orq	$1, 8(%rsp)
	iretq
lguest_noirq_end:

/* the HV does the swapgs and seting of the stack */
//FIXME - Stefan
//Nu exista syscall_return in paravirt_ops
//Deci nu cred ca se ajunge la acest cod
/*
ENTRY(lguest_syscall_return)
	pushq	%rax
	pushq	%rdx
	//movq	%gs:pda_oldrsp, %rdx
	movq	$LHCALL_SYSRET, %rax
	int	$LGUEST_TRAP_ENTRY
*/
//Si cu asta ce fac ca nu vede niciun simbol definit in asm-offsets_64
ENTRY(lguest_swapgs)
	pushq	%rax
	pushq	%rcx
/*
	movq	lguest_data_vcpu, %rcx
	movq	$LHCALL_SWAPGS, %rax
	orq	$LG_CPU_HC_FL, LG_CPU_DATA_flags(%rcx)
*/
    /* rcx is overridden by the syscall too */
	syscall
	popq	%rcx
	popq	%rax
	retq
