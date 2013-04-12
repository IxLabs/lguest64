#include <linux/linkage.h>
#include <linux/lguest.h>
#include <asm/segment.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/processor-flags.h>

/*
 * This is where we begin: we have a magic signature which the launcher looks
 * for.  The plan is that the Linux boot protocol will be extended with a
 * "platform type" field which will guide us here from the normal entry point,
 * but for the moment this suffices.  We pass the virtual address of the boot
 * info to lguest_init().
 *
 * We put it in .init.text will be discarded after boot.
 */
.section .init.text, "ax", @progbits
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

LGUEST_PATCH(cli, movq $0, lguest_data_vcpu+LGUEST_VCPU_DATA_irq_enabled)
LGUEST_PATCH(sti, movq $X86_EFLAGS_IF, lguest_data_vcpu+LGUEST_VCPU_DATA_irq_enabled)
LGUEST_PATCH(popf, movq %rdi, lguest_data_vcpu+LGUEST_VCPU_DATA_irq_enabled)
LGUEST_PATCH(pushf, movq lguest_data_vcpu+LGUEST_VCPU_DATA_irq_enabled, %rax)

.text
/* These demark the EIP range where host should never deliver interrupts. */
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
	movq	%rax, LGUEST_VCPU_DATA_irq_enabled(%rcx)
	/* save the old SS */
	movq	(32+8+8)(%rsp), %rax
	movq	%rax, LGUEST_VCPU_DATA_old_ss(%rcx)
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
	movq	$(__KERNEL_DS | 1), 32(%rsp)
	jmp	2f
1:
	movq	$(__USER_DS | 1), 32(%rsp)
2:
	/* we are always going to ring 1 or 3 */
	orq	$1, 8(%rsp)
	iretq
lguest_noirq_end:

/* the HV does the swapgs and seting of the stack */
ENTRY(lguest_syscall_return)
	pushq	%rax
	pushq	%rdx
	movq	%gs:pda_oldrsp, %rdx
	movq	$LHCALL_SYSRET, %rax
	int	$LGUEST_TRAP_ENTRY

ENTRY(lguest_swapgs)
	pushq	%rax
	pushq	%rcx
	movq	lguest_data_vcpu, %rcx
	movq	$LHCALL_SWAPGS, %rax
	orq	$LGUEST_VCPU_HC_FL, LGUEST_VCPU_DATA_flags(%rcx)
	/* rcx is overridden by the syscall too */
	syscall
	popq	%rcx
	popq	%rax
	retq
