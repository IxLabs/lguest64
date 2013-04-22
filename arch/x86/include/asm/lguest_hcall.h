/* Architecture specific portion of the lguest hypercalls */
#ifndef _ASM_X86_LGUEST_HCALL_H
#define _ASM_X86_LGUEST_HCALL_H

#define LHCALL_FLUSH_ASYNC	0
#define LHCALL_LGUEST_INIT	1



//TODO Just rename CRASH HYPERCALL in X86_64
#ifdef CONFIG_X86_64
#define LHCALL_CRASH		2
#endif
#ifdef CONFIG_X86_32
#define LHCALL_SHUTDOWN		2
#endif




#define LHCALL_LOAD_GDT     3
#define LHCALL_NEW_PGTABLE	4
#define LHCALL_FLUSH_TLB	5
#define LHCALL_LOAD_IDT_ENTRY	6
#define LHCALL_SET_STACK	7
#define LHCALL_TS		8





#ifdef CONFIG_X86_32
#define LHCALL_SET_CLOCKEVENT	9
#define LHCALL_HALT		10
#define LHCALL_SET_PMD		13
#define LHCALL_SET_PTE		14
#define LHCALL_SET_PGD		15
#define LHCALL_LOAD_TLS		16
#define LHCALL_NOTIFY		17
#define LHCALL_LOAD_GDT_ENTRY	18
#define LHCALL_SEND_INTERRUPTS	19
#endif


#ifdef CONFIG_X86_64
#define LHCALL_TIMER_READ	9
#define LHCALL_TIMER_START	10
#define LHCALL_HALT		    11
#define LHCALL_NOTIFY		13
#define LHCALL_FLUSH_TLB_SIG	15
#define LHCALL_SET_PTE		16
#define LHCALL_SET_PMD		17
#define LHCALL_SET_PUD		18
#define LHCALL_SET_PGD		19
#define LHCALL_CLEAR_PTE	20
#define LHCALL_CLEAR_PMD	21
#define LHCALL_CLEAR_PUD	22
#define LHCALL_CLEAR_PGD	23
#define LHCALL_LOAD_TLS		24
#define LHCALL_RDMSR		25
#define LHCALL_WRMSR		26
#define LHCALL_IRET		27
#define LHCALL_SWAPGS		28
#define LHCALL_SYSRET		31
#define LHCALL_RELEASE_PGD	32
#define LHCALL_APIC_WRITE	33
#define LHCALL_APIC_READ	34
#define LHCALL_S2H		35	/* switch to host */
#define LHCALL_UPDATE_GS	36
#define LHCALL_UPDATE_FS	37
#define LHCALL_CPU_IDLE		38
#define LHCALL_NEW_VCPU		39
#define LHCALL_REMOTE_CALL	40	
#define LHCALL_STOP_VCPUS	41	

#define LHCALL_PRINT		60
#define LHCALL_DEBUG_ME		99

#define LGUEST_MAX_HCALLS	100
#endif

#define LGUEST_TRAP_ENTRY 0x1F

/* Argument number 3 to LHCALL_LGUEST_SHUTDOWN */
#define LGUEST_SHUTDOWN_POWEROFF	1
#define LGUEST_SHUTDOWN_RESTART		2

#ifndef __ASSEMBLY__
#include <asm/hw_irq.h>

/*G:030
 * But first, how does our Guest contact the Host to ask for privileged
 * operations?  There are two ways: the direct way is to make a "hypercall",
 * to make requests of the Host Itself.
 *
 * Our hypercall mechanism uses the highest unused trap code (traps 32 and
 * above are used by real hardware interrupts).  Seventeen hypercalls are
 * available: the hypercall number is put in the %eax register, and the
 * arguments (when required) are placed in %ebx, %ecx, %edx and %esi.
 * If a return value makes sense, it's returned in %eax.
 *
 * Grossly invalid calls result in Sudden Death at the hands of the vengeful
 * Host, rather than returning failure.  This reflects Winston Churchill's
 * definition of a gentleman: "someone who is only rude intentionally".
 */
#ifdef CONFIG_X86_32
static inline unsigned long
hcall(unsigned long call,
      unsigned long arg1, unsigned long arg2, unsigned long arg3,
      unsigned long arg4)
{
	/* "int" is the Intel instruction to trigger a trap. */
	asm volatile("int $" __stringify(LGUEST_TRAP_ENTRY)
		     /* The call in %eax (aka "a") might be overwritten */
		     : "=a"(call)
		       /* The arguments are in %eax, %ebx, %ecx, %edx & %esi */
		     : "a"(call), "b"(arg1), "c"(arg2), "d"(arg3), "S"(arg4)
		       /* "memory" means this might write somewhere in memory.
			* This isn't true for all calls, but it's safe to tell
			* gcc that it might happen so it doesn't get clever. */
		     : "memory");
	return call;
}
#endif

#ifdef CONFIG_X86_64
static inline unsigned long
hcall_int(unsigned long call,
      unsigned long arg1, unsigned long arg2, unsigned long arg3)
{
	asm volatile("int $" __stringify(LGUEST_TRAP_ENTRY)
		     : "=a"(call)
		     : "a"(call), "d"(arg1), "b"(arg2), "c"(arg3)
		     : "memory");
	return call;
}

//arg4 was introduced to have the same signature
//as in X86_32 case
static inline unsigned long
hcall(unsigned long call,
      unsigned long arg1, 
      unsigned long arg2,
      unsigned long arg3,
      unsigned long arg4)
{
	long foo;
	unsigned long flags;

	/* Note, using syscall hcall may disable interrupts anyway */
	local_irq_save(flags);
	asm volatile("syscall"
		     : "=a"(call), "=c"(foo)
		     : "a"(call), "d"(arg1), "b"(arg2), "D"(arg3)
		     : "memory");
	local_irq_restore(flags);

	return call;
}

#endif
/*:*/

/* Can't use our min() macro here: needs to be a constant */
#define LGUEST_IRQS (NR_IRQS < 32 ? NR_IRQS: 32)

#define LHCALL_RING_SIZE 64
struct hcall_args {
	/* These map directly onto eax/ebx/ecx/edx/esi in struct lguest_regs */
	unsigned long arg0, arg1, arg2, arg3, arg4;
};

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_X86_LGUEST_HCALL_H */
