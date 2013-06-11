#include <asm/ia32.h>
#include <linux/lguest.h>
#include "../../../drivers/lguest/lg.h"
#define __SYSCALL_64(nr, sym, compat) [nr] = 1,
#define __SYSCALL_COMMON(nr, sym, compat) [nr] = 1,
#ifdef CONFIG_X86_X32_ABI
# define __SYSCALL_X32(nr, sym, compat) [nr] = 1,
#else
# define __SYSCALL_X32(nr, sym, compat) /* nothing */
#endif
static char syscalls_64[] = {
#include <asm/syscalls_64.h>
};
#define __SYSCALL_I386(nr, sym, compat) [nr] = 1,
static char syscalls_ia32[] = {
#include <asm/syscalls_32.h>
};

int main(void)
{
#ifdef CONFIG_PARAVIRT
	OFFSET(PV_IRQ_adjust_exception_frame, pv_irq_ops, adjust_exception_frame);
	OFFSET(PV_CPU_usergs_sysret32, pv_cpu_ops, usergs_sysret32);
	OFFSET(PV_CPU_usergs_sysret64, pv_cpu_ops, usergs_sysret64);
	OFFSET(PV_CPU_swapgs, pv_cpu_ops, swapgs);
	BLANK();
#endif

#ifdef CONFIG_IA32_EMULATION
	OFFSET(TI_sysenter_return, thread_info, sysenter_return);
	BLANK();

#define ENTRY(entry) OFFSET(IA32_SIGCONTEXT_ ## entry, sigcontext_ia32, entry)
	ENTRY(ax);
	ENTRY(bx);
	ENTRY(cx);
	ENTRY(dx);
	ENTRY(si);
	ENTRY(di);
	ENTRY(bp);
	ENTRY(sp);
	ENTRY(ip);
	BLANK();
#undef ENTRY

	OFFSET(IA32_RT_SIGFRAME_sigcontext, rt_sigframe_ia32, uc.uc_mcontext);
	BLANK();
#endif

#define ENTRY(entry) OFFSET(pt_regs_ ## entry, pt_regs, entry)
	ENTRY(bx);
	ENTRY(bx);
	ENTRY(cx);
	ENTRY(dx);
	ENTRY(sp);
	ENTRY(bp);
	ENTRY(si);
	ENTRY(di);
	ENTRY(r8);
	ENTRY(r9);
	ENTRY(r10);
	ENTRY(r11);
	ENTRY(r12);
	ENTRY(r13);
	ENTRY(r14);
	ENTRY(r15);
	ENTRY(flags);
	BLANK();
#undef ENTRY

#define ENTRY(entry) OFFSET(saved_context_ ## entry, saved_context, entry)
	ENTRY(cr0);
	ENTRY(cr2);
	ENTRY(cr3);
	ENTRY(cr4);
	ENTRY(cr8);
	BLANK();
#undef ENTRY

	OFFSET(TSS_ist, tss_struct, x86_tss.ist);
	BLANK();

	DEFINE(__NR_syscall_max, sizeof(syscalls_64) - 1);
	DEFINE(NR_syscalls, sizeof(syscalls_64));

	DEFINE(__NR_ia32_syscall_max, sizeof(syscalls_ia32) - 1);
	DEFINE(IA32_NR_syscalls, sizeof(syscalls_ia32));

#if defined(CONFIG_LGUEST) || defined(CONFIG_LGUEST_GUEST)
#define ENTRY(entry)  DEFINE(LG_CPU_##entry, offsetof(struct lg_cpu, entry))
    /* Used for offset of GS reg in syscall */
    //FIXME
    //Cred ca toate calculele trebuie refacute pentru ca acum am schimbat
    //locatia lui regs; Ei se mapeaza undeva la sfarsitul memoriei - nu mai
    //sunt in structura lg_cpu, ci doar se tine un pointer la ei
    //
    //Las numele tot asa pana imi dau seama ce-i cu ei
    DEFINE(LG_CPU_regs_rsp, offsetof(struct lguest_regs, rsp));
    DEFINE(LG_CPU_regs_rax, offsetof(struct lguest_regs, rax));
    DEFINE(LG_CPU_regs_rdx, offsetof(struct lguest_regs, rdx));
    DEFINE(LG_CPU_regs_rcx, offsetof(struct lguest_regs, rcx));
    /* Used in interrupt handling */
    DEFINE(LG_CPU_trapnum, offsetof(struct lguest_regs, trapnum));
    /* Used for page faulting */
    DEFINE(LG_CPU_errcode, offsetof(struct lguest_regs, errcode));
    ENTRY(cpu_hv);
    ENTRY(cpu);
    ENTRY(regs);
    ENTRY(debug);
    ENTRY(magic);
    ENTRY(host_stack);
    ENTRY(gcr3);
    ENTRY(guest_cr3);
    ENTRY(host_cr3);
    ENTRY(host_gs_a);
    ENTRY(host_gs_d);
    ENTRY(host_proc_gs_a);
    ENTRY(host_proc_gs_d);
    ENTRY(hv_gdt);
    ENTRY(gdt);
    ENTRY(idt);
    ENTRY(page_fault_handler);
    ENTRY(page_fault_clear_if);
    ENTRY(host_gdt);
    ENTRY(host_idt);
    ENTRY(host_gdt_ptr);
    ENTRY(gdt_table);
    DEFINE(LG_CPU_host_idt_address, offsetof(struct lg_cpu, host_idt.address));
#undef ENTRY
#define ENTRY(entry)  DEFINE(LG_CPU_DATA_##entry, offsetof(struct lg_cpu_data, entry))
    ENTRY(df_stack_end);
    ENTRY(nmi_regs);
    ENTRY(nmi_vcpu);
    ENTRY(flags);
    ENTRY(cr2);
    ENTRY(tss_rsp0);
    ENTRY(LSTAR);
    ENTRY(SFMASK);
    ENTRY(irq_enabled);
    ENTRY(last_pgd);
    ENTRY(last_rip);
    ENTRY(last_vaddr);
    ENTRY(guest_fs_a);
    ENTRY(guest_fs_d);
    ENTRY(guest_gs_a);
    ENTRY(guest_gs_d);
    ENTRY(guest_gs_shadow_a);
    ENTRY(guest_gs_shadow_d);
    ENTRY(old_ss);
    ENTRY(nmi_gs_a);
    ENTRY(nmi_gs_d);
    ENTRY(nmi_gs_shadow_a);
    ENTRY(nmi_gs_shadow_d);
    ENTRY(nmi_stack_end);
    ENTRY(nmi_gdt);
#undef ENTRY
#define ENTRY(entry)  DEFINE(LGUEST_REGS_##entry, offsetof(struct lguest_regs, entry))
    ENTRY(rsp);
    ENTRY(errcode);
    ENTRY(rip);
    ENTRY(size);
    ENTRY(cs);
    ENTRY(ss);
    ENTRY(rax);
    ENTRY(rdx);
    ENTRY(r11);
    ENTRY(rflags);
    BLANK();
    //FIXME
    //Rsp nu se mai afla acolo. Am mutat regs.
    DEFINE(LG_CPU_save_rsp,
           ((sizeof(struct lguest_regs)+(PAGE_SIZE-1)) & ~(PAGE_SIZE-1)) +
           offsetof(struct lguest_regs, rsp));
#undef ENTRY

   BLANK();
   OFFSET(LGUEST_DATA_irq_enabled, lguest_data, irq_enabled);
   OFFSET(LGUEST_DATA_irq_pending, lguest_data, irq_pending);
#if 0
   OFFSET(LGUEST_DATA_pgdir, lguest_data, pgdir);

   BLANK();

   OFFSET(LGUEST_PAGES_host_gdt_desc, lguest_pages, state.host_gdt_desc);
   OFFSET(LGUEST_PAGES_host_idt_desc, lguest_pages, state.host_idt_desc);
   OFFSET(LGUEST_PAGES_host_cr3, lguest_pages, state.host_cr3);
   OFFSET(LGUEST_PAGES_host_sp, lguest_pages, state.host_sp);
   OFFSET(LGUEST_PAGES_guest_gdt_desc, lguest_pages,state.guest_gdt_desc);
   OFFSET(LGUEST_PAGES_guest_idt_desc, lguest_pages,state.guest_idt_desc);
   OFFSET(LGUEST_PAGES_guest_gdt, lguest_pages, state.guest_gdt);
   OFFSET(LGUEST_PAGES_regs_trapnum, lguest_pages, regs.trapnum);
   OFFSET(LGUEST_PAGES_regs_errcode, lguest_pages, regs.errcode);
   OFFSET(LGUEST_PAGES_regs, lguest_pages, regs);
#endif
#endif
   return 0;
}
