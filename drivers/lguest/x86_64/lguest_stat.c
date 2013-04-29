#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include "lg.h"

static struct dentry *lguest_d;
static struct dentry *lguest_d_hcall;
static struct dentry *lguest_d_traps;
static struct dentry *lguest_d_pghist;
static struct dentry *lguest_d_timehist;

static unsigned long lguest_total_hcalls[LGUEST_MAX_STAT_SZ];
static unsigned long lguest_total_traps[LGUEST_MAX_STAT_SZ];

static unsigned long lguest_total_hcall_times[LGUEST_MAX_STAT_SZ];
static unsigned long lguest_total_trap_times[LGUEST_MAX_STAT_SZ];

static unsigned long lguest_pg_hist[LGUEST_MAX_STAT_SZ];
static unsigned long lguest_time_hist[LGUEST_MAX_STAT_SZ];

DEFINE_SPINLOCK(lguest_stat_lock);

#define STAT_OFFSET 30
#define STAT_HCALL_FL	(1<<STAT_OFFSET)
#define STAT_TRAP_FL	(2<<STAT_OFFSET)
#define STAT_MASK	~(3<<STAT_OFFSET)

#define STAT_HCALL(cnt)	(STAT_HCALL_FL | cnt)
#define STAT_TRAP(cnt)	(STAT_TRAP_FL | cnt)

void lguest_stat_return_to_host(struct lg_cpu *cpu)
{
	struct lguest *lg = cpu->lg;
	struct lg_cpu_data *data = cpu->lg_cpu_data;
	unsigned long cnt;

	spin_lock(&lguest_stat_lock);
	if (cpu->regs->trapnum == LGUEST_TRAP_ENTRY) {
		cnt = cpu->regs->rax;
		if (unlikely(cnt > LGUEST_MAX_HCALLS))
			cnt = LGUEST_MAX_HCALLS;
		lg->stat_hcalls[cnt]++;
		lguest_total_hcalls[cnt]++;
		cpu->stat_cause = STAT_HCALL(cnt);
	}

	cnt = cpu->regs->trapnum;

	if (cnt != LGUEST_TRAP_ENTRY)
		cpu->stat_cause = STAT_TRAP(cnt);

	if (unlikely(cnt >= LGUEST_IRQS + FIRST_EXTERNAL_VECTOR)) {
		cnt = LGUEST_IRQS + FIRST_EXTERNAL_VECTOR - 1;
		WARN_ON(1);
	}
	lg->stat_traps[cnt]++;
	lguest_total_traps[cnt]++;
	spin_unlock(&lguest_stat_lock);
}

void lguest_stat_start_pagefault(struct lg_cpu *cpu)
{
	cpu->stat_pf = sched_clock();
}

void lguest_stat_end_pagefault(struct lg_cpu *cpu)
{
	u64 end = sched_clock();

	end -= cpu->stat_pf;
	/* measure in usecs */
	end /= 1000;

	if (end >= LGUEST_MAX_STAT_SZ)
		end = LGUEST_MAX_STAT_SZ;

	lguest_pg_hist[end]++;
}

void lguest_stat_start_time(struct lg_cpu *cpu)
{
	cpu->stat_time = sched_clock();
	if (!cpu->stat_time) /* off by one is ok ;-)  */
		cpu->stat_time = 1;
}

void lguest_stat_end_time(struct lg_cpu *cpu)
{
	u64 end;

	if (!cpu->stat_time)
		return;

	spin_lock(&lguest_stat_lock);
	end = sched_clock();

	end -= cpu->stat_time;
	/* measure in usecs */
	end /= 1000;

	if (cpu->stat_cause & STAT_HCALL_FL) {
		lguest_total_hcall_times[cpu->stat_cause & STAT_MASK] += end;
		lguest_total_trap_times[LGUEST_TRAP_ENTRY] += end;
	} else if (cpu->stat_cause & STAT_TRAP_FL)
		lguest_total_trap_times[cpu->stat_cause & STAT_MASK] += end;

	cpu->stat_cause = 0;

	if (end >= LGUEST_MAX_STAT_SZ)
		end = LGUEST_MAX_STAT_SZ;

	lguest_time_hist[end]++;


		
	spin_unlock(&lguest_stat_lock);
}

#define CALC_IDX(arr, v)					\
	((int)((char*)v - (char*)(arr)) /	sizeof(long))

static void *s_next(struct seq_file *m, void *v, loff_t *pos)
{
	unsigned long *arr = m->private;
	int i = (long)(v);

	(*pos)++;

	/* if i == 1, then this is first element */
	if (i == 1)
		i = 0;
	else
		i = CALC_IDX(arr, v) + 1;

	for (; i < LGUEST_MAX_STAT_SZ; i++)
		if (arr[i])
			return &arr[i];

	return NULL;
}

static void *s_start(struct seq_file *m, loff_t *pos)
{
	void *p = NULL;
	loff_t l = 0;

	for (p = (void *)1; p && l < *pos; p = s_next(m, p, &l))
		;

	return p;
}

static int hc_s_show(struct seq_file *m, void *v)
{
	unsigned long *arr = m->private;
	int i = (long)(v);
	unsigned long val;

	if (i == 1) {
		seq_printf(m,"Lguest Hypercall Histogram:");
		if (arr == lguest_total_hcalls)
			seq_printf(m, "   time(us)   Avg");
		seq_printf(m,"\n");
	} else {
		val = *(long*)v;
		i = CALC_IDX(arr, v);
		seq_printf(m, "\t%3d:  %9ld", i, val);

		if (arr == lguest_total_hcalls)
			seq_printf(m, "  %9ld  %9ld",
				   lguest_total_hcall_times[i],
				   lguest_total_hcall_times[i] / val);

		seq_printf(m,"\n");
	}

	return 0;
}

static int tr_s_show(struct seq_file *m, void *v)
{
	unsigned long *arr = m->private;
	int i = (long)(v);
	unsigned long val;

	if (i == 1) {
		seq_printf(m,"Lguest Trap Histogram:");
		if (arr == lguest_total_traps)
			seq_printf(m, "   time(us)   Avg");
		seq_printf(m,"\n");
	} else {
		val = *(long*)v;
		i = CALC_IDX(arr, v);
		seq_printf(m, "\t%3d:  %9ld", i, val);

		if (arr == lguest_total_traps)
			seq_printf(m, "  %9ld  %9ld",
				   lguest_total_trap_times[i],
				   lguest_total_trap_times[i] / val);

		seq_printf(m,"\n");
	}

	return 0;
}

static int pg_s_show(struct seq_file *m, void *v)
{
	unsigned long *arr = m->private;
	int i = (long)(v);
	unsigned long val;

	if (i == 1) {
		seq_printf(m,"Lguest Page fault hist (us):\n");
	} else {
		val = *(long*)v;
		i = CALC_IDX(arr, v);
		seq_printf(m, "\t%s%3d:  %ld\n",
			   i == LGUEST_MAX_STAT_SZ-1 ? ">" : "",
			   i, val);
	}

	return 0;
}

static int time_s_show(struct seq_file *m, void *v)
{
	unsigned long *arr = m->private;
	int i = (long)(v);
	unsigned long val;

	if (i == 1) {
		seq_printf(m,"Lguest HV time hist (us):\n");
	} else {
		val = *(long*)v;
		i = CALC_IDX(arr, v);
		seq_printf(m, "\t%s%3d:  %ld\n",
			   i == LGUEST_MAX_STAT_SZ-1 ? ">" : "",
			   i, val);
	}

	return 0;
}

static void s_stop(struct seq_file *m, void *p)
{
}

static struct seq_operations lguest_trseq_op = {
	.start = s_start,
	.next = s_next,
	.stop = s_stop,
	.show = tr_s_show,
};

static struct seq_operations lguest_hcseq_op = {
	.start = s_start,
	.next = s_next,
	.stop = s_stop,
	.show = hc_s_show,
};

static struct seq_operations lguest_pgseq_op = {
	.start = s_start,
	.next = s_next,
	.stop = s_stop,
	.show = pg_s_show,
};

static struct seq_operations lguest_timeseq_op = {
	.start = s_start,
	.next = s_next,
	.stop = s_stop,
	.show = time_s_show,
};

static int lguest_hcstat_open (struct inode *inode, struct file *file)
{
	int ret;

	ret = seq_open(file, &lguest_hcseq_op);
	if (!ret) {
		struct seq_file *m = file->private_data;
		m->private = inode->i_private;
	}

	return ret;
}

static int lguest_trstat_open (struct inode *inode, struct file *file)
{
	int ret;

	ret = seq_open(file, &lguest_trseq_op);
	if (!ret) {
		struct seq_file *m = file->private_data;
		m->private = inode->i_private;
	}

	return ret;
}

static int lguest_pghist_open (struct inode *inode, struct file *file)
{
	int ret;

	ret = seq_open(file, &lguest_pgseq_op);
	if (!ret) {
		struct seq_file *m = file->private_data;
		m->private = inode->i_private;
	}

	return ret;
}

static int lguest_timehist_open (struct inode *inode, struct file *file)
{
	int ret;

	ret = seq_open(file, &lguest_timeseq_op);
	if (!ret) {
		struct seq_file *m = file->private_data;
		m->private = inode->i_private;
	}

	return ret;
}

ssize_t zero_array(struct file *file, const char *buf, size_t count,
		   loff_t *f_pos)
{
	struct seq_file *m = file->private_data;
	unsigned long *arr = m->private;

	spin_lock(&lguest_stat_lock);

	memset(arr, 0, sizeof(long) * LGUEST_MAX_STAT_SZ);

	if (arr == lguest_total_hcalls)
		memset(lguest_total_hcall_times, 0,
		       sizeof(long) * LGUEST_MAX_STAT_SZ);

	if (arr == lguest_total_traps)
		memset(lguest_total_trap_times, 0,
		       sizeof(long) * LGUEST_MAX_STAT_SZ);

	spin_unlock(&lguest_stat_lock);

	return count;
}

static struct file_operations lguest_hcstat_fops = {
	.open = lguest_hcstat_open,
	.read = seq_read,
	.write = zero_array,
	.llseek = seq_lseek,
	.release = seq_release,
};

static struct file_operations lguest_trstat_fops = {
	.open = lguest_trstat_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = zero_array,
	.release = seq_release,
};

static struct file_operations lguest_pghist_fops = {
	.open = lguest_pghist_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = zero_array,
	.release = seq_release,
};

static struct file_operations lguest_timehist_fops = {
	.open = lguest_timehist_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = zero_array,
	.release = seq_release,
};

void lguest_stat_add_guest(struct lguest *lg)
{
	char buf[32];

	if (!lguest_d)
		return;

	sprintf(buf, "guest%d", lg->guestid);
	
	lg->dentry = debugfs_create_dir(buf, lguest_d);
	if (!lg->dentry) {
		printk("can't create guest entry\n");
		return;
	}
	lg->hcdentry = debugfs_create_file("stat_hcalls", 0444, lg->dentry,
				      &lg->stat_hcalls[0],
				      &lguest_hcstat_fops);
	lg->trdentry = debugfs_create_file("stat_traps", 0444, lg->dentry,
				      &lg->stat_traps[0],
				      &lguest_trstat_fops);
}

void lguest_stat_remove_guest(struct lguest *lg)
{
	if (lg->hcdentry)
		debugfs_remove(lg->hcdentry);
	if (lg->trdentry)
		debugfs_remove(lg->trdentry);
	if (lg->dentry)
		debugfs_remove(lg->dentry);
	lg->dentry = NULL;
}

void lguest_stat_init(void)
{
	lguest_d = debugfs_create_dir("lguest", NULL);
	if (!lguest_d) {
		printk("can't create lguest debugfs\n");
		return;
	}
	if (lguest_d == ERR_PTR(-ENODEV)) {
		printk("debugfs not configured in. Can't access lguest "
		       "from userspace\n");
		lguest_d = NULL;
		return;
	}

	lguest_d_hcall = debugfs_create_file("stat_hcalls", 0644, lguest_d,
					     &lguest_total_hcalls[0],
					     &lguest_hcstat_fops);
	lguest_d_traps = debugfs_create_file("stat_traps", 0644, lguest_d,
					     &lguest_total_traps[0],
					     &lguest_trstat_fops);
	lguest_d_pghist = debugfs_create_file("stat_pghist", 0644, lguest_d,
					      &lguest_pg_hist[0],
					      &lguest_pghist_fops);
	lguest_d_timehist = debugfs_create_file("stat_timehist", 0644, lguest_d,
					      &lguest_time_hist[0],
					      &lguest_timehist_fops);
}

void lguest_stat_cleanup(void)
{
	if (lguest_d_timehist)
		debugfs_remove(lguest_d_timehist);
	if (lguest_d_pghist)
		debugfs_remove(lguest_d_pghist);
	if (lguest_d_traps)
		debugfs_remove(lguest_d_traps);
	if (lguest_d_hcall)
		debugfs_remove(lguest_d_hcall);
	if (lguest_d)
		debugfs_remove(lguest_d);
	lguest_d = NULL;
}
