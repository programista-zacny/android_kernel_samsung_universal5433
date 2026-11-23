/*
 * pidfd: file descriptors that refer to a process
 *
 * Backport to 3.10 of the mainline pidfd pieces Android's lmkd uses:
 *
 *   pidfd_open()         32fcb426ec00 "pid: add pidfd_open()"
 *   pidfd_send_signal()  3eb39f47934f "signal: add pidfd_send_signal() syscall"
 *   pidfd file, fdinfo   b3e583825266 "clone: add CLONE_PIDFD" (the file only)
 *   poll() for exit      b53b0b9d9a61 "pidfd: add polling support"
 *   waitid(P_PIDFD)      3695eae5fee0 "pidfd: add P_PIDFD to waitid()"
 *                        (the lookup; the hunk itself is in kernel/exit.c)
 *
 * Mainline keeps this code in kernel/pid.c, kernel/fork.c and
 * kernel/signal.c; it lives in one file here so that the whole feature
 * hangs off CONFIG_PIDFD.
 *
 * Not implemented: CLONE_PIDFD, pidfd_getfd(), and pidfd_send_signal()
 * on a /proc/<pid> directory file descriptor.
 */

#include <linux/anon_inodes.h>
#include <linux/compat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/poll.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/signal.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

static const struct file_operations pidfd_fops;

static struct pid *pidfd_pid(const struct file *file)
{
	if (file->f_op == &pidfd_fops)
		return file->private_data;

	return ERR_PTR(-EBADF);
}

static int pidfd_release(struct inode *inode, struct file *file)
{
	struct pid *pid = file->private_data;

	file->private_data = NULL;
	put_pid(pid);
	return 0;
}

#ifdef CONFIG_PROC_FS
static int pidfd_show_fdinfo(struct seq_file *m, struct file *f)
{
	/*
	 * Mainline uses the pid namespace of the procfs instance; a 3.10
	 * seq_file does not lead back to it, so use the reader's.
	 */
	struct pid_namespace *ns = task_active_pid_ns(current);
	struct pid *pid = f->private_data;

	return seq_printf(m, "Pid:\t%d\n", pid_nr_ns(pid, ns));
}
#endif

/*
 * Poll support for process exit notification.
 */
static unsigned int pidfd_poll(struct file *file, struct poll_table_struct *pts)
{
	struct task_struct *task;
	struct pid *pid = file->private_data;
	unsigned int poll_flags = 0;

	poll_wait(file, &pid->wait_pidfd, pts);

	rcu_read_lock();
	task = pid_task(pid, PIDTYPE_PID);
	/*
	 * Inform pollers only when the whole thread group exits.
	 * If the thread group leader exits before all other threads in the
	 * group, then poll(2) should block, similar to the wait(2) family.
	 */
	if (!task || (task->exit_state && thread_group_empty(task)))
		poll_flags = POLLIN | POLLRDNORM;
	rcu_read_unlock();

	return poll_flags;
}

static const struct file_operations pidfd_fops = {
	.release	= pidfd_release,
	.poll		= pidfd_poll,
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= pidfd_show_fdinfo,
#endif
};

/**
 * pidfd_get_pid - get a reference to the pid a pidfd refers to
 * @fd: the file descriptor
 *
 * Returns the pid with its reference count raised, or an ERR_PTR() if
 * @fd is not a pidfd.
 */
struct pid *pidfd_get_pid(unsigned int fd)
{
	struct fd f;
	struct pid *pid;

	f = fdget(fd);
	if (!f.file)
		return ERR_PTR(-EBADF);

	pid = pidfd_pid(f.file);
	if (!IS_ERR(pid))
		get_pid(pid);

	fdput(f);
	return pid;
}

/**
 * do_notify_pidfd - wake up the pollers of a task's pidfds
 * @task: the task whose exit state changed
 *
 * Called with tasklist_lock write-held, after @task->exit_state has been
 * set, so that a poller that queued itself before the wakeup sees the new
 * state when it looks (see b191d6491be6 "pidfd: fix a poll race when
 * setting exit_state").
 */
void do_notify_pidfd(struct task_struct *task)
{
	struct pid *pid = task_pid(task);

	if (pid)
		wake_up_all(&pid->wait_pidfd);
}

/**
 * pidfd_create() - Create a new pid file descriptor.
 *
 * @pid:  struct pid that the pidfd will reference
 *
 * This creates a new pid file descriptor with the O_CLOEXEC flag set.
 *
 * Return: On success, a cloexec pidfd is returned.
 *         On error, a negative errno number will be returned.
 */
static int pidfd_create(struct pid *pid)
{
	int fd;

	fd = anon_inode_getfd("[pidfd]", &pidfd_fops, get_pid(pid),
			      O_RDWR | O_CLOEXEC);
	if (fd < 0)
		put_pid(pid);

	return fd;
}

/**
 * pidfd_open() - Open new pid file descriptor.
 *
 * @pid:   pid for which to retrieve a pidfd
 * @flags: flags to pass
 *
 * This creates a new pid file descriptor with the O_CLOEXEC flag set for
 * the process identified by @pid. The process identified by @pid must be
 * a thread-group leader: polling only supports thread-group leaders.
 *
 * Return: On success, a cloexec pidfd is returned.
 *         On error, a negative errno number will be returned.
 */
SYSCALL_DEFINE2(pidfd_open, pid_t, pid, unsigned int, flags)
{
	struct task_struct *task;
	struct pid *p;
	int fd, ret;

	if (flags)
		return -EINVAL;

	if (pid <= 0)
		return -EINVAL;

	p = find_get_pid(pid);
	if (!p)
		return -ESRCH;

	/* 3.10 has no PIDTYPE_TGID: look at the task the pid is attached to */
	ret = 0;
	rcu_read_lock();
	task = pid_task(p, PIDTYPE_PID);
	if (!task || !thread_group_leader(task))
		ret = -EINVAL;
	rcu_read_unlock();

	fd = ret ? ret : pidfd_create(p);
	put_pid(p);
	return fd;
}

/*
 * Verify that the signaler and signalee either are in the same pid namespace
 * or that the signaler's pid namespace is an ancestor of the signalee's pid
 * namespace.
 */
static bool access_pidfd_pidns(struct pid *pid)
{
	struct pid_namespace *active = task_active_pid_ns(current);
	struct pid_namespace *p = ns_of_pid(pid);

	for (;;) {
		if (!p)
			return false;
		if (p == active)
			break;
		p = p->parent;
	}

	return true;
}

static int copy_siginfo_from_user_any(siginfo_t *kinfo, siginfo_t __user *info)
{
#ifdef CONFIG_COMPAT
	/*
	 * Avoid hooking up compat syscalls and instead handle necessary
	 * conversions here.
	 */
	if (is_compat_task())
		return copy_siginfo_from_user32(kinfo,
				(struct compat_siginfo __user *)info);
#endif
	if (copy_from_user(kinfo, info, sizeof(siginfo_t)))
		return -EFAULT;
	return 0;
}

/**
 * sys_pidfd_send_signal - Signal a process through a pidfd
 * @pidfd:  file descriptor of the process
 * @sig:    signal to send
 * @info:   signal info
 * @flags:  future flags
 *
 * The syscall signals the process the pidfd refers to, like
 * kill(<positive-pid>, <signal>). It does not signal threads or process
 * groups.
 *
 * Return: 0 on success, negative errno on failure
 */
SYSCALL_DEFINE4(pidfd_send_signal, int, pidfd, int, sig,
		siginfo_t __user *, info, unsigned int, flags)
{
	int ret;
	struct fd f;
	struct pid *pid;
	siginfo_t kinfo;

	/* Enforce flags be set to 0 until we add an extension. */
	if (flags)
		return -EINVAL;

	f = fdget(pidfd);
	if (!f.file)
		return -EBADF;

	/* Is this a pidfd? */
	pid = pidfd_pid(f.file);
	if (IS_ERR(pid)) {
		ret = PTR_ERR(pid);
		goto err;
	}

	ret = -EINVAL;
	if (!access_pidfd_pidns(pid))
		goto err;

	if (info) {
		ret = copy_siginfo_from_user_any(&kinfo, info);
		if (unlikely(ret))
			goto err;

		ret = -EINVAL;
		if (unlikely(sig != kinfo.si_signo))
			goto err;

		/* Only allow sending arbitrary signals to yourself. */
		ret = -EPERM;
		if ((task_pid(current) != pid) &&
		    (kinfo.si_code >= 0 || kinfo.si_code == SI_TKILL))
			goto err;
	} else {
		/* what kill(2) would send */
		memset(&kinfo, 0, sizeof(kinfo));
		kinfo.si_signo = sig;
		kinfo.si_errno = 0;
		kinfo.si_code = SI_USER;
		kinfo.si_pid = task_tgid_vnr(current);
		kinfo.si_uid = from_kuid_munged(current_user_ns(),
						current_uid());
	}

	ret = kill_pid_info(sig, &kinfo, pid);

err:
	fdput(f);
	return ret;
}
