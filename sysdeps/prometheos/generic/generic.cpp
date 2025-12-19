#include <prometheos/syscall.h>
#include <asm/ioctls.h>
#include <stddef.h>
#include <bits/ensure.h>
#include <abi-bits/pid_t.h>
#include <abi-bits/fcntl.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/thread-entry.hpp>
#include <errno.h>
#include <sys/resource.h>

namespace mlibc{

int sys_ioctl(int fd, unsigned long request, void *arg, int *result) {
	// mlibc::infoLogger() << "mlibc: sys_ioctl is a stub" << frg::endlog;
	auto ret = syscall(SYSCALL_IOCTL, fd, request, arg);
	if (int e = sc_error(ret); e)
		return e;
	if (result)
		*result = sc_int_result<unsigned long>(ret);
	return 0;
}

int sys_fcntl(int fd, int cmd, va_list args, int *result) {
	// mlibc::infoLogger() << "mlibc: sys_fcntl is a stub" << frg::endlog;
    auto arg = va_arg(args, unsigned long);
    auto ret = syscall(SYSCALL_FCNTL, fd, cmd, arg);
    if (int e = sc_error(ret); e)
            return e;
    *result = sc_int_result<int>(ret);
    return 0;
}

int sys_tcgetattr(int fd, struct termios *attr) {
	auto ret = syscall(SYSCALL_IOCTL, fd, TCGETS, attr);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_tcsetattr(int fd, int optional_action, const struct termios *attr) {
	int req;

	switch (optional_action) {
		case TCSANOW: req = TCSETS; break;
		case TCSADRAIN: req = TCSETSW; break;
		case TCSAFLUSH: req = TCSETSF; break;
		default: return EINVAL;
	}

	auto ret = syscall(SYSCALL_IOCTL, fd, req, attr);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_ttyname(int fd, char *buf, size_t size) {
	// if (!isatty(fd))
	// 	return errno;

	// char *procname;
	// if(int e = asprintf(&procname, "/proc/self/fd/%i", fd); e)
	// 	return ENOMEM;
	// __ensure(procname);

	// ssize_t l = readlink(procname, buf, size);
	// free(procname);

	// if (l < 0)
	// 	return errno;
	// else if ((size_t)l >= size)
	// 	return ERANGE;

	// buf[l] = '\0';
	// struct stat st1;
	// struct stat st2;

	// if (stat(buf, &st1) || fstat(fd, &st2))
	// 	return errno;
	// if (st1.st_dev != st2.st_dev || st1.st_ino != st2.st_ino)
	// 	return ENODEV;
	mlibc::infoLogger() << "mlibc: sys_ttyname is a stub" << frg::endlog;
	buf[0] = 't';
	buf[0] = 'e';
	buf[0] = 'r';
	buf[0] = 'm';
	buf[0] = '\0';
	return 0;
}

int sys_futex_tid(){
	return syscall(SYSCALL_GETTID);
}

int sys_futex_wait(int *pointer, int expected, const struct timespec *time){
	return syscall(SYSCALL_FUTEX_WAIT, pointer, expected);
}

int sys_futex_wake(int *pointer) {
	return syscall(SYSCALL_FUTEX_WAKE, pointer);
}

int sys_tcb_set(void* pointer){
	return syscall(SYSCALL_ARCH_PRCTL, (uintptr_t)pointer);
}

int sys_anon_allocate(size_t size, void **pointer) {
	return sys_vm_map(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0, pointer);
}

int sys_anon_free(void *pointer, size_t size) {
	return sys_vm_unmap(pointer, size);
}

void sys_libc_panic(){
	sys_libc_log("libc panic!");
	__builtin_trap();
	for(;;);
}

void sys_libc_log(const char* msg){
	syscall(0, (uintptr_t)msg);
}

// #ifndef MLIBC_BUILDING_RTLD

void sys_exit(int status){
	syscall(SYSCALL_EXIT, status);
}

int sys_openat(int dirfd, const char *path, int flags, mode_t mode, int *fd) {
	auto ret = syscall(SYSCALL_OPENAT, dirfd, path, flags, mode);
	if (int e = sc_error(ret); e)
		return e;
	*fd = sc_int_result<int>(ret);
	return 0;
}

int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
	return sys_openat(AT_FDCWD, pathname, flags, mode, fd);
}

int sys_open_dir(const char *path, int *fd) {
	return sys_open(path, O_DIRECTORY, 0, fd);
}

int sys_read(int fd, void *buff, size_t count, ssize_t *bytes_read) {
	auto ret = syscall(SYSCALL_READ, fd, buff, count);
	if(int e = sc_error(ret); e)
		return e;
	*bytes_read = sc_int_result<ssize_t>(ret);
	return 0;
}

int sys_read_entries(int handle, void *buffer, size_t max_size, size_t *bytes_read) {
	auto ret = syscall(SYSCALL_GETDENTS, handle, buffer, max_size);
	if(int e = sc_error(ret); e)
		return e;
	*bytes_read = sc_int_result<int>(ret);
	return 0;
}

int sys_write(int fd, const void *buffer, size_t size, ssize_t *bytes_written) {
	auto ret = syscall(SYSCALL_WRITE, fd, buffer, size);
	if(int e = sc_error(ret); e)
		return e;
	if(bytes_written)
		*bytes_written = sc_int_result<ssize_t>(ret);
	return 0;
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
	auto ret = syscall(SYSCALL_LSEEK, fd, offset, whence);
	if(int e = sc_error(ret); e)
		return e;
	*new_offset = sc_int_result<off_t>(ret);
	return 0;
}
	
int sys_close(int fd) {
	auto ret = syscall(SYSCALL_CLOSE, fd);
	if(int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
	if(offset % 4096)
		return EINVAL;
	auto ret = syscall(SYSCALL_MMAP, hint, size, prot, flags, fd, offset);
	if(int e = sc_error(ret); e)
		return e;
	*window = (void *)ret;
	return 0;
}

int sys_vm_unmap(void *pointer, size_t size) {
	auto ret = syscall(SYSCALL_MUNMAP, pointer, size);
	if(int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_vm_protect(void *pointer, size_t size, int prot) {
	auto ret = syscall(SYSCALL_MPROTECT, pointer, size, prot);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
	if (fsfdt == fsfd_target::path)
		fd = AT_FDCWD;
	else if (fsfdt == fsfd_target::fd)
		flags |= AT_EMPTY_PATH;
	else
		__ensure(fsfdt == fsfd_target::fd_path);

	auto ret = syscall(SYSCALL_FSTATAT64, fd, path, statbuf, flags);
		if (int e = sc_error(ret); e) {
		return e;
	}

#if defined(__i386__)
	statbuf->st_atim.tv_sec = statbuf->__st_atim32.tv_sec;
	statbuf->st_atim.tv_nsec = statbuf->__st_atim32.tv_nsec;
	statbuf->st_mtim.tv_sec = statbuf->__st_mtim32.tv_sec;
	statbuf->st_mtim.tv_nsec = statbuf->__st_mtim32.tv_nsec;
	statbuf->st_ctim.tv_sec = statbuf->__st_ctim32.tv_sec;
	statbuf->st_ctim.tv_nsec = statbuf->__st_ctim32.tv_nsec;
#endif

	return 0;
}

int sys_isatty(int fd) {
	unsigned short winsizeHack[4];
	auto ret = syscall(SYSCALL_IOCTL, fd, TIOCGWINSZ, &winsizeHack);
	if (int e = sc_error(ret); e)
		return e;
	auto res = sc_int_result<unsigned long>(ret);
	if(!res) return 0;
	return 1;
}

pid_t sys_getpid(){
	uint32_t _pid;
	syscall(SYSCALL_GETPID, (uintptr_t)&_pid);

	pid_t pid = _pid;
	return pid;
}


pid_t sys_getppid(){
	return syscall(SYSCALL_GETPPID);
}

int sys_getpgid(pid_t pid, pid_t *out) {
	auto ret = syscall(SYSCALL_GETPGID, pid);
	if (int e = sc_error(ret); e)
		return e;
	*out = sc_int_result<pid_t>(ret);
	return 0;
}

int sys_setpgid(pid_t pid, pid_t pgid) {
	auto ret = syscall(SYSCALL_SETPGID, pid, pgid);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_uname(struct utsname *buf) {
	auto ret = syscall(SYSCALL_UNAME, buf);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_gethostname(char *buf, size_t bufsize) {
	struct utsname uname_buf;
	if (auto e = sys_uname(&uname_buf); e)
		return e;

	auto node_len = strlen(uname_buf.nodename);
	if (node_len >= bufsize)
		return ENAMETOOLONG;

	memcpy(buf, uname_buf.nodename, node_len);
	buf[node_len] = '\0';
	return 0;
}

// extern "C" void __mlibc_signal_restore(void);
// extern "C" void __mlibc_signal_restore_rt(void);

int sys_sigaction(int signum, const struct sigaction *act,
		struct sigaction *oldact) {
	// mlibc::infoLogger() << "mlibc: sys_sigaction is a stub" << frg::endlog;
	// struct ksigaction {
	// 	void (*handler)(int);
	// 	unsigned long flags;
	// 	void (*restorer)(void);
	// 	uint32_t mask[2];
	// };

	// struct ksigaction kernel_act, kernel_oldact;
	// if (act) {
	// 	kernel_act.handler = act->sa_handler;
	// 	kernel_act.flags = act->sa_flags | SA_RESTORER;
	// 	kernel_act.restorer = (act->sa_flags & SA_SIGINFO) ? __mlibc_signal_restore_rt : __mlibc_signal_restore;
	// 	memcpy(&kernel_act.mask, &act->sa_mask, sizeof(kernel_act.mask));
	// }

	// static_assert(sizeof(kernel_act.mask) == 8);

	// auto ret = syscall(SYSCALL_RT_SIGACTION, signum, act ?
	// 	&kernel_act : nullptr, oldact ?
	// 	&kernel_oldact : nullptr, sizeof(kernel_act.mask));
	// if (int e = sc_error(ret); e)
	// 	return e;

	// if (oldact) {
	// 	oldact->sa_handler = kernel_oldact.handler;
	// 	oldact->sa_flags = kernel_oldact.flags;
	// 	oldact->sa_restorer = kernel_oldact.restorer;
	// 	memcpy(&oldact->sa_mask, &kernel_oldact.mask, sizeof(kernel_oldact.mask));
	// }
	return 0;
}

int sys_pselect(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask, int *num_events) {
	// mlibc::infoLogger() << "mlibc: sys_pselect is a stub" << frg::endlog;
	// The Linux kernel sometimes modifies the timeout argument.
	struct timespec local_timeout;
	if(timeout)
		local_timeout = *timeout;

	// The Linux kernel really wants 7 arguments, even tho this is not supported
	// To fix that issue, they use a struct as the last argument.
	// See the man page of pselect and the glibc source code
	struct {
		const sigset_t *sigmask;
		size_t ss_len;
	} data;
	data.sigmask = sigmask;
	data.ss_len = NSIG / 8;

	auto ret = syscall(SYSCALL_PSELECT6, nfds, readfds, writefds,
			exceptfds, timeout ? &local_timeout : nullptr, &data);
	if (int e = sc_error(ret); e)
		return e;
	*num_events = sc_int_result<int>(ret);
	return 0;
}

int sys_sigprocmask(int how, const sigset_t *set, sigset_t *old) {
    auto ret = syscall(SYSCALL_RT_SIGPROCMASK, how, set, old, NSIG / 8);
    if (int e = sc_error(ret); e)
            return e;
	return 0;
}

int sys_clock_get(int clock, time_t *secs, long *nanos) {
	syscall(SYSCALL_CLOCK_GETTIME64, nanos);

	*secs = (*nanos) / 1000000000;
	*nanos = (*nanos) - (*secs) * 1000000000;

	return 0;
}

int sys_getcwd(char *buffer, size_t size){
	return syscall(SYSCALL_GETCWD, buffer, size);
}

int sys_chdir(const char *path) {
	auto ret = syscall(SYSCALL_CHDIR, path);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_access(const char *path, int mode) {
	auto ret = syscall(SYSCALL_FACCESSAT, AT_FDCWD, path, mode, 0);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_faccessat(int dirfd, const char *pathname, int mode, int flags) {
	auto ret = syscall(SYSCALL_FACCESSAT, dirfd, pathname, mode, flags);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_sleep(time_t* sec, long* nanosec){
	syscall(SYSCALL_NANOSLEEP, (*sec) * 1000000000 + (*nanosec));
	return 0;
}

uid_t sys_getuid(){
	return syscall(SYSCALL_GETUID);
}

uid_t sys_geteuid(){
	return syscall(SYSCALL_GETEUID);
}

int sys_setuid(uid_t uid){
	return -syscall(SYSCALL_SETUID, uid);
}

int sys_seteuid(uid_t euid){
	return -syscall(SYSCALL_SETREUID, euid);
}

gid_t sys_getgid(){
	return syscall(SYSCALL_GETGID);
}

gid_t sys_getegid(){
	return syscall(SYSCALL_GETEGID);
}

int sys_setgid(gid_t gid){
	mlibc::infoLogger() << "mlibc: sys_setgid is a stub" << frg::endlog;
	return 0;
}

int sys_setegid(gid_t egid){
	mlibc::infoLogger() << "mlibc: sys_setegid is a stub" << frg::endlog;
	return 0;
}

void sys_yield(){
	syscall(SYSCALL_SCHED_YIELD);
}

int sys_kill(int pid, int sig) {
	auto ret = syscall(SYSCALL_KILL, pid, sig);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_clone(void *tcb, pid_t *tid_out, void *stack){
	// pid_t tid = syscall(SYSCALL_RESTART_SYSCALL); //stubbed but still want to see

	// if(tid < 0){
	// 	errno = tid;
	// 	return -1;
	// }

	// *tid_out = tid;

	mlibc::infoLogger() << "mlibc: sys_setegid is a stub" << frg::endlog;
	return 0;
}

void sys_thread_exit(){
	syscall(SYSCALL_EXIT_GROUP);

	__builtin_unreachable();
}

int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
	auto ret = syscall(SYSCALL_WAITPID, pid, status, flags);
	if (int e = sc_error(ret); e)
			return e;
	*ret_pid = sc_int_result<pid_t>(ret);
	return 0;
}

int sys_fork(pid_t *child) {
	auto ret = syscall(SYSCALL_FORK);
	if (int e = sc_error(ret); e)
			return e;
	*child = sc_int_result<int>(ret);
	return 0;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]) {
    auto ret = syscall(SYSCALL_EXECVE, path, argv, envp);
    if (int e = sc_error(ret); e)
            return e;
    return 0;
}

}
