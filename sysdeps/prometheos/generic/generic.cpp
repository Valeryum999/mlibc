#include <prometheos/syscall.h>
#include <stddef.h>
#include <bits/ensure.h>
#include <abi-bits/pid_t.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/thread-entry.hpp>
#include <errno.h>
#include <sys/resource.h>

namespace mlibc{

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
		long ret;
		long err = syscall(SYSCALL_OPENAT, &ret, dirfd, (uintptr_t)path, flags, mode);
		if(err)
			return err;
		*fd = ret;
		return 0;
	}

	int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
		return sys_openat(AT_FDCWD, pathname, flags, mode, fd);
	};

	int sys_open_dir(const char *path, int *handle) {
		return sys_open(path, O_DIRECTORY, 0, handle);
	}

	int sys_read(int fd, void *buff, size_t count, ssize_t *bytes_read) {
		long readc;
		long error = syscall(SYSCALL_READ, &readc, fd, (uint64_t)buff, count);
		*bytes_read = readc;
		return error;
	}

	int sys_write(int fd, const void *buff, size_t count, ssize_t *bytes_written) {
		long writec;
		long error = syscall(SYSCALL_WRITE, &writec, fd, (uint64_t)buff, count);
		*bytes_written = writec;
		return error;
	}

	int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
		long ret = 0;
		long error = syscall(SYSCALL_LSEEK, &ret, fd, offset, whence);
		*new_offset = ret;
		return error;
	}
	
	int sys_close(int fd) {
		long r;
		return syscall(SYSCALL_CLOSE, &r, fd);
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
		long ret;
		return syscall(SYSCALL_MUNMAP, &ret, (uintptr_t)pointer, size);
	}
	
	int sys_isatty(int fd) {
		long ret;
		return syscall(SYSCALL_RESTART_SYSCALL, &ret, fd); //stubbed but still want to see
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

int sys_clock_get(int clock, time_t *secs, long *nanos) {
	syscall(SYSCALL_CLOCK_GETTIME64, nanos);

	*secs = (*nanos) / 1000000000;
	*nanos = (*nanos) - (*secs) * 1000000000;

	return 0;
}

int sys_getcwd(char *buffer, size_t size){
	return syscall(SYSCALL_GETCWD, buffer, size);
}

int sys_chdir(const char *path){
	syscall(SYSCALL_CHDIR, path);
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

int sys_clone(void *tcb, pid_t *tid_out, void *stack){
	pid_t tid = syscall(SYSCALL_RESTART_SYSCALL); //stubbed but still want to see

	if(tid < 0){
		errno = tid;
		return -1;
	}

	*tid_out = tid;

	return 0;
}

void sys_thread_exit(){
	syscall(SYSCALL_EXIT_GROUP);

	__builtin_unreachable();
}

int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid){
	if(ru) {
		mlibc::infoLogger() << "mlibc: struct rusage in sys_waitpid is unsupported" << frg::endlog;
		return ENOSYS;
	}

	pid_t ret = syscall(SYSCALL_WAITPID, pid, status, flags);

	if(ret < 0){
		return -ret;
	}

	*ret_pid = ret;

	return 0;
}

int sys_fork(pid_t *child){
	long pid = syscall(SYSCALL_FORK, 0);
	if(pid < 0){
		errno = pid;
		return -1;
	}

	*child = pid;
	return 0;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]){
	return -syscall(SYSCALL_EXECVE, path, argv, envp);
}

// #endif

}
