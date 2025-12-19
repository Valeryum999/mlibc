#ifndef _PROMETHEOS_SYSCALL
#define _PROMETHEOS_SYSCALL

extern "C" {

using sc_word_t = long;

static sc_word_t __do_syscall0(long sc) {
	sc_word_t ret;
	asm volatile("int $0x80" : "=a"(ret) : "a"(sc) : "memory");
	return ret;
}

static sc_word_t __do_syscall1(long sc, sc_word_t arg1) {
	sc_word_t ret;
	asm volatile("xchg %%ebx, %%edi;"
		"int $0x80;"
		"xchg %%edi, %%ebx;"
		: "=a"(ret)
		: "a"(sc), "D"(arg1)
		: "memory");
	return ret;
}

static sc_word_t __do_syscall2(long sc, sc_word_t arg1, sc_word_t arg2) {
	sc_word_t ret;
	asm volatile("xchg %%ebx, %%edi;"
		"int $0x80;"
		"xchg %%edi, %%ebx;"
		: "=a"(ret)
		: "a"(sc), "D"(arg1), "c"(arg2)
		: "memory");
	return ret;
}

static sc_word_t __do_syscall3(long sc, sc_word_t arg1, sc_word_t arg2, sc_word_t arg3) {
	sc_word_t ret;
	asm volatile("xchg %%ebx, %%edi;"
		"int $0x80;"
		"xchg %%edi, %%ebx;"
		: "=a"(ret)
		: "a"(sc), "D"(arg1), "c"(arg2), "d"(arg3)
		: "memory");
	return ret;
}

static sc_word_t __do_syscall4(long sc, sc_word_t arg1, sc_word_t arg2, sc_word_t arg3, sc_word_t arg4) {
	sc_word_t ret;
	asm volatile("xchg %%ebx, %%edi;"
		"int $0x80;"
		"xchg %%edi, %%ebx;"
		: "=a"(ret)
		: "a"(sc), "D"(arg1), "c"(arg2), "d"(arg3), "S"(arg4)
		: "memory");
	return ret;
}

static sc_word_t __do_syscall5(long sc, sc_word_t arg1, sc_word_t arg2, sc_word_t arg3, sc_word_t arg4,
		sc_word_t arg5) {
	sc_word_t ret;
	asm volatile("pushl %2;"
		"push %%ebx;"
		"mov 4(%%esp), %%ebx;"
		"int $0x80;"
		"pop %%ebx;"
		"add $4, %%esp;"
		: "=a"(ret)
		: "a"(sc), "g"(arg1), "c"(arg2), "d"(arg3), "S"(arg4), "D"(arg5)
		: "memory");
	return ret;
}

static sc_word_t __do_syscall6(long sc, sc_word_t arg1, sc_word_t arg2, sc_word_t arg3, sc_word_t arg4,
		sc_word_t arg5, sc_word_t arg6) {
	sc_word_t ret;
	sc_word_t a1a6[2] = { arg1, arg6 };
	asm volatile ("pushl %1;"
		"push %%ebx;"
		"push %%ebp;"
		"mov 8(%%esp),%%ebx;"
		"mov 4(%%ebx),%%ebp;"
		"mov (%%ebx),%%ebx;"
		"int $0x80;"
		"pop %%ebp;"
		"pop %%ebx;"
		"add $4,%%esp;"
		: "=a"(ret) : "g"(&a1a6), "a"(sc), "c"(arg2), "d"(arg3), "S"(arg4), "D"(arg5) : "memory");
	return ret;
}
} /* extern "C" */

/* Cast to the argument type of the extern "C" functions. */
__attribute__((__always_inline__)) static inline sc_word_t sc_cast(long x) { return x; }
__attribute__((__always_inline__)) static inline sc_word_t sc_cast(const void *x) {
    return reinterpret_cast<sc_word_t>(x);
}

/* C++ wrappers for the extern "C" functions. */
__attribute__((__always_inline__)) static inline long _syscall(int call) {
    return __do_syscall0(call);
}

__attribute__((__always_inline__)) static inline long _syscall(int call,
                                                           sc_word_t arg0) {
    return __do_syscall1(call, arg0);
}

__attribute__((__always_inline__)) static inline long
_syscall(int call, sc_word_t arg0, sc_word_t arg1) {
    return __do_syscall2(call, arg0, arg1);
}

__attribute__((__always_inline__)) static inline long
_syscall(int call, sc_word_t arg0, sc_word_t arg1, sc_word_t arg2) {
    return __do_syscall3(call, arg0, arg1, arg2);
}

__attribute__((__always_inline__)) static inline long
_syscall(int call, sc_word_t arg0, sc_word_t arg1, sc_word_t arg2,
         sc_word_t arg3) {
    return __do_syscall4(call, arg0, arg1, arg2, arg3);
}

__attribute__((__always_inline__)) static inline long
_syscall(int call, sc_word_t arg0, sc_word_t arg1, sc_word_t arg2,
         sc_word_t arg3, sc_word_t arg4) {
    return __do_syscall5(call, arg0, arg1, arg2, arg3, arg4);
}

__attribute__((__always_inline__)) static inline long
_syscall(int call, sc_word_t arg0, sc_word_t arg1, sc_word_t arg2,
         sc_word_t arg3, sc_word_t arg4, sc_word_t arg5) {
    return __do_syscall6(call, arg0, arg1, arg2, arg3, arg4, arg5);
}

template <typename... T>
__attribute__((__always_inline__)) static inline long syscall(sc_word_t call,
                                                          T... args) {
    return _syscall(call, sc_cast(args)...);
}

inline int sc_error(long ret) {
    if (ret < 0)
        return -ret;
    return 0;
}

// Cast from the syscall result type.
template<typename T>
T sc_int_result(long ret) {
	auto v = static_cast<sc_word_t>(ret);
	return v;
}

template<typename T>
T *sc_ptr_result(long ret) {
	auto v = static_cast<sc_word_t>(ret);
	return reinterpret_cast<T *>(v);
}


#define SYSCALL_RESTART_SYSCALL 0
#define SYSCALL_EXIT 1
#define SYSCALL_FORK 2
#define SYSCALL_READ 3
#define SYSCALL_WRITE 4
#define SYSCALL_OPEN 5
#define SYSCALL_CLOSE 6
#define SYSCALL_WAITPID 7
#define SYSCALL_CREAT 8
#define SYSCALL_LINK 9
#define SYSCALL_UNLINK 10
#define SYSCALL_EXECVE 11
#define SYSCALL_CHDIR 12
#define SYSCALL_TIME 13
#define SYSCALL_MKNOD 14
#define SYSCALL_CHMOD 15
#define SYSCALL_LCHOWN 16
#define SYSCALL_OLDSTAT 18
#define SYSCALL_LSEEK 19
#define SYSCALL_GETPID 20
#define SYSCALL_MOUNT 21
#define SYSCALL_UMOUNT 22
#define SYSCALL_SETUID 23
#define SYSCALL_GETUID 24
#define SYSCALL_STIME 25
#define SYSCALL_PTRACE 26
#define SYSCALL_ALARM 27
#define SYSCALL_OLDFSTAT 28
#define SYSCALL_PAUSE 29
#define SYSCALL_UTIME 30
#define SYSCALL_ACCESS 33
#define SYSCALL_NICE 34
#define SYSCALL_SYNC 36
#define SYSCALL_KILL 37
#define SYSCALL_RENAME 38
#define SYSCALL_MKDIR 39
#define SYSCALL_RMDIR 40
#define SYSCALL_DUP 41
#define SYSCALL_PIPE 42
#define SYSCALL_TIMES 43
#define SYSCALL_BRK 45
#define SYSCALL_SETGID 46
#define SYSCALL_GETGID 47
#define SYSCALL_SIGNAL 48
#define SYSCALL_GETEUID 49
#define SYSCALL_GETEGID 50
#define SYSCALL_ACCT 51
#define SYSCALL_UMOUNT2 52
#define SYSCALL_IOCTL 54
#define SYSCALL_FCNTL 55
#define SYSCALL_SETPGID 57
#define SYSCALL_OLDOLDUNAME 59
#define SYSCALL_UMASK 60
#define SYSCALL_CHROOT 61
#define SYSCALL_USTAT 62
#define SYSCALL_DUP2 63
#define SYSCALL_GETPPID 64
#define SYSCALL_GETPGRP 65
#define SYSCALL_SETSID 66
#define SYSCALL_SIGACTION 67
#define SYSCALL_SGETMASK 68
#define SYSCALL_SSETMASK 69
#define SYSCALL_SETREUID 70
#define SYSCALL_SETREGID 71
#define SYSCALL_SIGSUSPEND 72
#define SYSCALL_SIGPENDING 73
#define SYSCALL_SETHOSTNAME 74
#define SYSCALL_SETRLIMIT 75
#define SYSCALL_GETRLIMIT 76
#define SYSCALL_GETRUSAGE 77
#define SYSCALL_GETTIMEOFDAY 78
#define SYSCALL_SETTIMEOFDAY 79
#define SYSCALL_GETGROUPS 80
#define SYSCALL_SETGROUPS 81
#define SYSCALL_SELECT 82
#define SYSCALL_SYMLINK 83
#define SYSCALL_OLDLSTAT 84
#define SYSCALL_READLINK 85
#define SYSCALL_USELIB 86
#define SYSCALL_SWAPON 87
#define SYSCALL_REBOOT 88
#define SYSCALL_READDIR 89
#define SYSCALL_MMAP 90
#define SYSCALL_MUNMAP 91
#define SYSCALL_TRUNCATE 92
#define SYSCALL_FTRUNCATE 93
#define SYSCALL_FCHMOD 94
#define SYSCALL_FCHOWN 95
#define SYSCALL_GETPRIORITY 96
#define SYSCALL_SETPRIORITY 97
#define SYSCALL_STATFS 99
#define SYSCALL_FSTATFS 100
#define SYSCALL_IOPERM 101
#define SYSCALL_SOCKETCALL 102
#define SYSCALL_SYSLOG 103
#define SYSCALL_SETITIMER 104
#define SYSCALL_GETITIMER 105
#define SYSCALL_STAT 106
#define SYSCALL_LSTAT 107
#define SYSCALL_FSTAT 108
#define SYSCALL_OLDUNAME 109
#define SYSCALL_IOPL 110
#define SYSCALL_VHANGUP 111
#define SYSCALL_IDLE 112
#define SYSCALL_VM86OLD 113
#define SYSCALL_WAIT4 114
#define SYSCALL_SWAPOFF 115
#define SYSCALL_SYSINFO 116
#define SYSCALL_IPC 117
#define SYSCALL_FSYNC 118
#define SYSCALL_SIGRETURN 119
#define SYSCALL_CLONE 120
#define SYSCALL_SETDOMAINNAME 121
#define SYSCALL_UNAME 122
#define SYSCALL_MODIFY_LDT 123
#define SYSCALL_ADJTIMEX 124
#define SYSCALL_MPROTECT 125
#define SYSCALL_SIGPROCMASK 126
#define SYSCALL_CREATE_MODULE 127
#define SYSCALL_INIT_MODULE 128
#define SYSCALL_DELETE_MODULE 129
#define SYSCALL_GET_KERNEL_SYMS 130
#define SYSCALL_QUOTACTL 131
#define SYSCALL_GETPGID 132
#define SYSCALL_FCHDIR 133
#define SYSCALL_BDFLUSH 134
#define SYSCALL_SYSFS 135
#define SYSCALL_PERSONALITY 136
#define SYSCALL_SETFSUID 138
#define SYSCALL_SETFSGID 139
#define SYSCALL__LLSEEK 140
#define SYSCALL_GETDENTS 141
#define SYSCALL__NEWSELECT 142
#define SYSCALL_FLOCK 143
#define SYSCALL_MSYNC 144
#define SYSCALL_READV 145
#define SYSCALL_WRITEV 146
#define SYSCALL_GETSID 147
#define SYSCALL_FDATASYNC 148
#define SYSCALL__SYSCTL 149
#define SYSCALL_MLOCK 150
#define SYSCALL_MUNLOCK 151
#define SYSCALL_MLOCKALL 152
#define SYSCALL_MUNLOCKALL 153
#define SYSCALL_SCHED_SETPARAM 154
#define SYSCALL_SCHED_GETPARAM 155
#define SYSCALL_SCHED_SETSCHEDULER 156
#define SYSCALL_SCHED_GETSCHEDULER 157
#define SYSCALL_SCHED_YIELD 158
#define SYSCALL_SCHED_GET_PRIORITY_MAX 159
#define SYSCALL_SCHED_GET_PRIORITY_MIN 160
#define SYSCALL_SCHED_RR_GET_INTERVAL 161
#define SYSCALL_NANOSLEEP 162
#define SYSCALL_MREMAP 163
#define SYSCALL_SETRESUID 164
#define SYSCALL_GETRESUID 165
#define SYSCALL_VM86 166
#define SYSCALL_QUERY_MODULE 167
#define SYSCALL_POLL 168
#define SYSCALL_NFSSERVCTL 169
#define SYSCALL_SETRESGID 170
#define SYSCALL_GETRESGID 171
#define SYSCALL_PRCTL 172
#define SYSCALL_RT_SIGRETURN 173
#define SYSCALL_RT_SIGACTION 174
#define SYSCALL_RT_SIGPROCMASK 175
#define SYSCALL_RT_SIGPENDING 176
#define SYSCALL_RT_SIGTIMEDWAIT 177
#define SYSCALL_RT_SIGQUEUEINFO 178
#define SYSCALL_RT_SIGSUSPEND 179
#define SYSCALL_PREAD64 180
#define SYSCALL_PWRITE64 181
#define SYSCALL_CHOWN 182
#define SYSCALL_GETCWD 183
#define SYSCALL_CAPGET 184
#define SYSCALL_CAPSET 185
#define SYSCALL_SIGALTSTACK 186
#define SYSCALL_SENDFILE 187
#define SYSCALL_GETPMSG 188
#define SYSCALL_VFORK 190
#define SYSCALL_UGETRLIMIT 191
#define SYSCALL_MMAP2 192
#define SYSCALL_TRUNCATE64 193
#define SYSCALL_FTRUNCATE64 194
#define SYSCALL_STAT64 195
#define SYSCALL_LSTAT64 196
#define SYSCALL_FSTAT64 197
#define SYSCALL_LCHOWN32 198
#define SYSCALL_GETUID32 199
#define SYSCALL_GETGID32 200
#define SYSCALL_GETEUID32 201
#define SYSCALL_GETEGID32 202
#define SYSCALL_SETREUID32 203
#define SYSCALL_SETREGID32 204
#define SYSCALL_GETGROUPS32 205
#define SYSCALL_SETGROUPS32 206
#define SYSCALL_FCHOWN32 207
#define SYSCALL_SETRESUID32 208
#define SYSCALL_GETRESUID32 209
#define SYSCALL_SETRESGID32 210
#define SYSCALL_GETRESGID32 211
#define SYSCALL_CHOWN32 212
#define SYSCALL_SETUID32 213
#define SYSCALL_SETGID32 214
#define SYSCALL_SETFSUID32 215
#define SYSCALL_SETFSGID32 216
#define SYSCALL_PIVOT_ROOT 217
#define SYSCALL_MINCORE 218
#define SYSCALL_MADVISE 219
#define SYSCALL_GETDENTS64 220
#define SYSCALL_FCNTL64 221
#define SYSCALL_GETTID 224
#define SYSCALL_READAHEAD 225
#define SYSCALL_SETXATTR 226
#define SYSCALL_LSETXATTR 227
#define SYSCALL_FSETXATTR 228
#define SYSCALL_GETXATTR 229
#define SYSCALL_LGETXATTR 230
#define SYSCALL_FGETXATTR 231
#define SYSCALL_LISTXATTR 232
#define SYSCALL_LLISTXATTR 233
#define SYSCALL_FLISTXATTR 234
#define SYSCALL_REMOVEXATTR 235
#define SYSCALL_LREMOVEXATTR 236
#define SYSCALL_FREMOVEXATTR 237
#define SYSCALL_TKILL 238
#define SYSCALL_SENDFILE64 239
#define SYSCALL_FUTEX 240
#define SYSCALL_SCHED_SETAFFINITY 241
#define SYSCALL_SCHED_GETAFFINITY 242
#define SYSCALL_SET_THREAD_AREA 243
#define SYSCALL_GET_THREAD_AREA 244
#define SYSCALL_IO_SETUP 245
#define SYSCALL_IO_DESTROY 246
#define SYSCALL_IO_GETEVENTS 247
#define SYSCALL_IO_SUBMIT 248
#define SYSCALL_IO_CANCEL 249
#define SYSCALL_FADVISE64 250
#define SYSCALL_EXIT_GROUP 252
#define SYSCALL_LOOKUP_DCOOKIE 253
#define SYSCALL_EPOLL_CREATE 254
#define SYSCALL_EPOLL_CTL 255
#define SYSCALL_EPOLL_WAIT 256
#define SYSCALL_REMAP_FILE_PAGES 257
#define SYSCALL_SET_TID_ADDRESS 258
#define SYSCALL_TIMER_CREATE 259
#define SYSCALL_TIMER_SETTIME 260
#define SYSCALL_TIMER_GETTIME 261
#define SYSCALL_TIMER_GETOVERRUN 262
#define SYSCALL_TIMER_DELETE 263
#define SYSCALL_CLOCK_SETTIME 264
#define SYSCALL_CLOCK_GETTIME 265
#define SYSCALL_CLOCK_GETRES 266
#define SYSCALL_CLOCK_NANOSLEEP 267
#define SYSCALL_STATFS64 268
#define SYSCALL_FSTATFS64 269
#define SYSCALL_TGKILL 270
#define SYSCALL_UTIMES 271
#define SYSCALL_FADVISE64_64 272
#define SYSCALL_MBIND 274
#define SYSCALL_GET_MEMPOLICY 275
#define SYSCALL_SET_MEMPOLICY 276
#define SYSCALL_MQ_OPEN 277
#define SYSCALL_MQ_UNLINK 278
#define SYSCALL_MQ_TIMEDSEND 279
#define SYSCALL_MQ_TIMEDRECEIVE 280
#define SYSCALL_MQ_NOTIFY 281
#define SYSCALL_MQ_GETSETATTR 282
#define SYSCALL_KEXEC_LOAD 283
#define SYSCALL_WAITID 284
#define SYSCALL_ADD_KEY 286
#define SYSCALL_REQUEST_KEY 287
#define SYSCALL_KEYCTL 288
#define SYSCALL_IOPRIO_SET 289
#define SYSCALL_IOPRIO_GET 290
#define SYSCALL_INOTIFY_INIT 291
#define SYSCALL_INOTIFY_ADD_WATCH 292
#define SYSCALL_INOTIFY_RM_WATCH 293
#define SYSCALL_MIGRATE_PAGES 294
#define SYSCALL_OPENAT 295
#define SYSCALL_MKDIRAT 296
#define SYSCALL_MKNODAT 297
#define SYSCALL_FCHOWNAT 298
#define SYSCALL_FUTIMESAT 299
#define SYSCALL_FSTATAT64 300
#define SYSCALL_UNLINKAT 301
#define SYSCALL_RENAMEAT 302
#define SYSCALL_LINKAT 303
#define SYSCALL_SYMLINKAT 304
#define SYSCALL_READLINKAT 305
#define SYSCALL_FCHMODAT 306
#define SYSCALL_FACCESSAT 307
#define SYSCALL_PSELECT6 308
#define SYSCALL_PPOLL 309
#define SYSCALL_UNSHARE 310
#define SYSCALL_SET_ROBUST_LIST 311
#define SYSCALL_GET_ROBUST_LIST 312
#define SYSCALL_SPLICE 313
#define SYSCALL_SYNC_FILE_RANGE 314
#define SYSCALL_TEE 315
#define SYSCALL_VMSPLICE 316
#define SYSCALL_MOVE_PAGES 317
#define SYSCALL_GETCPU 318
#define SYSCALL_EPOLL_PWAIT 319
#define SYSCALL_UTIMENSAT 320
#define SYSCALL_SIGNALFD 321
#define SYSCALL_TIMERFD_CREATE 322
#define SYSCALL_EVENTFD 323
#define SYSCALL_FALLOCATE 324
#define SYSCALL_TIMERFD_SETTIME 325
#define SYSCALL_TIMERFD_GETTIME 326
#define SYSCALL_SIGNALFD4 327
#define SYSCALL_EVENTFD2 328
#define SYSCALL_EPOLL_CREATE1 329
#define SYSCALL_DUP3 330
#define SYSCALL_PIPE2 331
#define SYSCALL_INOTIFY_INIT1 332
#define SYSCALL_PREADV 333
#define SYSCALL_PWRITEV 334
#define SYSCALL_RT_TGSIGQUEUEINFO 335
#define SYSCALL_PERF_EVENT_OPEN 336
#define SYSCALL_RECVMMSG 337
#define SYSCALL_FANOTIFY_INIT 338
#define SYSCALL_FANOTIFY_MARK 339
#define SYSCALL_PRLIMIT64 340
#define SYSCALL_NAME_TO_HANDLE_AT 341
#define SYSCALL_OPEN_BY_HANDLE_AT 342
#define SYSCALL_CLOCK_ADJTIME 343
#define SYSCALL_SYNCFS 344
#define SYSCALL_SENDMMSG 345
#define SYSCALL_SETNS 346
#define SYSCALL_PROCESS_VM_READV 347
#define SYSCALL_PROCESS_VM_WRITEV 348
#define SYSCALL_KCMP 349
#define SYSCALL_FINIT_MODULE 350
#define SYSCALL_SCHED_SETATTR 351
#define SYSCALL_SCHED_GETATTR 352
#define SYSCALL_RENAMEAT2 353
#define SYSCALL_SECCOMP 354
#define SYSCALL_GETRANDOM 355
#define SYSCALL_MEMFD_CREATE 356
#define SYSCALL_BPF 357
#define SYSCALL_EXECVEAT 358
#define SYSCALL_SOCKET 359
#define SYSCALL_SOCKETPAIR 360
#define SYSCALL_BIND 361
#define SYSCALL_CONNECT 362
#define SYSCALL_LISTEN 363
#define SYSCALL_ACCEPT4 364
#define SYSCALL_GETSOCKOPT 365
#define SYSCALL_SETSOCKOPT 366
#define SYSCALL_GETSOCKNAME 367
#define SYSCALL_GETPEERNAME 368
#define SYSCALL_SENDTO 369
#define SYSCALL_SENDMSG 370
#define SYSCALL_RECVFROM 371
#define SYSCALL_RECVMSG 372
#define SYSCALL_SHUTDOWN 373
#define SYSCALL_USERFAULTFD 374
#define SYSCALL_MEMBARRIER 375
#define SYSCALL_MLOCK2 376
#define SYSCALL_COPY_FILE_RANGE 377
#define SYSCALL_PREADV2 378
#define SYSCALL_PWRITEV2 379
#define SYSCALL_PKEY_MPROTECT 380
#define SYSCALL_PKEY_ALLOC 381
#define SYSCALL_PKEY_FREE 382
#define SYSCALL_STATX 383
#define SYSCALL_ARCH_PRCTL 384
#define SYSCALL_IO_PGETEVENTS 385
#define SYSCALL_RSEQ 386
#define SYSCALL_SEMGET 393
#define SYSCALL_SEMCTL 394
#define SYSCALL_SHMGET 395
#define SYSCALL_SHMCTL 396
#define SYSCALL_SHMAT 397
#define SYSCALL_SHMDT 398
#define SYSCALL_MSGGET 399
#define SYSCALL_MSGSND 400
#define SYSCALL_MSGRCV 401
#define SYSCALL_MSGCTL 402
#define SYSCALL_CLOCK_GETTIME64 403
#define SYSCALL_CLOCK_SETTIME64 404
#define SYSCALL_CLOCK_ADJTIME64 405
#define SYSCALL_CLOCK_GETRES_TIME64 406
#define SYSCALL_CLOCK_NANOSLEEP_TIME64 407
#define SYSCALL_TIMER_GETTIME64 408
#define SYSCALL_TIMER_SETTIME64 409
#define SYSCALL_TIMERFD_GETTIME64 410
#define SYSCALL_TIMERFD_SETTIME64 411
#define SYSCALL_UTIMENSAT_TIME64 412
#define SYSCALL_PSELECT6_TIME64 413
#define SYSCALL_PPOLL_TIME64 414
#define SYSCALL_IO_PGETEVENTS_TIME64 416
#define SYSCALL_RECVMMSG_TIME64 417
#define SYSCALL_MQ_TIMEDSEND_TIME64 418
#define SYSCALL_MQ_TIMEDRECEIVE_TIME64 419
#define SYSCALL_SEMTIMEDOP_TIME64 420
#define SYSCALL_RT_SIGTIMEDWAIT_TIME64 421
#define SYSCALL_FUTEX_TIME64 422
#define SYSCALL_SCHED_RR_GET_INTERVAL_TIME64 423
#define SYSCALL_PIDFD_SEND_SIGNAL 424
#define SYSCALL_IO_URING_SETUP 425
#define SYSCALL_IO_URING_ENTER 426
#define SYSCALL_IO_URING_REGISTER 427
#define SYSCALL_OPEN_TREE 428
#define SYSCALL_MOVE_MOUNT 429
#define SYSCALL_FSOPEN 430
#define SYSCALL_FSCONFIG 431
#define SYSCALL_FSMOUNT 432
#define SYSCALL_FSPICK 433
#define SYSCALL_PIDFD_OPEN 434
#define SYSCALL_CLONE3 435
#define SYSCALL_CLOSE_RANGE 436
#define SYSCALL_OPENAT2 437
#define SYSCALL_PIDFD_GETFD 438
#define SYSCALL_FACCESSAT2 439
#define SYSCALL_PROCESS_MADVISE 440
#define SYSCALL_EPOLL_PWAIT2 441
#define SYSCALL_MOUNT_SETATTR 442
#define SYSCALL_QUOTACTL_FD 443
#define SYSCALL_LANDLOCK_CREATE_RULESET 444
#define SYSCALL_LANDLOCK_ADD_RULE 445
#define SYSCALL_LANDLOCK_RESTRICT_SELF 446
#define SYSCALL_MEMFD_SECRET 447
#define SYSCALL_PROCESS_MRELEASE 448
#define SYSCALL_FUTEX_WAITV 449
#define SYSCALL_SET_MEMPOLICY_HOME_NODE 450
#define SYSCALL_CACHESTAT 451
#define SYSCALL_FCHMODAT2 452
#define SYSCALL_MAP_SHADOW_STACK 453
#define SYSCALL_FUTEX_WAKE 454
#define SYSCALL_FUTEX_WAIT 455
#define SYSCALL_FUTEX_REQUEUE 456
#define SYSCALL_STATMOUNT 457
#define SYSCALL_LISTMOUNT 458
#define SYSCALL_LSM_GET_SELF_ATTR 459
#define SYSCALL_LSM_SET_SELF_ATTR 460
#define SYSCALL_LSM_LIST_MODULES 461
#define SYSCALL_MSEAL 462
#define SYSCALL_SETXATTRAT 463
#define SYSCALL_GETXATTRAT 464
#define SYSCALL_LISTXATTRAT 465
#define SYSCALL_REMOVEXATTRAT 466

#endif