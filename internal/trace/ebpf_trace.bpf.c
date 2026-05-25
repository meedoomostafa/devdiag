//go:build ignore

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef long long __s64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __always_inline inline __attribute__((always_inline))

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0
#define AF_INET 2
#define MAX_ARG_LEN 96

#define EVENT_OPENAT 1
#define EVENT_EXECVE 2
#define EVENT_CONNECT 3
#define EVENT_BIND 4
#define EVENT_FORK 5

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)112;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)113;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)114;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;

char __license[] SEC("license") = "Dual MIT/GPL";

struct trace_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 ppid;
	__u32 event_type;
	__s64 ret;
	__u32 family;
	__u32 port;
	__u32 addr4;
	__u8 arg0[MAX_ARG_LEN];
	__u8 arg1[MAX_ARG_LEN];
};

struct pending_key {
	__u32 pid;
	__u32 event_type;
};

struct pending_value {
	__u32 event_type;
	__u32 family;
	__u32 port;
	__u32 addr4;
	__u8 arg0[MAX_ARG_LEN];
	__u8 arg1[MAX_ARG_LEN];
};

struct sys_enter_ctx {
	__u64 pad;
	__s64 id;
	__u64 args[6];
};

struct sys_exit_ctx {
	__u64 pad;
	__s64 id;
	__s64 ret;
};

struct sched_process_fork_ctx {
	__u64 pad;
	__u8 parent_comm[16];
	__u32 parent_pid;
	__u8 child_comm[16];
	__u32 child_pid;
};

struct sockaddr_in_lite {
	__u16 family;
	__u16 port;
	__u32 addr;
};

struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

struct pt_regs_x86_64 {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_rax;
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
};

#define SYS_X86_64_EXECVE 59
#define SYS_X86_64_CONNECT 42
#define SYS_X86_64_BIND 49
#define SYS_X86_64_OPENAT 257

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} tracked_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct pending_key);
	__type(value, struct pending_value);
} pending_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct trace_event);
} events SEC(".maps");

static __always_inline __u32 current_pid(void) {
	return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline int is_tracked(__u32 pid) {
	__u8 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
	return tracked != 0;
}

static __always_inline __u16 ntohs16(__u16 value) {
	return (value >> 8) | (value << 8);
}

static __always_inline void read_sockaddr(__u64 user_ptr, struct pending_value *value) {
	struct sockaddr_in_lite addr = {};
	if (user_ptr == 0) {
		return;
	}
	if (bpf_probe_read_user(&addr, sizeof(addr), (void *)user_ptr) != 0) {
		return;
	}
	value->family = addr.family;
	if (addr.family == AF_INET) {
		value->port = ntohs16(addr.port);
		value->addr4 = addr.addr;
	}
}

static __always_inline int store_path_pending(__u32 event_type, __u64 user_ptr) {
	__u32 pid = current_pid();
	if (!is_tracked(pid)) {
		return 0;
	}
	struct pending_key key = {
		.pid = pid,
		.event_type = event_type,
	};
	struct pending_value value = {
		.event_type = event_type,
	};
	if (user_ptr != 0) {
		bpf_probe_read_user_str(value.arg0, sizeof(value.arg0), (void *)user_ptr);
	}
	bpf_map_update_elem(&pending_events, &key, &value, BPF_ANY);
	return 0;
}

static __always_inline int store_sockaddr_pending(__u32 event_type, __u64 user_ptr) {
	__u32 pid = current_pid();
	if (!is_tracked(pid)) {
		return 0;
	}
	struct pending_key key = {
		.pid = pid,
		.event_type = event_type,
	};
	struct pending_value value = {
		.event_type = event_type,
	};
	read_sockaddr(user_ptr, &value);
	bpf_map_update_elem(&pending_events, &key, &value, BPF_ANY);
	return 0;
}

static __always_inline int emit_pending(__u32 event_type, __s64 ret) {
	__u32 pid = current_pid();
	struct pending_key key = {
		.pid = pid,
		.event_type = event_type,
	};
	struct pending_value *pending = bpf_map_lookup_elem(&pending_events, &key);
	if (!pending) {
		return 0;
	}
	if (ret >= 0) {
		bpf_map_delete_elem(&pending_events, &key);
		return 0;
	}
	struct trace_event *event = bpf_ringbuf_reserve(&events, sizeof(struct trace_event), 0);
	if (!event) {
		bpf_map_delete_elem(&pending_events, &key);
		return 0;
	}
	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid = pid;
	event->ppid = 0;
	event->event_type = event_type;
	event->ret = ret;
	event->family = pending->family;
	event->port = pending->port;
	event->addr4 = pending->addr4;
	__builtin_memcpy(event->arg0, pending->arg0, sizeof(event->arg0));
	__builtin_memcpy(event->arg1, pending->arg1, sizeof(event->arg1));
	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&pending_events, &key);
	return 0;
}

static __always_inline int read_x86_regs(__u64 regs_ptr, struct pt_regs_x86_64 *regs) {
	if (regs_ptr == 0) {
		return -1;
	}
	return bpf_probe_read_kernel(regs, sizeof(*regs), (void *)regs_ptr);
}

static __always_inline int raw_syscall_enter_x86(__u64 regs_ptr) {
	struct pt_regs_x86_64 regs = {};
	if (read_x86_regs(regs_ptr, &regs) != 0) {
		return 0;
	}
	switch (regs.orig_rax) {
	case SYS_X86_64_OPENAT:
		return store_path_pending(EVENT_OPENAT, regs.rsi);
	case SYS_X86_64_EXECVE:
		return store_path_pending(EVENT_EXECVE, regs.rdi);
	case SYS_X86_64_CONNECT:
		return store_sockaddr_pending(EVENT_CONNECT, regs.rsi);
	case SYS_X86_64_BIND:
		return store_sockaddr_pending(EVENT_BIND, regs.rsi);
	default:
		return 0;
	}
}

static __always_inline int raw_syscall_exit_x86(__u64 regs_ptr, __s64 ret) {
	struct pt_regs_x86_64 regs = {};
	if (read_x86_regs(regs_ptr, &regs) != 0) {
		return 0;
	}
	switch (regs.orig_rax) {
	case SYS_X86_64_OPENAT:
		return emit_pending(EVENT_OPENAT, ret);
	case SYS_X86_64_EXECVE:
		return emit_pending(EVENT_EXECVE, ret);
	case SYS_X86_64_CONNECT:
		return emit_pending(EVENT_CONNECT, ret);
	case SYS_X86_64_BIND:
		return emit_pending(EVENT_BIND, ret);
	default:
		return 0;
	}
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_sys_enter_openat(struct sys_enter_ctx *ctx) {
	return store_path_pending(EVENT_OPENAT, ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint_sys_exit_openat(struct sys_exit_ctx *ctx) {
	return emit_pending(EVENT_OPENAT, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_sys_enter_execve(struct sys_enter_ctx *ctx) {
	return store_path_pending(EVENT_EXECVE, ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint_sys_exit_execve(struct sys_exit_ctx *ctx) {
	return emit_pending(EVENT_EXECVE, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_sys_enter_connect(struct sys_enter_ctx *ctx) {
	return store_sockaddr_pending(EVENT_CONNECT, ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint_sys_exit_connect(struct sys_exit_ctx *ctx) {
	return emit_pending(EVENT_CONNECT, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_bind")
int tracepoint_sys_enter_bind(struct sys_enter_ctx *ctx) {
	return store_sockaddr_pending(EVENT_BIND, ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_bind")
int tracepoint_sys_exit_bind(struct sys_exit_ctx *ctx) {
	return emit_pending(EVENT_BIND, ctx->ret);
}

SEC("tracepoint/sched/sched_process_fork")
int tracepoint_sched_process_fork(struct sched_process_fork_ctx *ctx) {
	if (!is_tracked(ctx->parent_pid)) {
		return 0;
	}
	__u32 child_pid = ctx->child_pid;
	__u8 tracked = 1;
	bpf_map_update_elem(&tracked_pids, &child_pid, &tracked, BPF_ANY);
	struct trace_event *event = bpf_ringbuf_reserve(&events, sizeof(struct trace_event), 0);
	if (!event) {
		return 0;
	}
	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid = child_pid;
	event->ppid = ctx->parent_pid;
	event->event_type = EVENT_FORK;
	event->ret = 0;
	event->family = 0;
	event->port = 0;
	event->addr4 = 0;
	__builtin_memset(event->arg0, 0, sizeof(event->arg0));
	__builtin_memset(event->arg1, 0, sizeof(event->arg1));
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	return raw_syscall_enter_x86(ctx->args[0]);
}

SEC("raw_tracepoint/sys_exit")
int raw_tracepoint_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
	return raw_syscall_exit_x86(ctx->args[0], (__s64)ctx->args[1]);
}
