// SPDX-License-Identifier: GPL-2.0
// Sentinel sensor: observes openat / execve / connect for ENROLLED workloads only.
//
// Design notes (maps to the Oct-18 discussion doc):
//  * Events are emitted on syscall EXIT so every event carries an outcome
//    (success / failed / pending) instead of just "attempted".     [Arg 4]
//  * Identity = mount-namespace inode, which userspace maps to a container it
//    enrolled itself (not a label the workload can set).            [Arg 5]
//  * Channel A only: typed fields. Raw argv is captured into a separate field
//    that the policy engine never reads; it exists for Channel B.   [Arg 2]

#include "headers/common.h"
#include "headers/bpf_helpers.h"

char __license[] SEC("license") = "GPL";

#define PATH_LEN 256
#define ARG_LEN 64
#define MAX_ARGS 4

enum ev_type { EV_OPEN = 1, EV_EXEC = 2, EV_CONNECT = 3 };

// ---- minimal kernel struct definitions, relocated with CO-RE ----
struct ns_common { unsigned int inum; } __attribute__((preserve_access_index));
struct mnt_namespace { struct ns_common ns; } __attribute__((preserve_access_index));
struct nsproxy { struct mnt_namespace *mnt_ns; } __attribute__((preserve_access_index));
struct task_struct {
	struct nsproxy *nsproxy;
	struct task_struct *real_parent;
	int tgid;
} __attribute__((preserve_access_index));

struct pending {
	__u64 enter_ns;
	__u32 type;
	__u32 flags;
	__u16 family;
	__u16 port;
	__u8 addr[16];
	char path[PATH_LEN];
	char args[MAX_ARGS][ARG_LEN];
};

struct event {
	__u64 enter_ns;
	__u64 exit_ns;
	__s64 ret;
	__u32 type;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u32 mntns;
	__u32 flags;
	__u16 family;
	__u16 port;
	__u8 addr[16];
	char comm[16];
	char path[PATH_LEN];
	char args[MAX_ARGS][ARG_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);   // mount ns inode
	__type(value, __u8);  // 1 = enrolled
} watched SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);   // pid_tgid
	__type(value, struct pending);
} inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pending);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// force BTF emission of struct event for bpf2go
const struct event *unused_event __attribute__((unused));

// tracepoint context layouts (from /sys/kernel/tracing/events/syscalls/*/format)
struct tp_enter { __u64 _common; __s32 nr; __u32 _pad; __u64 a0, a1, a2, a3; };
struct tp_exit  { __u64 _common; __s32 nr; __u32 _pad; __s64 ret; };

static __always_inline __u32 current_mntns(void) {
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct nsproxy *nsp = 0;
	struct mnt_namespace *mnt = 0;
	unsigned int inum = 0;
	bpf_probe_read_kernel(&nsp, sizeof(nsp), &t->nsproxy);
	if (!nsp) return 0;
	bpf_probe_read_kernel(&mnt, sizeof(mnt), &nsp->mnt_ns);
	if (!mnt) return 0;
	bpf_probe_read_kernel(&inum, sizeof(inum), &mnt->ns.inum);
	return inum;
}

static __always_inline int is_watched(void) {
	__u32 ns = current_mntns();
	return bpf_map_lookup_elem(&watched, &ns) != 0;
}

static __always_inline struct pending *fresh(__u32 type) {
	__u32 zero = 0;
	struct pending *p = bpf_map_lookup_elem(&scratch, &zero);
	if (!p) return 0;
	__builtin_memset(p, 0, sizeof(*p));
	p->type = type;
	p->enter_ns = bpf_ktime_get_ns();
	return p;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct tp_enter *ctx) {
	if (!is_watched()) return 0;
	struct pending *p = fresh(EV_OPEN);
	if (!p) return 0;
	bpf_probe_read_user_str(p->path, sizeof(p->path), (const void *)ctx->a1);
	p->flags = (__u32)ctx->a2;
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&inflight, &id, p, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct tp_enter *ctx) {
	if (!is_watched()) return 0;
	struct pending *p = fresh(EV_EXEC);
	if (!p) return 0;
	bpf_probe_read_user_str(p->path, sizeof(p->path), (const void *)ctx->a0);
	const char *const *argv = (const char *const *)ctx->a1;
#pragma unroll
	for (int i = 0; i < MAX_ARGS; i++) {
		const char *arg = 0;
		if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) || !arg) break;
		bpf_probe_read_user_str(p->args[i], ARG_LEN, arg);
	}
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&inflight, &id, p, BPF_ANY);
	return 0;
}

struct sockaddr_any { __u16 family; __u16 port; __u32 flowinfo_or_v4; __u8 v6[16]; };

SEC("tracepoint/syscalls/sys_enter_connect")
int enter_connect(struct tp_enter *ctx) {
	if (!is_watched()) return 0;
	struct sockaddr_any sa = {};
	if (bpf_probe_read_user(&sa, sizeof(sa), (const void *)ctx->a1)) return 0;
	if (sa.family != 2 && sa.family != 10) return 0; // AF_INET / AF_INET6 only
	struct pending *p = fresh(EV_CONNECT);
	if (!p) return 0;
	p->family = sa.family;
	p->port = sa.port; // network byte order
	if (sa.family == 2) {
		__builtin_memcpy(p->addr, &sa.flowinfo_or_v4, 4);
	} else {
		__builtin_memcpy(p->addr, sa.v6, 16);
	}
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&inflight, &id, p, BPF_ANY);
	return 0;
}

static __always_inline int emit(struct tp_exit *ctx, __u32 type) {
	__u64 id = bpf_get_current_pid_tgid();
	struct pending *p = bpf_map_lookup_elem(&inflight, &id);
	if (!p) return 0;
	if (p->type != type) { bpf_map_delete_elem(&inflight, &id); return 0; }
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) { bpf_map_delete_elem(&inflight, &id); return 0; }
	e->enter_ns = p->enter_ns;
	e->exit_ns = bpf_ktime_get_ns();
	e->ret = ctx->ret;
	e->type = type;
	e->pid = (__u32)id;
	e->tgid = id >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->mntns = current_mntns();
	e->flags = p->flags;
	e->family = p->family;
	e->port = p->port;
	__builtin_memcpy(e->addr, p->addr, 16);
	__builtin_memcpy(e->path, p->path, PATH_LEN);
	__builtin_memcpy(e->args, p->args, sizeof(e->args));
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = 0;
	bpf_probe_read_kernel(&parent, sizeof(parent), &t->real_parent);
	if (parent) bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &parent->tgid);
	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&inflight, &id);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int exit_openat(struct tp_exit *ctx) { return emit(ctx, EV_OPEN); }

SEC("tracepoint/syscalls/sys_exit_execve")
int exit_execve(struct tp_exit *ctx) { return emit(ctx, EV_EXEC); }

SEC("tracepoint/syscalls/sys_exit_connect")
int exit_connect(struct tp_exit *ctx) { return emit(ctx, EV_CONNECT); }
