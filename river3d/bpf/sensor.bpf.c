// SPDX-License-Identifier: GPL-2.0
// River3 sensor: observes openat / execve / connect for ENROLLED workloads only.
//
// Two program families share one event record, one ring buffer and one `watched`
// map, so userspace has a single decoder whichever family is attached:
//
//  * tracepoints (-source ebpf): enter/exit pairs on the three syscalls. Events
//    are emitted on EXIT so every event carries an outcome (success / failed /
//    pending) instead of just "attempted".                           [Arg 4]
//  * BPF-LSM hooks (-source lsm): file_open / bprm_check_security /
//    socket_connect. These run BEFORE the operation and can return -EPERM, which
//    is how -block-decoys denies an open of a listed inode. Their events carry
//    lsm=1 ("inline"); ret is 0 (allowed) or -EPERM (blocked).
//
// Design notes (maps to the Oct-18 discussion doc):
//  * Identity = mount-namespace inode, which userspace maps to a container it
//    enrolled itself (not a label the workload can set).            [Arg 5]
//  * Channel A only: typed fields. Raw argv is captured into a separate field
//    that the policy engine never reads; it exists for Channel B.   [Arg 2]
//  * The blocking decision never depends on the ring buffer: the inode lookup
//    and the return value are computed first; the event is best-effort after.

#include "headers/common.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_tracing.h"

char __license[] SEC("license") = "GPL";

#define PATH_LEN 256
#define ARG_LEN 64
#define MAX_ARGS 4
#define EPERM 1
#define AF_INET 2
#define AF_INET6 10

enum ev_type { EV_OPEN = 1, EV_EXEC = 2, EV_CONNECT = 3 };

// ---- minimal kernel struct definitions, relocated with CO-RE ----
// Only the fields read here are declared; preserve_access_index makes clang emit
// relocations so the real offsets come from the running kernel's BTF at load time.
struct ns_common { unsigned int inum; } __attribute__((preserve_access_index));
struct mnt_namespace { struct ns_common ns; } __attribute__((preserve_access_index));
struct nsproxy { struct mnt_namespace *mnt_ns; } __attribute__((preserve_access_index));
struct task_struct {
	struct nsproxy *nsproxy;
	struct task_struct *real_parent;
	int tgid;
} __attribute__((preserve_access_index));

struct dentry;
struct vfsmount;
struct path { struct vfsmount *mnt; struct dentry *dentry; } __attribute__((preserve_access_index));
// dev_t is 32 bits inside the kernel (12-bit major, 20-bit minor); userspace sees a
// different encoding through stat(2). inodes.go converts before writing the map.
struct super_block { unsigned int s_dev; } __attribute__((preserve_access_index));
struct inode {
	struct super_block *i_sb;
	unsigned long i_ino;
} __attribute__((preserve_access_index));
struct file {
	struct path f_path;
	struct inode *f_inode;
	unsigned int f_flags;
} __attribute__((preserve_access_index));
struct linux_binprm { struct file *file; } __attribute__((preserve_access_index));

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
	// LSM-only facts. dev/ino identify the opened or executed file in the kernel's
	// own encoding so userspace can correlate with the blocked-inode table when
	// bpf_d_path could not produce a string. lsm=1 marks an inline (pre-operation)
	// event; the tracepoint programs leave all three zero.
	__u64 dev;
	__u64 ino;
	__u8 lsm;
	__u8 _pad[7];
};

// Key of `blocked_inodes`. The mount namespace is part of the key so one
// workload's decoy never blocks the same (dev, ino) seen from another workload
// (shared lower layers of an image make that a real possibility).
struct inode_key {
	__u64 dev;
	__u64 ino;
	__u32 mntns;
	__u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);   // mount ns inode
	__type(value, __u8);  // 1 = enrolled
} watched SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct inode_key);
	__type(value, __u8);  // 1 = deny every open
} blocked_inodes SEC(".maps");

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

// force BTF emission of the record types for bpf2go -type
const struct event *unused_event __attribute__((unused));
const struct inode_key *unused_inode_key __attribute__((unused));

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

// fill_task writes the identity fields every event carries, from `current`.
static __always_inline void fill_task(struct event *e) {
	__u64 id = bpf_get_current_pid_tgid();
	e->pid = (__u32)id;
	e->tgid = id >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = 0;
	bpf_probe_read_kernel(&parent, sizeof(parent), &t->real_parent);
	if (parent) bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &parent->tgid);
}

// ============================================================================
// Tracepoint family (-source ebpf)
// ============================================================================

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

// sockaddr_in and the first 24 bytes of sockaddr_in6 share this layout.
struct sockaddr_any { __u16 family; __u16 port; __u32 flowinfo_or_v4; __u8 v6[16]; };

SEC("tracepoint/syscalls/sys_enter_connect")
int enter_connect(struct tp_enter *ctx) {
	if (!is_watched()) return 0;
	struct sockaddr_any sa = {};
	if (bpf_probe_read_user(&sa, sizeof(sa), (const void *)ctx->a1)) return 0;
	if (sa.family != AF_INET && sa.family != AF_INET6) return 0;
	struct pending *p = fresh(EV_CONNECT);
	if (!p) return 0;
	p->family = sa.family;
	p->port = sa.port; // network byte order
	if (sa.family == AF_INET) {
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
	e->mntns = current_mntns();
	e->flags = p->flags;
	e->family = p->family;
	e->port = p->port;
	__builtin_memcpy(e->addr, p->addr, 16);
	__builtin_memcpy(e->path, p->path, PATH_LEN);
	__builtin_memcpy(e->args, p->args, sizeof(e->args));
	e->dev = 0;
	e->ino = 0;
	e->lsm = 0;
	__builtin_memset(e->_pad, 0, sizeof(e->_pad));
	fill_task(e);
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

// ============================================================================
// BPF-LSM family (-source lsm)
// ============================================================================
//
// These hooks run in the context of the calling task, before the operation. The
// LSM program type can walk kernel structures by BTF directly (no probe_read),
// and bpf_d_path is permitted on these three hooks because they are in the
// kernel's sleepable-LSM set. d_path renders the path relative to the CALLER's
// root, i.e. exactly what the process inside the container would call the file,
// with every symlink already followed by the VFS: no userspace lexical walk.

// lsm_reserve allocates and zero-fills an inline event. Zeroing matters: the
// ring buffer hands back whatever was there before, and userspace reads path and
// comm as NUL-terminated strings.
static __always_inline struct event *lsm_reserve(__u32 type, __u32 mntns, __s64 ret) {
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));
	__u64 now = bpf_ktime_get_ns();
	e->enter_ns = now;
	e->exit_ns = now;
	e->ret = ret;
	e->type = type;
	e->mntns = mntns;
	e->lsm = 1;
	fill_task(e);
	return e;
}

// file_identity records (dev, ino) of a file in the kernel's own encoding.
static __always_inline void file_identity(struct file *f, __u64 *dev, __u64 *ino) {
	struct inode *in = f->f_inode;
	if (!in) return;
	*ino = in->i_ino;
	struct super_block *sb = in->i_sb;
	if (sb) *dev = sb->s_dev;
}

// fill_path renders f's path; on failure (ENAMETOOLONG, mostly) the buffer is
// left empty and userspace falls back to (dev, ino).
static __always_inline void fill_path(struct event *e, struct file *f) {
	long n = bpf_d_path(&f->f_path, e->path, sizeof(e->path));
	if (n < 0) e->path[0] = 0;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file) {
	__u32 ns = current_mntns();
	if (!bpf_map_lookup_elem(&watched, &ns)) return 0;

	// Decide first. The decision must not depend on whether an event can be
	// recorded, so the ring buffer is touched only afterwards.
	struct inode_key key = {};
	file_identity(file, &key.dev, &key.ino);
	key.mntns = ns;
	__s64 ret = 0;
	if (key.ino && bpf_map_lookup_elem(&blocked_inodes, &key)) ret = -EPERM;

	struct event *e = lsm_reserve(EV_OPEN, ns, ret);
	if (!e) return ret;
	e->flags = file->f_flags;
	e->dev = key.dev;
	e->ino = key.ino;
	fill_path(e, file);
	bpf_ringbuf_submit(e, 0);
	return ret;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm) {
	__u32 ns = current_mntns();
	if (!bpf_map_lookup_elem(&watched, &ns)) return 0;
	struct file *f = bprm->file;
	if (!f) return 0;
	struct event *e = lsm_reserve(EV_EXEC, ns, 0);
	if (!e) return 0;
	// bprm->file is the binary the kernel actually opened for this exec stage,
	// so the path is the real file (python3.13, not the python3 symlink). argv is
	// not read here: the LSM path carries no Channel B payload.
	file_identity(f, &e->dev, &e->ino);
	fill_path(e, f);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
	__u32 ns = current_mntns();
	if (!bpf_map_lookup_elem(&watched, &ns)) return 0;
	if (addrlen < 8) return 0;
	// `address` is the kernel's copy (sockaddr_storage), so reading past
	// sizeof(struct sockaddr) is safe; the verifier only needs probe_read.
	struct sockaddr_any sa = {};
	if (bpf_probe_read_kernel(&sa, 16, address)) return 0;
	if (sa.family == AF_INET6) {
		if (addrlen < 24 || bpf_probe_read_kernel(&sa, 24, address)) return 0;
	} else if (sa.family != AF_INET) {
		return 0;
	}
	struct event *e = lsm_reserve(EV_CONNECT, ns, 0);
	if (!e) return 0;
	e->family = sa.family;
	e->port = sa.port; // network byte order
	if (sa.family == AF_INET) {
		__builtin_memcpy(e->addr, &sa.flowinfo_or_v4, 4);
	} else {
		__builtin_memcpy(e->addr, sa.v6, 16);
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}
