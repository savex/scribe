// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* scribe's eBPF programs (plan option 7B).
 *
 * who:  fentry/tcp_connect and fexit/udp_sendmsg, fexit/udpv6_sendmsg write a struct scribe_flow
 *       to the `events` ring buffer when a process opens a TCP connection or sends a datagram
 *       (once per socket and destination every `udp_repeat_ns`), with the executable's path read
 *       from the kernel (no /proc, no ptrace rights needed).
 * what: the `packets` socket filter, attached to an AF_PACKET SOCK_DGRAM socket, passes outgoing
 *       TCP and UDP packets, incoming TCP packets without data (SYN-ACK, FIN, RST, ACK) and
 *       incoming DNS answers; incoming data, which scribe never reads, and incoming connection
 *       attempts stay in the kernel. Loopback traffic passes whole (both ends are local).
 *
 * Kernel types come with CO-RE relocations (minimal definitions below, matched by name against
 * the running kernel's BTF); UAPI types from the system's kernel headers. */

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "scribe.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* ---- kernel types, relocated by name (only the fields used here) ---- */

struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct msghdr {
	void *msg_name;
} __attribute__((preserve_access_index));

struct qstr {
	union {
		struct {
			__u32 hash;
			__u32 len;
		};
		__u64 hash_len;
	};
	const unsigned char *name;
} __attribute__((preserve_access_index));

struct dentry {
	struct dentry *d_parent;
	struct qstr d_name;
} __attribute__((preserve_access_index));

struct vfsmount {
	struct dentry *mnt_root;
} __attribute__((preserve_access_index));

struct mount {
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
} __attribute__((preserve_access_index));

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
} __attribute__((preserve_access_index));

struct mm_struct {
	struct file *exe_file;
} __attribute__((preserve_access_index));

struct task_struct {
	struct mm_struct *mm;
} __attribute__((preserve_access_index));

/* ---- maps and settings ---- */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} events SEC(".maps");

/* Where a record is built before it is copied to `events`. Kernel 5.8's verifier loses track of a
 * ring-buffer pointer kept on the stack (bpf_ringbuf_reserve), a map value's it keeps. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scribe_flow);
} scratch SEC(".maps");

/* Records lost because the ring buffer was full: index 0, summed over CPUs by scribed. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lost SEC(".maps");

struct udp_key {
	__u64 sk;
	__u8 daddr[16];
	__u16 dport;
	__u16 pad[3];
};

/* When each UDP socket last reported each destination. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct udp_key);
	__type(value, __u64);
} udp_seen SEC(".maps");

/* Set by scribed before loading. */
const volatile __u64 udp_repeat_ns = 30ULL * 1000000000ULL;
const volatile __u32 loopback_ifindex = 1;
/* scribed's pid namespace (stat of /proc/self/ns/pid): pids are reported as scribed sees them.
 * Zero: report the kernel's own (initial namespace) pids. */
const volatile __u64 pidns_dev = 0;
const volatile __u64 pidns_ino = 0;

/* Deepest path walked: directories plus mount points crossed. */
#define PATH_DEPTH 32
#define NAME_MAX_LEN 255

static __always_inline void count_lost(void)
{
	__u32 zero = 0;
	__u64 *n = bpf_map_lookup_elem(&lost, &zero);

	if (n)
		*n += 1;
}

/* The current process and thread ids as scribed sees them; false when the process is outside
 * scribed's pid namespace. */
static __always_inline int current_ids(__u64 *id)
{
	*id = bpf_get_current_pid_tgid();
	if (pidns_ino) {
		struct bpf_pidns_info ns = {};

		if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &ns, sizeof(ns)))
			return 0;
		*id = ((__u64)ns.tgid << 32) | ns.pid;
	}
	return 1;
}

/* The current executable's path, written backwards into e->path, crossing mount points up to
 * the root of the process's mount namespace.
 *
 * The write position lives in e->path_off and is read back through a volatile pointer: the
 * verifier then knows only its type, not a range per iteration, so the states of the walk's
 * branches match and get pruned (tracked in a register, 32 iterations exceed its 1M budget). */
static __always_inline void exe_path(struct scribe_flow *e)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct file *exe = BPF_CORE_READ(task, mm, exe_file);
	volatile __u16 *at = &e->path_off;
	struct dentry *d, *parent, *root;
	struct vfsmount *vmnt;
	struct mount *mnt, *up;
	__u64 mnt_off = bpf_core_field_offset(struct mount, mnt);
	__u32 off, len;
	const unsigned char *name;
	int i;

	*at = SCRIBE_PATH_MAX;
	e->path_truncated = 0;
	if (!exe)
		return; /* kernel threads */
	d = BPF_CORE_READ(exe, f_path.dentry);
	vmnt = BPF_CORE_READ(exe, f_path.mnt);
	mnt = (struct mount *)((void *)vmnt - mnt_off);

	for (i = 0; i < PATH_DEPTH; i++) {
		root = BPF_CORE_READ(vmnt, mnt_root);
		parent = BPF_CORE_READ(d, d_parent);
		if (d == root || d == parent) {
			/* At the root of a mount: continue from where it is mounted. */
			up = BPF_CORE_READ(mnt, mnt_parent);
			if (up == mnt || !up)
				return; /* the namespace's root */
			d = BPF_CORE_READ(mnt, mnt_mountpoint);
			mnt = up;
			vmnt = (struct vfsmount *)((void *)mnt + mnt_off);
			continue;
		}
		len = BPF_CORE_READ(d, d_name.len);
		name = BPF_CORE_READ(d, d_name.name);
		off = *at;
		if (len == 0 || len > NAME_MAX_LEN || len + 1 > off || off > SCRIBE_PATH_MAX) {
			e->path_truncated = 1;
			return;
		}
		off -= len + 1;
		bpf_probe_read_kernel(&e->path[(off + 1) & (SCRIBE_PATH_MAX - 1)], len & NAME_MAX_LEN,
				      name);
		e->path[off & (SCRIBE_PATH_MAX - 1)] = '/';
		*at = off;
		d = parent;
	}
	e->path_truncated = 1; /* deeper than PATH_DEPTH */
}

static __always_inline void fill_process(struct scribe_flow *e, __u64 id, __u8 kind, __u16 family)
{
	e->ts_ns = bpf_ktime_get_ns();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->tgid = id >> 32;
	e->pid = (__u32)id;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->family = family;
	e->kind = kind;
	e->version = SCRIBE_RECORD_VERSION;
	e->pad = 0;
	__builtin_memset(e->saddr, 0, sizeof(e->saddr));
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	exe_path(e);
}

static __always_inline void local_address(struct scribe_flow *e, struct sock *sk, __u16 family)
{
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	if (family == AF_INET) {
		__be32 s = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

		__builtin_memcpy(e->saddr, &s, 4);
	} else {
		BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
	}
}

/* The connected peer of `sk` into dport / daddr (16 bytes, IPv4 in the first 4). */
static __always_inline void peer_address(struct sock *sk, __u16 family, __u16 *dport, __u8 *daddr)
{
	*dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (family == AF_INET) {
		__be32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);

		__builtin_memcpy(daddr, &d, 4);
	} else {
		BPF_CORE_READ_INTO(daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}
}

static __always_inline struct scribe_flow *new_record(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&scratch, &zero);
}

static __always_inline void send_record(struct scribe_flow *e)
{
	if (bpf_ringbuf_output(&events, e, sizeof(*e), 0))
		count_lost();
}

/* ---- who: connections and datagrams ---- */

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk)
{
	struct scribe_flow *e;
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	__u64 id;

	if ((family != AF_INET && family != AF_INET6) || !current_ids(&id))
		return 0;
	e = new_record();
	if (!e)
		return 0;
	fill_process(e, id, SCRIBE_TCP_CONNECT, family);
	local_address(e, sk, family);
	peer_address(sk, family, &e->dport, e->daddr);
	send_record(e);
	return 0;
}

static __always_inline int udp_send(struct sock *sk, struct msghdr *msg, int ret)
{
	struct scribe_flow *e;
	struct udp_key key = {};
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	void *name = BPF_CORE_READ(msg, msg_name);
	__u64 id, now, *last;

	if (ret < 0 || (family != AF_INET && family != AF_INET6) || !current_ids(&id))
		return 0;
	if (!name) {
		peer_address(sk, family, &key.dport, key.daddr); /* connected socket */
	} else if (family == AF_INET) {
		struct sockaddr_in sin = {};

		bpf_probe_read_kernel(&sin, sizeof(sin), name);
		if (sin.sin_family != AF_INET)
			return 0;
		key.dport = bpf_ntohs(sin.sin_port);
		__builtin_memcpy(key.daddr, &sin.sin_addr, 4);
	} else {
		struct sockaddr_in6 sin6 = {};

		bpf_probe_read_kernel(&sin6, sizeof(sin6), name);
		if (sin6.sin6_family != AF_INET6)
			return 0;
		key.dport = bpf_ntohs(sin6.sin6_port);
		__builtin_memcpy(key.daddr, &sin6.sin6_addr, 16);
	}
	if (key.dport == 0)
		return 0;

	key.sk = (__u64)sk;
	now = bpf_ktime_get_ns();
	last = bpf_map_lookup_elem(&udp_seen, &key);
	if (last && now - *last < udp_repeat_ns)
		return 0;
	bpf_map_update_elem(&udp_seen, &key, &now, BPF_ANY);

	e = new_record();
	if (!e)
		return 0;
	fill_process(e, id, SCRIBE_UDP_SEND, family);
	local_address(e, sk, family);
	e->dport = key.dport;
	__builtin_memcpy(e->daddr, key.daddr, 16);
	send_record(e);
	return 0;
}

SEC("fexit/udp_sendmsg")
int BPF_PROG(udp_sendmsg_exit, struct sock *sk, struct msghdr *msg, __u64 len, int ret)
{
	return udp_send(sk, msg, ret);
}

SEC("fexit/udpv6_sendmsg")
int BPF_PROG(udpv6_sendmsg_exit, struct sock *sk, struct msghdr *msg, __u64 len, int ret)
{
	return udp_send(sk, msg, ret);
}

/* ---- what: packets for the flow tracker ---- */

SEC("socket")
int packets(struct __sk_buff *skb)
{
	/* AF_PACKET SOCK_DGRAM: the data starts at the network header. */
	__u32 len = skb->len, off;
	__u8 proto;
	int lo = skb->ifindex == loopback_ifindex;
	int out = skb->pkt_type == PACKET_OUTGOING;

	/* Loopback packets show up twice: keep the received copy. */
	if (lo && out)
		return 0;
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr ip;

		if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)))
			return 0;
		if (ip.frag_off & bpf_htons(0x1fff))
			return 0; /* later fragments carry no transport header */
		proto = ip.protocol;
		off = ip.ihl * 4;
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6;

		if (bpf_skb_load_bytes(skb, 0, &ip6, sizeof(ip6)))
			return 0;
		proto = ip6.nexthdr; /* extension headers: not followed */
		off = sizeof(ip6);
	} else {
		return 0;
	}

	if (proto == IPPROTO_TCP) {
		struct tcphdr th;

		if (bpf_skb_load_bytes(skb, off, &th, sizeof(th)))
			return 0;
		/* Someone else connecting to this machine: not an outgoing flow. */
		if (!out && !lo && th.syn && !th.ack)
			return 0;
		/* Incoming data is the server talking: only its flags matter, and those come with
		 * packets that carry no data, or with SYN, FIN or RST. */
		if (!out && !lo && len > off + th.doff * 4 && !(th.syn || th.fin || th.rst))
			return 0;
		return len;
	}
	if (proto == IPPROTO_UDP) {
		struct udphdr uh;

		if (bpf_skb_load_bytes(skb, off, &uh, sizeof(uh)))
			return 0;
		if (!out && !lo && uh.source != bpf_htons(53))
			return 0; /* incoming datagrams other than DNS answers */
		return len;
	}
	return 0;
}
