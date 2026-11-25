// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* scribe's eBPF programs (plan option 7B).
 *
 * who:  fentry/tcp_connect and fexit/udp_sendmsg, fexit/udpv6_sendmsg write a struct scribe_flow
 *       to the `events` ring buffer when a process opens a TCP connection or sends a datagram
 *       (once per socket and destination every `udp_repeat_ns`).
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

/* ---- maps and settings ---- */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

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

static __always_inline void count_lost(void)
{
	__u32 zero = 0;
	__u64 *n = bpf_map_lookup_elem(&lost, &zero);

	if (n)
		*n += 1;
}

/* Fills in the process; false when it is outside scribed's pid namespace. */
static __always_inline int fill_process(struct scribe_flow *e, __u8 kind, __u16 family)
{
	__u64 id = bpf_get_current_pid_tgid();

	if (pidns_ino) {
		struct bpf_pidns_info ns = {};

		if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &ns, sizeof(ns)))
			return 0;
		id = ((__u64)ns.tgid << 32) | ns.pid;
	}
	e->ts_ns = bpf_ktime_get_ns();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->tgid = id >> 32;
	e->pid = (__u32)id;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->family = family;
	e->kind = kind;
	e->version = SCRIBE_RECORD_VERSION;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return 1;
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

static __always_inline void remote_address(struct scribe_flow *e, struct sock *sk, __u16 family)
{
	e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (family == AF_INET) {
		__be32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);

		__builtin_memcpy(e->daddr, &d, 4);
	} else {
		BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}
}

/* ---- who: connections and datagrams ---- */

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk)
{
	struct scribe_flow e = {};
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

	if (family != AF_INET && family != AF_INET6)
		return 0;
	if (!fill_process(&e, SCRIBE_TCP_CONNECT, family))
		return 0;
	local_address(&e, sk, family);
	remote_address(&e, sk, family);
	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0))
		count_lost();
	return 0;
}

static __always_inline int udp_send(struct sock *sk, struct msghdr *msg, int ret)
{
	struct scribe_flow e = {};
	struct udp_key key = {};
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	void *name = BPF_CORE_READ(msg, msg_name);
	__u64 now, *last;

	if (ret < 0 || (family != AF_INET && family != AF_INET6))
		return 0;
	if (!fill_process(&e, SCRIBE_UDP_SEND, family))
		return 0;
	local_address(&e, sk, family);
	if (!name) {
		remote_address(&e, sk, family); /* connected socket */
	} else if (family == AF_INET) {
		struct sockaddr_in sin = {};

		bpf_probe_read_kernel(&sin, sizeof(sin), name);
		if (sin.sin_family != AF_INET)
			return 0;
		e.dport = bpf_ntohs(sin.sin_port);
		__builtin_memcpy(e.daddr, &sin.sin_addr, 4);
	} else {
		struct sockaddr_in6 sin6 = {};

		bpf_probe_read_kernel(&sin6, sizeof(sin6), name);
		if (sin6.sin6_family != AF_INET6)
			return 0;
		e.dport = bpf_ntohs(sin6.sin6_port);
		__builtin_memcpy(e.daddr, &sin6.sin6_addr, 16);
	}
	if (e.dport == 0)
		return 0;

	key.sk = (__u64)sk;
	__builtin_memcpy(key.daddr, e.daddr, 16);
	key.dport = e.dport;
	now = e.ts_ns;
	last = bpf_map_lookup_elem(&udp_seen, &key);
	if (last && now - *last < udp_repeat_ns)
		return 0;
	bpf_map_update_elem(&udp_seen, &key, &now, BPF_ANY);
	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0))
		count_lost();
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
