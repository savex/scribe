/* Records the eBPF programs hand to scribed through the ring buffer (plan option 7B).
 * Mirrored by crates/sensor-linux/src/record.rs: change both together and bump
 * SCRIBE_RECORD_VERSION. Integers are in host byte order, addresses in network order. */
#ifndef SCRIBE_H
#define SCRIBE_H

#define SCRIBE_RECORD_VERSION 1
#define SCRIBE_COMM_LEN 16

enum scribe_kind {
	SCRIBE_TCP_CONNECT = 1, /* tcp_connect(): a new outgoing TCP connection */
	SCRIBE_UDP_SEND = 2,    /* udp_sendmsg() / udpv6_sendmsg(): first datagram of a flow (deduplicated) */
};

struct scribe_flow {
	__u64 ts_ns;      /* bpf_ktime_get_ns() */
	__u64 cgroup_id;  /* bpf_get_current_cgroup_id() */
	__u32 tgid;       /* process id */
	__u32 pid;        /* thread id */
	__u32 uid;
	__u16 family;     /* AF_INET (2) or AF_INET6 (10) */
	__u8 kind;        /* enum scribe_kind */
	__u8 version;     /* SCRIBE_RECORD_VERSION */
	__u16 sport;      /* host order; 0 if not bound yet */
	__u16 dport;      /* host order */
	__u8 saddr[16];   /* IPv4 in the first 4 bytes; all zero for an unbound UDP socket */
	__u8 daddr[16];
	char comm[SCRIBE_COMM_LEN];
	__u32 pad;
};                        /* 88 bytes */

#endif
