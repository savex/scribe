use std::net::SocketAddr;

use scribe_process::{parse_proc_net, ProcNetEntry};

const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18001 1 0000000000000000 100 0 0 10 0
   1: 0200000A:C350 0700A8C0:01BB 01 00000000:00000000 02:000A2B4C 00000000  1000        0 18002 2 0000000000000000 20 4 30 10 -1
   2: garbage line
";

const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000200000A:C351 0000000000000000FFFF00000700A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 18003 1 0000000000000000 20 4 30 10 -1
   1: B80D0120000000000000000001000000:C352 B80D0120000000000000000002000000:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 18004 1 0000000000000000 20 4 30 10 -1
";

const UDP: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:D431 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 18005 2 0000000000000000 0
";

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[test]
fn ipv4_lines_give_addresses_inodes_and_listen_state() {
    let entries = parse_proc_net(TCP);
    assert_eq!(
        entries,
        [
            ProcNetEntry {
                local: addr("127.0.0.1:631"),
                remote: None,
                inode: 18001,
                listening: true,
            },
            ProcNetEntry {
                local: addr("10.0.0.2:50000"),
                remote: Some(addr("192.168.0.7:443")),
                inode: 18002,
                listening: false,
            },
        ],
        "the header and the garbage line are skipped"
    );
}

#[test]
fn ipv6_lines_keep_v4_mapped_and_v6_addresses() {
    let entries = parse_proc_net(TCP6);
    assert_eq!(entries[0].local, addr("[::ffff:10.0.0.2]:50001"));
    assert_eq!(entries[0].remote, Some(addr("[::ffff:192.168.0.7]:443")));
    assert_eq!(entries[1].local, addr("[2001:db8::1]:50002"));
    assert_eq!(entries[1].remote, Some(addr("[2001:db8::2]:443")));
}

#[test]
fn unconnected_udp_has_no_remote() {
    let entries = parse_proc_net(UDP);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].local, addr("0.0.0.0:54321"));
    assert_eq!(entries[0].remote, None);
    assert!(!entries[0].listening);
    assert!(parse_proc_net("").is_empty());
}
