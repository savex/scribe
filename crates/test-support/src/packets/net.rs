use std::net::{IpAddr, SocketAddr};

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

const CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn pseudo_header(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            out.extend(s.octets());
            out.extend(d.octets());
            out.extend([0, proto]);
            out.extend((len as u16).to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            out.extend(s.octets());
            out.extend(d.octets());
            out.extend((len as u32).to_be_bytes());
            out.extend([0, 0, 0, proto]);
        }
        _ => panic!("source and destination must use the same IP version"),
    }
    out
}

/// Transport checksum over pseudo header + segment, written at `offset` in `segment`.
fn fill_transport_checksum(src: IpAddr, dst: IpAddr, proto: u8, segment: &mut [u8], offset: usize) {
    let mut data = pseudo_header(src, dst, proto, segment.len());
    data.extend_from_slice(segment);
    let sum = checksum(&data);
    segment[offset..offset + 2].copy_from_slice(&sum.to_be_bytes());
}

fn ip_packet(src: IpAddr, dst: IpAddr, proto: u8, payload: &[u8]) -> (u16, Vec<u8>) {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = (20 + payload.len()) as u16;
            let mut h = vec![0x45, 0x00];
            h.extend(total.to_be_bytes());
            h.extend([0x00, 0x00, 0x40, 0x00, 64, proto, 0x00, 0x00]);
            h.extend(s.octets());
            h.extend(d.octets());
            let sum = checksum(&h);
            h[10..12].copy_from_slice(&sum.to_be_bytes());
            h.extend_from_slice(payload);
            (0x0800, h)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut h = vec![0x60, 0x00, 0x00, 0x00];
            h.extend((payload.len() as u16).to_be_bytes());
            h.extend([proto, 64]);
            h.extend(s.octets());
            h.extend(d.octets());
            h.extend_from_slice(payload);
            (0x86dd, h)
        }
        _ => panic!("source and destination must use the same IP version"),
    }
}

fn ethernet(ethertype: u16, payload: &[u8], from_client: bool) -> Vec<u8> {
    let (dst, src) = if from_client {
        (GATEWAY_MAC, CLIENT_MAC)
    } else {
        (CLIENT_MAC, GATEWAY_MAC)
    };
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend(dst);
    f.extend(src);
    f.extend(ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Ethernet frame carrying one TCP segment from `src` to `dst`.
pub fn tcp_frame(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    from_client: bool,
) -> Vec<u8> {
    let mut seg = Vec::with_capacity(20 + payload.len());
    seg.extend(src.port().to_be_bytes());
    seg.extend(dst.port().to_be_bytes());
    seg.extend(seq.to_be_bytes());
    seg.extend(ack.to_be_bytes());
    seg.extend([5 << 4, flags, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);
    seg.extend_from_slice(payload);
    fill_transport_checksum(src.ip(), dst.ip(), PROTO_TCP, &mut seg, 16);
    let (ethertype, ip) = ip_packet(src.ip(), dst.ip(), PROTO_TCP, &seg);
    ethernet(ethertype, &ip, from_client)
}

/// Ethernet frame carrying one UDP datagram from `src` to `dst`.
pub fn udp_frame(src: SocketAddr, dst: SocketAddr, payload: &[u8], from_client: bool) -> Vec<u8> {
    let mut seg = Vec::with_capacity(8 + payload.len());
    seg.extend(src.port().to_be_bytes());
    seg.extend(dst.port().to_be_bytes());
    seg.extend(((8 + payload.len()) as u16).to_be_bytes());
    seg.extend([0x00, 0x00]);
    seg.extend_from_slice(payload);
    fill_transport_checksum(src.ip(), dst.ip(), PROTO_UDP, &mut seg, 6);
    let (ethertype, ip) = ip_packet(src.ip(), dst.ip(), PROTO_UDP, &seg);
    ethernet(ethertype, &ip, from_client)
}

/// Tracks sequence numbers for one client -> server TCP connection.
pub struct TcpFlow {
    pub client: SocketAddr,
    pub server: SocketAddr,
    client_seq: u32,
    server_seq: u32,
}

impl TcpFlow {
    pub fn new(client: SocketAddr, server: SocketAddr) -> Self {
        Self {
            client,
            server,
            client_seq: 1000,
            server_seq: 5000,
        }
    }

    /// SYN, SYN-ACK, ACK.
    pub fn handshake(&mut self) -> Vec<Vec<u8>> {
        let (c, s) = (self.client, self.server);
        let frames = vec![
            tcp_frame(c, s, self.client_seq, 0, SYN, &[], true),
            tcp_frame(
                s,
                c,
                self.server_seq,
                self.client_seq + 1,
                SYN | ACK,
                &[],
                false,
            ),
            tcp_frame(
                c,
                s,
                self.client_seq + 1,
                self.server_seq + 1,
                ACK,
                &[],
                true,
            ),
        ];
        self.client_seq += 1;
        self.server_seq += 1;
        frames
    }

    /// One client data segment; advances the client sequence number.
    pub fn client_data(&mut self, payload: &[u8]) -> Vec<u8> {
        let frame = tcp_frame(
            self.client,
            self.server,
            self.client_seq,
            self.server_seq,
            PSH | ACK,
            payload,
            true,
        );
        self.client_seq += payload.len() as u32;
        frame
    }

    pub fn client_fin(&mut self) -> Vec<u8> {
        let frame = tcp_frame(
            self.client,
            self.server,
            self.client_seq,
            self.server_seq,
            FIN | ACK,
            &[],
            true,
        );
        self.client_seq += 1;
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod functional {
        use super::*;

        #[test]
        fn ipv4_header_checksum_verifies_to_zero() {
            let frame = udp_frame(
                "10.0.0.2:5000".parse().unwrap(),
                "192.0.2.1:53".parse().unwrap(),
                b"x",
                true,
            );
            assert_eq!(checksum(&frame[14..34]), 0);
        }
    }
}
