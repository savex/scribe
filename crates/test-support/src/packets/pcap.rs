/// Base timestamp for fixtures: 2023-11-14T22:13:20Z.
pub const BASE_TS_SECS: u32 = 1_700_000_000;

/// Classic little-endian pcap file, Ethernet link type, one frame per millisecond.
pub fn write_pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0xa1b2_c3d4u32.to_le_bytes());
    out.extend(2u16.to_le_bytes());
    out.extend(4u16.to_le_bytes());
    out.extend(0i32.to_le_bytes()); // thiszone
    out.extend(0u32.to_le_bytes()); // sigfigs
    out.extend(65_535u32.to_le_bytes()); // snaplen
    out.extend(1u32.to_le_bytes()); // LINKTYPE_ETHERNET

    for (i, frame) in frames.iter().enumerate() {
        out.extend(BASE_TS_SECS.to_le_bytes());
        out.extend(((i as u32) * 1000).to_le_bytes());
        out.extend((frame.len() as u32).to_le_bytes());
        out.extend((frame.len() as u32).to_le_bytes());
        out.extend_from_slice(frame);
    }
    out
}
