//! Reading classic pcap files (not pcapng): both byte orders, microsecond and nanosecond
//! timestamps. Used to replay captures and the test fixtures through the same decoder and flow
//! tracker as live capture.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FileError {
    #[error("not a pcap file (pcapng files must be converted, e.g. with `tshark -F pcap`)")]
    NotPcap,
    #[error("truncated pcap file")]
    Truncated,
}

/// One captured frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    pub ts: SystemTime,
    pub data: &'a [u8],
}

/// A parsed capture: its link type and frames.
#[derive(Debug, Clone)]
pub struct Capture<'a> {
    pub linktype: i32,
    pub frames: Vec<Frame<'a>>,
}

pub fn parse(bytes: &[u8]) -> Result<Capture<'_>, FileError> {
    let magic = bytes.get(..4).ok_or(FileError::NotPcap)?;
    let (le, nanos) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err(FileError::NotPcap),
    };
    let u32_at = |at: usize| -> Result<u32, FileError> {
        let b: [u8; 4] = bytes
            .get(at..at + 4)
            .ok_or(FileError::Truncated)?
            .try_into()
            .map_err(|_| FileError::Truncated)?;
        Ok(if le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    let linktype = (u32_at(20)? & 0x0fff_ffff) as i32;
    let mut frames = Vec::new();
    let mut at = 24;
    while at < bytes.len() {
        let secs = u32_at(at)?;
        let frac = u32_at(at + 4)?;
        let caplen = u32_at(at + 8)? as usize;
        let start = at + 16;
        let data = bytes
            .get(start..start + caplen)
            .ok_or(FileError::Truncated)?;
        let sub = if nanos {
            Duration::from_nanos(u64::from(frac))
        } else {
            Duration::from_micros(u64::from(frac))
        };
        frames.push(Frame {
            ts: UNIX_EPOCH + Duration::from_secs(u64::from(secs)) + sub,
            data,
        });
        at = start + caplen;
    }
    Ok(Capture { linktype, frames })
}
