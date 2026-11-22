//! SNI from QUIC Initial packets (FR-3, RFC 9000 / 9001, QUIC v2 RFC 9369).
//!
//! The client's Initial keys come from its Destination Connection ID and a published salt, so an
//! observer can decrypt them: HKDF-SHA256 for the keys, AES-128-ECB to remove header protection,
//! AES-128-GCM for the payload, all with `ring`. The CRYPTO frames carry a TLS ClientHello, which
//! may span several Initial packets (large post-quantum key shares); [`InitialReassembler`] joins
//! them by offset. Never panics on any input.

use std::collections::BTreeMap;

use ring::aead::{self, quic, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;

use crate::tls::{parse_client_hello_handshake, ClientHello, HelloError};

pub const VERSION_1: u32 = 0x0000_0001;
pub const VERSION_2: u32 = 0x6b33_43cf;
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
const MAX_CID: usize = 20;
const TAG: usize = 16;
/// CRYPTO bytes kept per flow while waiting for the rest of a ClientHello.
const MAX_CRYPTO: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicError {
    /// Not a long-header Initial packet (short header, Handshake, 0-RTT, Retry, Version Negotiation).
    NotInitial,
    UnsupportedVersion(u32),
    Malformed,
    /// Authentication failed: not a client Initial for this DCID, or corrupted.
    Decrypt,
}

/// Keys protecting one direction of Initial packets.
pub struct InitialKeys {
    key: LessSafeKey,
    iv: [u8; 12],
    hp: quic::HeaderProtectionKey,
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-Expand-Label (RFC 8446 7.1) with an empty context.
fn expand_label(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) {
    let len = (out.len() as u16).to_be_bytes();
    let label_len = [6 + label.len() as u8];
    let info: [&[u8]; 5] = [&len, &label_len, b"tls13 ", label, &[0]];
    prk.expand(&info, Len(out.len()))
        .and_then(|okm| okm.fill(out))
        .expect("HKDF output lengths are fixed and valid");
}

impl InitialKeys {
    /// The client's keys for `dcid` (the Destination Connection ID of its first Initial).
    pub fn client(version: u32, dcid: &[u8]) -> Result<Self, QuicError> {
        let (salt, labels): (&[u8], [&[u8]; 3]) = match version {
            VERSION_1 => (&SALT_V1, [b"quic key", b"quic iv", b"quic hp"]),
            VERSION_2 => (&SALT_V2, [b"quicv2 key", b"quicv2 iv", b"quicv2 hp"]),
            v => return Err(QuicError::UnsupportedVersion(v)),
        };
        let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dcid);
        let mut secret = [0u8; 32];
        expand_label(&initial, b"client in", &mut secret);
        let client = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &secret);
        let (mut key, mut iv, mut hp) = ([0u8; 16], [0u8; 12], [0u8; 16]);
        expand_label(&client, labels[0], &mut key);
        expand_label(&client, labels[1], &mut iv);
        expand_label(&client, labels[2], &mut hp);
        Ok(Self {
            key: LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).expect("16-byte key")),
            iv,
            hp: quic::HeaderProtectionKey::new(&quic::AES_128, &hp).expect("16-byte key"),
        })
    }
}

/// One decrypted Initial packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Initial {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub packet_number: u64,
    /// The decrypted frames.
    pub payload: Vec<u8>,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], QuicError> {
        if self.0.len() < n {
            return Err(QuicError::Malformed);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, QuicError> {
        Ok(self.bytes(1)?[0])
    }

    /// QUIC variable-length integer (RFC 9000 16).
    fn varint(&mut self) -> Result<u64, QuicError> {
        let first = self.u8()?;
        let len = 1usize << (first >> 6);
        let mut v = u64::from(first & 0x3f);
        for &b in self.bytes(len - 1)? {
            v = (v << 8) | u64::from(b);
        }
        Ok(v)
    }

    fn len_bytes(&mut self) -> Result<&'a [u8], QuicError> {
        let n = self.varint()?;
        self.bytes(usize::try_from(n).map_err(|_| QuicError::Malformed)?)
    }
}

/// Decrypt the first packet of a UDP datagram if it is a client Initial (v1 or v2). Coalesced
/// packets after it are ignored.
pub fn decrypt_initial(datagram: &[u8]) -> Result<Initial, QuicError> {
    let mut r = Reader(datagram);
    let first = r.u8().map_err(|_| QuicError::NotInitial)?;
    if first & 0x80 == 0 {
        return Err(QuicError::NotInitial);
    }
    let version = u32::from_be_bytes(
        r.bytes(4)
            .map_err(|_| QuicError::NotInitial)?
            .try_into()
            .expect("4 bytes"),
    );
    let initial_type = match version {
        VERSION_1 => 0b00,
        VERSION_2 => 0b01,
        0 => return Err(QuicError::NotInitial), // Version Negotiation
        v => return Err(QuicError::UnsupportedVersion(v)),
    };
    if (first >> 4) & 0b11 != initial_type {
        return Err(QuicError::NotInitial);
    }
    let dcid_len = r.u8()? as usize;
    if dcid_len > MAX_CID {
        return Err(QuicError::Malformed);
    }
    let dcid = r.bytes(dcid_len)?;
    let scid_len = r.u8()? as usize;
    if scid_len > MAX_CID {
        return Err(QuicError::Malformed);
    }
    r.bytes(scid_len)?;
    r.len_bytes()?; // token
    let length = usize::try_from(r.varint()?).map_err(|_| QuicError::Malformed)?;
    let pn_offset = datagram.len() - r.0.len();
    // The sample starts 4 bytes after the packet number's start, whatever its real length.
    if length < 4 + TAG || r.0.len() < length {
        return Err(QuicError::Malformed);
    }
    let keys = InitialKeys::client(version, dcid)?;
    let mut packet = datagram[..pn_offset + length].to_vec();
    let sample = &packet[pn_offset + 4..pn_offset + 4 + TAG];
    let mask = keys.hp.new_mask(sample).map_err(|_| QuicError::Malformed)?;
    packet[0] ^= mask[0] & 0x0f;
    let pn_len = usize::from(packet[0] & 0x03) + 1;
    let mut pn = 0u64;
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | u64::from(packet[pn_offset + i]);
    }
    let mut nonce = keys.iv;
    for (n, p) in nonce[4..].iter_mut().zip(pn.to_be_bytes()) {
        *n ^= p;
    }
    let (header, body) = packet.split_at_mut(pn_offset + pn_len);
    let plain = keys
        .key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&*header),
            body,
        )
        .map_err(|_| QuicError::Decrypt)?;
    Ok(Initial {
        version,
        dcid: dcid.to_vec(),
        packet_number: pn,
        payload: plain.to_vec(),
    })
}

/// The CRYPTO frames of a decrypted Initial payload, as (offset, data). Only frames allowed in
/// Initial packets are accepted (PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE).
pub fn crypto_frames(payload: &[u8]) -> Result<Vec<(u64, &[u8])>, QuicError> {
    let mut r = Reader(payload);
    let mut out = Vec::new();
    while !r.0.is_empty() {
        match r.varint()? {
            0x00 | 0x01 => {}
            ty @ (0x02 | 0x03) => {
                r.varint()?; // largest acknowledged
                r.varint()?; // delay
                let ranges = r.varint()?;
                r.varint()?; // first range
                for _ in 0..ranges {
                    r.varint()?;
                    r.varint()?;
                }
                if ty == 0x03 {
                    for _ in 0..3 {
                        r.varint()?;
                    }
                }
            }
            0x06 => {
                let offset = r.varint()?;
                out.push((offset, r.len_bytes()?));
            }
            0x1c => {
                r.varint()?; // error code
                r.varint()?; // frame type
                r.len_bytes()?; // reason
            }
            _ => return Err(QuicError::Malformed),
        }
    }
    Ok(out)
}

/// What [`InitialReassembler::push`] learned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// More CRYPTO data is needed.
    NeedMore,
    Hello(ClientHello),
    /// This flow will not yield a ClientHello (not TLS, malformed, too large).
    Failed,
}

/// Joins the CRYPTO data of one flow's client Initials until the ClientHello is complete.
#[derive(Debug, Default)]
pub struct InitialReassembler {
    dcid: Option<Vec<u8>>,
    chunks: BTreeMap<u64, Vec<u8>>,
    done: bool,
}

impl InitialReassembler {
    /// Feed one client datagram. Datagrams that are not client Initials for this flow's first
    /// DCID are ignored (returns `NeedMore`).
    pub fn push(&mut self, datagram: &[u8]) -> Progress {
        if self.done {
            return Progress::Failed;
        }
        let Ok(initial) = decrypt_initial(datagram) else {
            return Progress::NeedMore;
        };
        match &self.dcid {
            Some(d) if *d != initial.dcid => return Progress::NeedMore,
            Some(_) => {}
            None => self.dcid = Some(initial.dcid.clone()),
        }
        let Ok(frames) = crypto_frames(&initial.payload) else {
            return self.fail();
        };
        for (offset, data) in frames {
            if offset.saturating_add(data.len() as u64) > MAX_CRYPTO {
                return self.fail();
            }
            let slot = self.chunks.entry(offset).or_default();
            if data.len() > slot.len() {
                *slot = data.to_vec();
            }
        }
        let mut joined = Vec::new();
        for (&offset, data) in &self.chunks {
            let end = offset as usize + data.len();
            if offset as usize > joined.len() {
                break; // gap
            }
            if end > joined.len() {
                joined.extend_from_slice(&data[joined.len() - offset as usize..]);
            }
        }
        match parse_client_hello_handshake(&joined) {
            Ok(hello) => {
                self.done = true;
                self.chunks.clear();
                Progress::Hello(hello)
            }
            Err(HelloError::Incomplete) => Progress::NeedMore,
            Err(_) => self.fail(),
        }
    }

    fn fail(&mut self) -> Progress {
        self.done = true;
        self.chunks.clear();
        Progress::Failed
    }
}

/// The ClientHello of a single datagram, when it carries all of it.
pub fn client_hello_from_initial(datagram: &[u8]) -> Option<ClientHello> {
    match InitialReassembler::default().push(datagram) {
        Progress::Hello(h) => Some(h),
        _ => None,
    }
}
