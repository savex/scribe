use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;

pub enum Answer<'a> {
    A(&'a str, Ipv4Addr),
    Aaaa(&'a str, Ipv6Addr),
    Cname(&'a str, &'a str),
}

pub fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = header(id, 0x0100, 0);
    push_question(&mut out, name, qtype);
    out
}

/// Response with uncompressed names, all answers sharing one TTL.
pub fn response(id: u16, name: &str, qtype: u16, answers: &[Answer], ttl: u32) -> Vec<u8> {
    let mut out = header(id, 0x8180, answers.len() as u16);
    push_question(&mut out, name, qtype);
    for answer in answers {
        let (owner, rtype, rdata) = match answer {
            Answer::A(owner, ip) => (*owner, TYPE_A, ip.octets().to_vec()),
            Answer::Aaaa(owner, ip) => (*owner, TYPE_AAAA, ip.octets().to_vec()),
            Answer::Cname(owner, target) => (*owner, TYPE_CNAME, encode_name(target)),
        };
        out.extend(encode_name(owner));
        out.extend(rtype.to_be_bytes());
        out.extend(1u16.to_be_bytes()); // class IN
        out.extend(ttl.to_be_bytes());
        out.extend((rdata.len() as u16).to_be_bytes());
        out.extend(rdata);
    }
    out
}

fn header(id: u16, flags: u16, answers: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(id.to_be_bytes());
    out.extend(flags.to_be_bytes());
    out.extend(1u16.to_be_bytes()); // questions
    out.extend(answers.to_be_bytes());
    out.extend([0, 0, 0, 0]); // authority, additional
    out
}

fn push_question(out: &mut Vec<u8>, name: &str, qtype: u16) {
    out.extend(encode_name(name));
    out.extend(qtype.to_be_bytes());
    out.extend(1u16.to_be_bytes());
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}
