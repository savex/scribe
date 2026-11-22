#[derive(Debug, Clone, Default)]
pub struct ClientHelloOptions {
    pub sni: Option<String>,
    /// Adds `supported_versions` with TLS 1.3; otherwise a TLS 1.2-only hello.
    pub tls13: bool,
    /// Adds an `encrypted_client_hello` (0xfe0d) extension; `sni` is then the outer public name.
    pub ech: bool,
    /// Adds an ALPN extension with these protocols when not empty.
    pub alpn: Vec<String>,
}

/// TLS 1.3 ClientHello with the given SNI.
pub fn client_hello_sni(host: &str) -> Vec<u8> {
    client_hello(&ClientHelloOptions {
        sni: Some(host.into()),
        tls13: true,
        ..Default::default()
    })
}

/// A complete TLS record containing one ClientHello handshake message.
pub fn client_hello(opts: &ClientHelloOptions) -> Vec<u8> {
    let mut ext = Vec::new();
    if let Some(name) = &opts.sni {
        let name = name.as_bytes();
        let mut list = vec![0x00]; // host_name
        list.extend((name.len() as u16).to_be_bytes());
        list.extend_from_slice(name);
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend(list);
        push_extension(&mut ext, 0x0000, &data);
    }
    push_extension(&mut ext, 0x000a, &[0x00, 0x02, 0x00, 0x1d]); // supported_groups: x25519
    if !opts.alpn.is_empty() {
        let mut list = Vec::new();
        for p in &opts.alpn {
            list.push(p.len() as u8);
            list.extend_from_slice(p.as_bytes());
        }
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend(list);
        push_extension(&mut ext, 0x0010, &data);
    }
    if opts.tls13 {
        push_extension(&mut ext, 0x002b, &[0x02, 0x03, 0x04]); // supported_versions: TLS 1.3
    }
    if opts.ech {
        // outer, HKDF-SHA256, AES-128-GCM, config id, enc, payload
        let mut data = vec![0x00, 0x00, 0x01, 0x00, 0x01, 0x2a];
        data.extend(32u16.to_be_bytes());
        data.extend([0xec; 32]);
        data.extend(64u16.to_be_bytes());
        data.extend([0xed; 64]);
        push_extension(&mut ext, 0xfe0d, &data);
    }

    let mut body = vec![0x03, 0x03]; // legacy_version TLS 1.2
    body.extend([0x11; 32]); // random
    body.push(32);
    body.extend([0x22; 32]); // legacy_session_id
    let suites: &[u16] = if opts.tls13 {
        &[0x1301, 0x1302, 0xc02f]
    } else {
        &[0xc02f, 0xc030]
    };
    body.extend(((suites.len() * 2) as u16).to_be_bytes());
    for suite in suites {
        body.extend(suite.to_be_bytes());
    }
    body.extend([0x01, 0x00]); // compression: null
    body.extend((ext.len() as u16).to_be_bytes());
    body.extend(ext);

    let mut handshake = vec![0x01]; // client_hello
    handshake.extend(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend(body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend((handshake.len() as u16).to_be_bytes());
    record.extend(handshake);
    record
}

fn push_extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    out.extend(ext_type.to_be_bytes());
    out.extend((data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}
