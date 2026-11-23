//! SMK-13: the pcap decoder reads every committed fixture in `testdata/pcap/`.

use scribe_sensor_pcap::decode::decode;
use scribe_sensor_pcap::file::parse;

#[test]
fn pcap_decoder_reads_every_fixture() {
    let dir = scribe_tests::testdata("pcap");
    let mut files = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("pcap") {
            continue;
        }
        files += 1;
        let bytes = std::fs::read(&path).unwrap();
        let capture = parse(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let decoded = capture
            .frames
            .iter()
            .filter(|f| decode(capture.linktype, f.data, f.ts).is_some())
            .count();
        let malformed = path.file_stem().and_then(|s| s.to_str()) == Some("malformed");
        assert_eq!(
            decoded == 0,
            malformed,
            "{}: {decoded} frames decoded",
            path.display()
        );
    }
    assert!(
        files >= 16,
        "only {files} fixtures found in {}",
        dir.display()
    );
}
