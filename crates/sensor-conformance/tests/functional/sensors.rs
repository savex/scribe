//! Real sensors against the suite. Needs capture privileges:
//! `sudo -E cargo test -p scribe-sensor-conformance --test sensors -- --ignored`

use scribe_sensor_conformance::{run_sensor_suite, SuiteOptions};

fn loopback_interface() -> &'static str {
    if cfg!(target_os = "linux") {
        "lo"
    } else if cfg!(windows) {
        r"\Device\NPF_Loopback"
    } else {
        "lo0"
    }
}

#[test]
#[ignore = "needs capture privileges (root, or Npcap on Windows)"]
fn pcap_sensor_conforms() {
    let mut sensor = scribe_sensor_pcap::PcapSensor::new(Some(loopback_interface().into()));
    let opts = SuiteOptions {
        expect_process_info: false,
        names_flows: false,
        ..Default::default()
    };
    if let Err(failures) = run_sensor_suite(&mut sensor, &opts) {
        panic!("pcap sensor failed:\n{}", failures.join("\n"));
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs root, or CAP_BPF, CAP_PERFMON and CAP_NET_RAW; kernel 5.8+ (6.0+ on arm64)"]
fn ebpf_sensor_conforms() {
    let mut sensor = scribe_sensor_linux::EbpfSensor::default();
    let opts = SuiteOptions {
        expect_process_info: true,
        names_flows: false,
        ..Default::default()
    };
    if let Err(failures) = run_sensor_suite(&mut sensor, &opts) {
        panic!("eBPF sensor failed:\n{}", failures.join("\n"));
    }
}

// TODO: Windows ETW (cfg windows) and the macOS Network Extension bridge (option 9A) get a test
// here each once their sensors exist.
