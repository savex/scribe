//! Real sensors against the suite. Needs capture privileges:
//! `sudo -E cargo test -p scribe-sensor-conformance --test sensors -- --ignored`

use scribe_sensor_conformance::{run_sensor_suite, SuiteOptions};

#[test]
#[ignore = "needs capture privileges; pcap sensor not implemented yet"]
fn pcap_sensor_conforms() {
    let mut sensor = scribe_sensor_pcap::PcapSensor {
        interface: Some(loopback_interface().into()),
    };
    let opts = SuiteOptions {
        expect_process_info: false,
        ..Default::default()
    };
    if let Err(failures) = run_sensor_suite(&mut sensor, &opts) {
        panic!("pcap sensor failed:\n{}", failures.join("\n"));
    }
}

fn loopback_interface() -> &'static str {
    if cfg!(target_os = "linux") {
        "lo"
    } else if cfg!(windows) {
        r"\Device\NPF_Loopback"
    } else {
        "lo0"
    }
}

// TODO: linux eBPF (cfg linux), Windows ETW (cfg windows) and the macOS Network Extension
// bridge get a test here each once their sensors exist.
