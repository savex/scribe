//! The sensor: device choice and the libpcap binding (live capture needs privileges and runs in
//! the sensor conformance suite).

use std::net::IpAddr;

use scribe_core::Sensor;
use scribe_sensor_pcap::choose_device;
use scribe_sensor_pcap::ffi::{Device, Lib, PCAP_IF_LOOPBACK, PCAP_IF_RUNNING, PCAP_IF_UP};
use scribe_sensor_pcap::PcapSensor;

fn device(name: &str, flags: u32, addresses: &[&str]) -> Device {
    Device {
        name: name.into(),
        description: String::new(),
        flags,
        addresses: addresses
            .iter()
            .map(|a| a.parse::<IpAddr>().unwrap())
            .collect(),
    }
}

const UP: u32 = PCAP_IF_UP | PCAP_IF_RUNNING;

#[test]
fn any_wins_then_the_first_real_interface() {
    let devices = vec![
        device("lo0", UP | PCAP_IF_LOOPBACK, &["127.0.0.1"]),
        device("utun0", UP, &[]),
        device("en0", UP, &["192.0.2.5", "2001:db8::5"]),
        device("en1", UP, &["198.51.100.5"]),
    ];
    let (name, local) = choose_device(&devices, None).unwrap();
    assert_eq!(name, "en0");
    assert_eq!(local.len(), 4, "every device's addresses are local");
    let mut with_any = devices.clone();
    with_any.push(device("any", UP, &[]));
    assert_eq!(choose_device(&with_any, None).unwrap().0, "any");
    assert_eq!(
        choose_device(&with_any, Some("")).unwrap().0,
        "any",
        "empty = automatic"
    );
}

#[test]
fn a_named_device_must_exist() {
    let devices = vec![device("lo0", UP | PCAP_IF_LOOPBACK, &["127.0.0.1"])];
    assert_eq!(choose_device(&devices, Some("lo0")).unwrap().0, "lo0");
    let err = choose_device(&devices, Some("eth9")).unwrap_err();
    assert!(
        err.contains("no capture device \"eth9\"") && err.contains("lo0"),
        "{err}"
    );
    let err = choose_device(&devices, None).unwrap_err();
    assert!(err.contains("no capture device is up"), "{err}");
}

#[test]
fn devices_with_no_flags_count_as_up() {
    // Older libpcap and Npcap don't set the UP / RUNNING flags.
    assert!(device("x", 0, &[]).is_up());
    assert!(!device("x", PCAP_IF_UP, &[]).is_up(), "up but not running");
}

#[test]
fn the_system_libpcap_loads_and_lists_devices() {
    let lib = match Lib::load() {
        Ok(lib) => lib,
        Err(e) => {
            // CI machines without libpcap / Npcap: nothing to check here.
            eprintln!("skipped: {e}");
            return;
        }
    };
    let devices = lib.devices().expect("pcap_findalldevs");
    assert!(!devices.is_empty(), "at least a loopback device");
    assert!(devices
        .iter()
        .any(|d| d.is_loopback() || d.name.starts_with("lo")));
}

#[test]
fn the_sensor_reports_no_process_info() {
    let mut s = PcapSensor::new(Some("lo0".into()));
    assert_eq!(s.name(), "pcap");
    assert!(!s.has_process_info());
    s.set_payload(false);
    s.stop(); // stopping a sensor that never started is fine
}
