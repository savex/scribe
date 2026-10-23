//! `scribed` — the scribe background service.
//!
//! Runs as root / SYSTEM under systemd, launchd or the Windows Service Control Manager.

use scribe_core::{Mode, Sensor, VERSION};
use scribe_storage_manager::Registry;

fn platform_sensor() -> Box<dyn Sensor> {
    #[cfg(target_os = "linux")]
    return Box::new(scribe_sensor_linux::EbpfSensor);
    #[cfg(windows)]
    return Box::new(scribe_sensor_windows::EtwSensor);
    // macOS: flows arrive from the Network Extension over XPC; pcap until that exists.
    #[cfg(not(any(target_os = "linux", windows)))]
    return Box::new(scribe_sensor_pcap::PcapSensor { interface: None });
}

fn main() {
    let mode = Mode::default();
    let sensor = platform_sensor();
    let registry = Registry::with_builtin();

    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("scribed {VERSION}");
        return;
    }

    println!("scribed {VERSION} (not functional yet)");
    println!("  mode:     {mode}");
    println!(
        "  sensor:   {} (process info: {})",
        sensor.name(),
        sensor.has_process_info()
    );
    println!(
        "  storage:  {}",
        registry.kinds().collect::<Vec<_>>().join(", ")
    );
    // TODO: load config, start sensor -> enrich -> policy -> storage pipeline, serve local API.
}
