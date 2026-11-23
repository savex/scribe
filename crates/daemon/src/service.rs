//! Running under a service manager (specs 6.1): systemd readiness notifications on Linux, the
//! Windows service control manager, and the files that install scribed as a service
//! (`packaging/`). launchd needs nothing from the binary: it runs `scribed` in the foreground and
//! stops it with SIGTERM.

/// Tell systemd (`Type=notify`) about a state change, e.g. `READY=1` or `STOPPING=1`. Does nothing
/// when not started by systemd (`NOTIFY_SOCKET` unset) and on other systems.
pub fn notify(state: &str) {
    #[cfg(target_os = "linux")]
    if let Some(path) = std::env::var_os("NOTIFY_SOCKET") {
        if let Err(e) = notify_socket(&path, state) {
            tracing::warn!("cannot notify systemd ({state}): {e}");
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = state;
}

/// Send one notification to the systemd socket at `path` (`@name` = abstract namespace).
#[cfg(target_os = "linux")]
pub fn notify_socket(path: &std::ffi::OsStr, state: &str) -> std::io::Result<()> {
    linux::send(path, state)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsStr;
    use std::io;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    pub fn send(path: &OsStr, state: &str) -> io::Result<()> {
        let socket = UnixDatagram::unbound()?;
        let bytes = path.as_bytes();
        let addr = match bytes.strip_prefix(b"@") {
            // Abstract socket namespace.
            Some(name) => SocketAddr::from_abstract_name(name)?,
            None => SocketAddr::from_pathname(path)?,
        };
        socket.send_to_addr(state.as_bytes(), &addr)?;
        Ok(())
    }
}

/// The service name scribed registers with the Windows service control manager.
pub const WINDOWS_SERVICE: &str = "scribed";

/// Run as a Windows service (`scribed --service`): the service control manager starts and stops
/// it; Stop and Shutdown end `serve` like Ctrl-C does.
#[cfg(windows)]
pub fn run_windows_service() -> std::process::ExitCode {
    match windows::start() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("scribed: cannot run as a Windows service: {e}");
            std::process::ExitCode::from(crate::app::EXIT_FAILURE)
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::OsString;
    use std::time::Duration;

    use clap::Parser;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    use super::WINDOWS_SERVICE;

    define_windows_service!(ffi_service_main, service_main);

    pub fn start() -> windows_service::Result<()> {
        service_dispatcher::start(WINDOWS_SERVICE, ffi_service_main)
    }

    fn status(state: ServiceState, exit: u32) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(exit),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        }
    }

    fn service_main(_arguments: Vec<OsString>) {
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let handler = move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let Ok(handle) = service_control_handler::register(WINDOWS_SERVICE, handler) else {
            return;
        };
        let _ = handle.set_service_status(status(ServiceState::Running, 0));
        let args = crate::app::Args::parse_from(std::env::args_os());
        let code = crate::app::run_until(
            args,
            std::env::var_os("SCRIBE_CONFIG"),
            std::env::var("SCRIBE_LOG").ok(),
            async move {
                let _ = tokio::task::spawn_blocking(move || stop_rx.recv()).await;
            },
        );
        let exit = if code == std::process::ExitCode::SUCCESS {
            0
        } else {
            1
        };
        let _ = handle.set_service_status(status(ServiceState::Stopped, exit));
    }
}
