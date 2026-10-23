use std::net::IpAddr;
use std::time::SystemTime;

/// An alert raised by the policy engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub ts: SystemTime,
    pub host: Option<String>,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub process_path: Option<String>,
    pub score: u32,
    pub reason: String,
}

/// Destination for alerts: OS notification, log, webhook.
pub trait AlertOutput: Send + Sync {
    fn name(&self) -> &str;
    fn notify(&self, alert: &Alert);
}
