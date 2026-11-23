//! The module's API (specs 7.4.5): the `scribe.v1.modules.url.Url` service, served by scribed
//! while the module is enabled, and the `scribe url …` subcommand.

/// Generated messages and, per feature, `url_server` / `url_client`.
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod pb {
    tonic::include_proto!("scribe.v1.modules.url");
}

/// Requests listed when the call names no limit, and the most it may ask for.
pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 10_000;

/// A stored `url.request` record as the API shows it.
pub fn request(r: &scribe_core::ModuleRecord) -> pb::Request {
    let text = |key: &str| {
        r.payload
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    pb::Request {
        ts_ms: r
            .ts
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64),
        host: r.host.clone().unwrap_or_default(),
        method: text("method"),
        url: text("url"),
    }
}

#[cfg(feature = "server")]
pub use server::{service, UrlApi};

#[cfg(feature = "server")]
mod server {
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    use scribe_module_api::RecordReader;
    use tonic::{Request, Response, Status};

    use super::pb::url_server::{Url, UrlServer};
    use super::pb::{ListRequest, RequestList};
    use super::{request, DEFAULT_LIMIT, MAX_LIMIT};

    /// The service over the daemon's stored records.
    pub struct UrlApi {
        reader: Arc<dyn RecordReader>,
    }

    impl UrlApi {
        pub fn new(reader: Arc<dyn RecordReader>) -> Self {
            Self { reader }
        }
    }

    /// The service with the API's message size limit.
    pub fn service(reader: Arc<dyn RecordReader>) -> UrlServer<UrlApi> {
        UrlServer::new(UrlApi::new(reader))
            .max_decoding_message_size(scribe_api::limits::MAX_MESSAGE)
            .max_encoding_message_size(scribe_api::limits::MAX_MESSAGE)
    }

    #[tonic::async_trait]
    impl Url for UrlApi {
        async fn list(
            &self,
            request_: Request<ListRequest>,
        ) -> Result<Response<RequestList>, Status> {
            // A read call: anyone who can reach the socket, with an identity from the transport.
            scribe_api::access::caller(&request_)?;
            let r = request_.into_inner();
            let limit = match r.limit as usize {
                0 => DEFAULT_LIMIT,
                n => n.min(MAX_LIMIT),
            };
            let host = r.host.trim().trim_end_matches('.').to_ascii_lowercase();
            let since = r
                .since_ms
                .map(|ms| UNIX_EPOCH + Duration::from_millis(ms.max(0) as u64));
            let records = self
                .reader
                .records(
                    crate::REQUEST,
                    (!host.is_empty()).then_some(host.as_str()),
                    since,
                    limit,
                )
                .await
                .map_err(Status::unavailable)?;
            Ok(Response::new(RequestList {
                items: records.iter().map(request).collect(),
            }))
        }
    }
}

#[cfg(feature = "client")]
pub use client::{run, UrlCommand};

#[cfg(feature = "client")]
mod client {
    use std::fmt::Write as _;
    use std::time::Duration;

    use tonic::transport::Channel;

    use super::pb::url_client::UrlClient;
    use super::pb::{ListRequest, RequestList};

    /// `scribe url …`
    #[derive(Debug, Clone, PartialEq, Eq, clap::Subcommand)]
    pub enum UrlCommand {
        /// Stored plaintext HTTP requests, newest last
        List {
            /// Only requests to this host
            #[arg(long)]
            host: Option<String>,
            /// At most this many, the newest (default 100)
            #[arg(long, default_value_t = 100)]
            limit: u32,
            /// Only from this long ago on, e.g. 1h
            #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
            since: Option<Duration>,
            /// Print JSON
            #[arg(long)]
            json: bool,
        },
    }

    fn parse_duration(s: &str) -> Result<Duration, String> {
        s.parse::<scribe_core::HumanDuration>()
            .map(Duration::from)
            .map_err(|e| e.to_string())
    }

    /// Runs `command` over `channel`; returns what to print.
    pub async fn run(command: &UrlCommand, channel: Channel) -> Result<String, tonic::Status> {
        let UrlCommand::List {
            host,
            limit,
            since,
            json,
        } = command;
        let since_ms = since.map(|d| {
            std::time::SystemTime::now()
                .checked_sub(d)
                .unwrap_or(std::time::UNIX_EPOCH)
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as i64)
        });
        let list = UrlClient::new(channel)
            .max_decoding_message_size(scribe_api::limits::MAX_MESSAGE)
            .list(ListRequest {
                host: host.clone().unwrap_or_default(),
                limit: *limit,
                since_ms,
            })
            .await?
            .into_inner();
        Ok(if *json {
            serde_json::to_string_pretty(&list).unwrap_or_default() + "\n"
        } else {
            render(&list)
        })
    }

    /// One request per line: time, method, URL.
    pub fn render(list: &RequestList) -> String {
        if list.items.is_empty() {
            return "no requests stored\n".into();
        }
        let mut out = String::new();
        for r in &list.items {
            let _ = writeln!(
                out,
                "{}  {:<7} {}",
                scribe_core::time::rfc3339_ms(r.ts_ms),
                r.method,
                r.url
            );
        }
        out
    }
}

#[cfg(feature = "client")]
pub use client::render;
