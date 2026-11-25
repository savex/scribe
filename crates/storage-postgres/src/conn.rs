//! Connection settings: the URL (no password in it), the password from `credentials`, an optional
//! `schema`, and the TLS rule of specs 12.1.1: a server that isn't on this machine is reached only
//! over TLS with full certificate checks (the system trust store through `scribe-net`, like
//! webhooks); `sslmode=disable` or `prefer` is refused for it. A loopback or Unix-socket server
//! may go without TLS.

use std::str::FromStr;
use std::sync::Arc;

use scribe_storage_api::{required_option, BackendOptions, Result, StorageError};
use tokio_postgres::config::{Host, SslMode};
use tokio_postgres::{Client, Config, NoTls};

use crate::KIND;

#[derive(Clone)]
pub struct Settings {
    config: Config,
    tls: Option<Arc<tokio_postgres_rustls::MakeRustlsConnect>>,
    schema: Option<String>,
    /// For messages: host and database, never the user or password.
    pub label: String,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("label", &self.label)
            .field("tls", &self.tls.is_some())
            .field("schema", &self.schema)
            .finish()
    }
}

fn config_error(message: String) -> StorageError {
    StorageError::Config(format!("{KIND}: {message}"))
}

fn is_local(host: &Host) -> bool {
    match host {
        Host::Tcp(name) => scribe_net::is_loopback(name),
        #[cfg(unix)]
        Host::Unix(_) => true,
    }
}

/// A schema name scribed may put in SQL unquoted: lower-case letters, digits and `_`.
fn check_schema(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !name.as_bytes()[0].is_ascii_digit();
    if ok {
        Ok(())
    } else {
        Err(config_error(format!(
            "schema `{name}`: use lower-case letters, digits and `_`, not starting with a digit"
        )))
    }
}

impl Settings {
    /// From the backend options: `url` (required), `credentials` (secret reference holding the
    /// password), `schema` (tables in this schema instead of `public`; created if missing).
    pub fn from_options(options: &BackendOptions) -> Result<Self> {
        let url = required_option(options, KIND, "url")?;
        let mut config =
            Config::from_str(url).map_err(|e| config_error(format!("url can't be read: {e}")))?;
        if let Some(reference) = options.get("credentials") {
            let reference: scribe_secrets::SecretRef = reference
                .parse()
                .map_err(|e| config_error(format!("credentials: {e}")))?;
            let secret = scribe_secrets::read(&reference)
                .map_err(|e| config_error(format!("credentials: {e}")))?;
            config.password(secret.expose());
        }
        let schema = options.get("schema").cloned();
        if let Some(schema) = &schema {
            check_schema(schema)?;
        }
        let hosts = config.get_hosts().to_vec();
        if hosts.is_empty() {
            return Err(config_error("url names no host".into()));
        }
        let local = hosts.iter().all(is_local);
        let tls = if local && config.get_ssl_mode() != SslMode::Require {
            None
        } else {
            if !local && config.get_ssl_mode() != SslMode::Require {
                if url.contains("sslmode=") && config.get_ssl_mode() == SslMode::Disable {
                    return Err(config_error(
                        "sslmode=disable is only allowed for a server on this machine".into(),
                    ));
                }
                // `prefer` (the default) could fall back to plain text: always require TLS.
                config.ssl_mode(SslMode::Require);
            }
            let rustls = scribe_net::tls_config(None)
                .map_err(|e| config_error(format!("TLS settings: {e}")))?;
            Some(Arc::new(tokio_postgres_rustls::MakeRustlsConnect::new(
                (*rustls).clone(),
            )))
        };
        let label = format!(
            "{}/{}",
            hosts
                .iter()
                .map(|h| match h {
                    Host::Tcp(name) => name.clone(),
                    #[cfg(unix)]
                    Host::Unix(path) => path.display().to_string(),
                })
                .collect::<Vec<_>>()
                .join(","),
            config.get_dbname().unwrap_or("")
        );
        Ok(Self {
            config,
            tls,
            schema,
            label,
        })
    }

    pub fn uses_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Connect; the connection runs as a task on the current (worker) runtime.
    pub async fn connect(&self) -> Result<Client> {
        let failed = |e: tokio_postgres::Error| {
            StorageError::Backend(format!("{KIND} {}: cannot connect: {e}", self.label).into())
        };
        let client = match &self.tls {
            Some(tls) => {
                let (client, connection) =
                    self.config.connect((**tls).clone()).await.map_err(failed)?;
                tokio::spawn(connection);
                client
            }
            None => {
                let (client, connection) = self.config.connect(NoTls).await.map_err(failed)?;
                tokio::spawn(connection);
                client
            }
        };
        if let Some(schema) = &self.schema {
            client
                .batch_execute(&format!(
                    "CREATE SCHEMA IF NOT EXISTS {schema}; SET search_path TO {schema}"
                ))
                .await
                .map_err(|e| {
                    StorageError::Backend(format!("{KIND}: schema {schema}: {e}").into())
                })?;
        }
        Ok(client)
    }
}
