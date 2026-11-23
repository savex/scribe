//! URL tracking module (specs 7.4.6): reads plaintext HTTP requests from the flow's first bytes,
//! stores the URL according to `[modules.url] query`, attaches it to the flow as the `url` note,
//! records `url.request` and counts requests per host in module state.
//!
//! `query = "hash"` replaces the query with the first 6 hex digits of its HMAC-SHA256 under a
//! per-install key: `hash_key` (a secret reference) or, by default, `file:<data_dir>/url_hash.key`,
//! created on first start.

#[cfg(any(feature = "server", feature = "client"))]
pub mod api;
pub mod parse;
pub mod privacy;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ring::hmac;
use scribe_core::{ModuleRecord, Security};
use scribe_module_api::{
    Access, Call, ConfigDoc, FlowContext, FlowHook, HookOutput, Manifest, Module, ModuleContext,
    ModuleError, ModuleHealth, RecordKind, Reload, SectionError,
};
use scribe_secrets::SecretRef;
use serde::Deserialize;
use serde_json::json;

pub const ID: &str = "url";
pub const REQUEST: &str = "url.request";
/// The default key file in `data_dir`.
pub const KEY_FILE: &str = "url_hash.key";

/// How much of a URL's query is stored (specs 12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Query {
    Full,
    #[default]
    RedactValues,
    Strip,
    PathOnly,
    Hash,
}

impl Query {
    pub fn name(self) -> &'static str {
        match self {
            Query::Full => "full",
            Query::RedactValues => "redact_values",
            Query::Strip => "strip",
            Query::PathOnly => "path_only",
            Query::Hash => "hash",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Section {
    query: Option<Query>,
    hash_key: Option<String>,
}

/// The settings the module runs with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    pub query: Query,
    /// Where the `hash` key lives; `None` = `file:<data_dir>/url_hash.key`.
    pub hash_key: Option<SecretRef>,
}

/// Read `[modules.url]`, honouring the deprecated `privacy.url_query` (one minor version).
pub fn settings(doc: &ConfigDoc<'_>) -> Result<Settings, SectionError> {
    let section: Section = doc.section(ID)?;
    let old: Option<Query> = doc.get(&["privacy", "url_query"])?;
    let query = match (section.query, old) {
        (Some(new), Some(old)) if new != old => {
            return Err(SectionError::new(
                format!(
                    "`modules.url.query` ({}) and the deprecated `privacy.url_query` ({}) disagree; keep only `modules.url.query`",
                    new.name(),
                    old.name()
                ),
                doc.span_of(&["privacy", "url_query"]),
            ))
        }
        (Some(q), _) | (None, Some(q)) => q,
        (None, None) => Query::default(),
    };
    let hash_key = match &section.hash_key {
        None => None,
        Some(text) => Some(text.parse().map_err(|e: scribe_secrets::SecretError| {
            SectionError::new(e.to_string(), doc.span_of(&["modules", ID, "hash_key"]))
        })?),
    };
    Ok(Settings { query, hash_key })
}

struct Hook {
    ctx: Mutex<Option<ModuleContext>>,
    settings: Mutex<Settings>,
    key: Mutex<Option<hmac::Key>>,
    paused: AtomicBool,
    requests: Mutex<BTreeMap<String, u64>>,
}

impl FlowHook for Hook {
    fn on_flow(&self, flow: &FlowContext<'_>) -> HookOutput {
        if self.paused.load(Ordering::Relaxed) || flow.event.security != Security::Plaintext {
            return HookOutput::none();
        }
        let Some(request) = flow.head.and_then(parse::parse_request) else {
            return HookOutput::none();
        };
        let query = self.settings.lock().unwrap().query;
        let key = self.key.lock().unwrap().clone();
        let hash = key.map(|key| move |q: &str| short_hash(&key, q));
        let url = privacy::apply(
            &request,
            query,
            hash.as_ref().map(|h| h as &dyn Fn(&str) -> String),
        );
        let Some(ctx) = self.ctx.lock().unwrap().clone() else {
            return HookOutput::none();
        };
        let host = flow.event.hostname.clone();
        ctx.emitter.record(ModuleRecord {
            ts: flow.event.ts,
            module: ID.into(),
            kind: REQUEST.into(),
            schema: 1,
            host: host.clone(),
            payload: json!({ "method": request.method, "url": url }),
        });
        if let Some(host) = host {
            let mut requests = self.requests.lock().unwrap();
            let n = requests.entry(host.clone()).or_default();
            *n += 1;
            ctx.emitter
                .put_state(&format!("requests.{host}"), json!(*n));
        }
        HookOutput::note(json!(url))
    }
}

pub struct UrlModule {
    manifest: Manifest,
    hook: Arc<Hook>,
    running: bool,
}

impl Default for UrlModule {
    fn default() -> Self {
        let mut manifest = Manifest::new(ID, 1, "URL tracking for plaintext HTTP");
        manifest.records.push(RecordKind {
            name: REQUEST,
            schema: 1,
        });
        manifest.calls.push(Call {
            name: "list",
            access: Access::Read,
        });
        manifest.needs.payload = true;
        Self {
            manifest,
            hook: Arc::new(Hook {
                ctx: Mutex::new(None),
                settings: Mutex::new(Settings::default()),
                key: Mutex::new(None),
                paused: AtomicBool::new(false),
                requests: Mutex::new(BTreeMap::new()),
            }),
            running: false,
        }
    }
}

impl UrlModule {
    pub fn settings(&self) -> Settings {
        self.hook.settings.lock().unwrap().clone()
    }

    /// Load (or create) the `hash` key when the mode needs it; drop it otherwise.
    fn load_key(&self, data_dir: Option<&Path>) -> Result<(), ModuleError> {
        let settings = self.settings();
        let key = if settings.query == Query::Hash {
            let r = match (settings.hash_key, data_dir) {
                (Some(r), _) => r,
                (None, Some(dir)) => SecretRef::File(dir.join(KEY_FILE)),
                (None, None) => {
                    return Err(ModuleError::Start(
                        "query = \"hash\" needs `modules.url.hash_key` or a data_dir".into(),
                    ))
                }
            };
            let secret = scribe_secrets::read_or_create(&r, 32)
                .map_err(|e| ModuleError::Start(format!("hash key: {e}")))?;
            Some(hmac::Key::new(hmac::HMAC_SHA256, secret.expose()))
        } else {
            None
        };
        *self.hook.key.lock().unwrap() = key;
        Ok(())
    }

    fn data_dir(&self) -> Option<std::path::PathBuf> {
        self.hook
            .ctx
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|c| c.data_dir.clone())
    }
}

/// The first 6 hex digits of HMAC-SHA256(`key`, `query`).
pub fn short_hash(key: &hmac::Key, query: &str) -> String {
    let tag = hmac::sign(key, query.as_bytes());
    tag.as_ref()[..3]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl Module for UrlModule {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    fn configure(&mut self, doc: &ConfigDoc<'_>) -> Result<Reload, ModuleError> {
        *self.hook.settings.lock().unwrap() = settings(doc)?;
        if self.running {
            self.load_key(self.data_dir().as_deref())?;
        }
        Ok(Reload::Live)
    }

    fn start(&mut self, ctx: ModuleContext) -> Result<(), ModuleError> {
        self.load_key(ctx.data_dir.as_deref())?;
        let mut requests = self.hook.requests.lock().unwrap();
        requests.clear();
        for (key, value) in &ctx.state {
            if let (Some(host), Some(n)) = (key.strip_prefix("requests."), value.as_u64()) {
                requests.insert(host.to_owned(), n);
            }
        }
        drop(requests);
        *self.hook.ctx.lock().unwrap() = Some(ctx);
        self.hook.paused.store(false, Ordering::Relaxed);
        self.running = true;
        Ok(())
    }

    fn pause(&mut self) {
        self.hook.paused.store(true, Ordering::Relaxed);
    }

    fn resume(&mut self) {
        self.hook.paused.store(false, Ordering::Relaxed);
    }

    fn stop(&mut self) {
        *self.hook.ctx.lock().unwrap() = None;
        self.running = false;
    }

    fn health(&self) -> ModuleHealth {
        ModuleHealth::Healthy
    }

    fn effective_config(&self) -> Option<toml::Table> {
        let mut table = toml::Table::new();
        let settings = self.settings();
        table.insert("query".into(), settings.query.name().into());
        if let Some(r) = settings.hash_key {
            table.insert("hash_key".into(), r.to_string().into());
        }
        Some(table)
    }

    fn flow_hook(&self) -> Option<&dyn FlowHook> {
        Some(self.hook.as_ref())
    }
}
