//! URL tracking module (specs 7.4.6): reads plaintext HTTP requests from the flow's first bytes,
//! stores the URL according to `[modules.url] query`, attaches it to the flow as the `url` note,
//! records `url.request` and counts requests per host in module state.
//!
//! The `hash` query mode arrives with the secrets crate (phase 3, step 5); until then it stores
//! no query, like `strip`.

pub mod parse;
pub mod privacy;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use scribe_core::{ModuleRecord, Security};
use scribe_module_api::{
    Access, Call, ConfigDoc, FlowContext, FlowHook, HookOutput, Manifest, Module, ModuleContext,
    ModuleError, ModuleHealth, RecordKind, Reload, SectionError,
};
use serde::Deserialize;
use serde_json::json;

pub const ID: &str = "url";
pub const REQUEST: &str = "url.request";

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
}

/// The settings the module runs with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Settings {
    pub query: Query,
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
    Ok(Settings { query })
}

struct Hook {
    ctx: Mutex<Option<ModuleContext>>,
    settings: Mutex<Settings>,
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
        let url = privacy::apply(&request, query, None);
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
                paused: AtomicBool::new(false),
                requests: Mutex::new(BTreeMap::new()),
            }),
            running: false,
        }
    }
}

impl UrlModule {
    pub fn settings(&self) -> Settings {
        *self.hook.settings.lock().unwrap()
    }
}

impl Module for UrlModule {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    fn configure(&mut self, doc: &ConfigDoc<'_>) -> Result<Reload, ModuleError> {
        *self.hook.settings.lock().unwrap() = settings(doc)?;
        Ok(Reload::Live)
    }

    fn start(&mut self, ctx: ModuleContext) -> Result<(), ModuleError> {
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
        table.insert("query".into(), self.settings().query.name().into());
        Some(table)
    }

    fn flow_hook(&self) -> Option<&dyn FlowHook> {
        Some(self.hook.as_ref())
    }
}
