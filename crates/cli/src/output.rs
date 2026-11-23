//! How `scribe` prints API answers for people. Every function returns the text, so tests can read
//! it; `--json` prints the messages themselves instead.

use std::fmt::Write as _;
use std::time::Duration;

use scribe_api::pb;
use scribe_core::time::{human_duration, rfc3339_ms};

/// Columns padded to their widest cell, two spaces apart; the last column isn't padded.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(cell.chars().count());
            }
        }
    }
    let mut out = String::new();
    let mut line = |cells: Vec<&str>| {
        let last = cells.len().saturating_sub(1);
        let mut text = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i == last {
                text.push_str(cell);
            } else {
                let _ = write!(text, "{cell:<w$}  ", w = widths[i]);
            }
        }
        out.push_str(text.trim_end());
        out.push('\n');
    };
    line(headers.to_vec());
    for row in rows {
        line(row.iter().map(String::as_str).collect());
    }
    out
}

/// `512 B`, `1.5 KiB`, `7.0 MiB`.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn or_dash(s: Option<&str>) -> String {
    match s {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => "-".to_owned(),
    }
}

/// `scribe daemon status`: critical metrics first (marked `!`, red on a terminal).
pub fn status(s: &pb::Status, color: bool) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "scribed {} (API {}): {}, up {}",
        s.daemon_version,
        s.api_version,
        s.run_state,
        human_duration(Duration::from_secs(s.uptime_s))
    );
    for c in &s.critical {
        if color {
            let _ = writeln!(out, "\x1b[1;31m! {}: {}\x1b[0m", c.kind, c.detail);
        } else {
            let _ = writeln!(out, "! {}: {}", c.kind, c.detail);
        }
    }
    let mut row = |name: &str, value: String| {
        let _ = writeln!(out, "{name:<10} {value}");
    };
    row("mode", format!("{}, profile {}", s.mode, s.profile));
    if let Some(until) = s.learn_until_ms {
        row("learn", format!("ends {}", rfc3339_ms(until)));
    }
    if let Some(since) = s.hibernating_since_ms {
        let until = s
            .hibernating_until_ms
            .map_or_else(|| "someone wakes it up".to_owned(), rfc3339_ms);
        row(
            "hibernate",
            format!(
                "since {} until {until}, by {}",
                rfc3339_ms(since),
                or_dash(Some(&s.hibernated_by))
            ),
        );
    }
    if let Some(sensor) = &s.sensor {
        row(
            "sensor",
            format!(
                "{}, {}, {}",
                sensor.name,
                if sensor.process_info {
                    "process info"
                } else {
                    "no process info"
                },
                sensor.health
            ),
        );
    }
    row(
        "config",
        format!(
            "{}, loaded {}",
            s.config_path,
            rfc3339_ms(s.config_loaded_ms)
        ),
    );
    if let Some(c) = &s.counters {
        row(
            "counters",
            format!(
                "since {}: {} ({:.1}/s), {:.1} events/s, {}, {}, {} dropped while hibernating, {}",
                rfc3339_ms(s.counters_since_ms),
                plural(c.flows, "flow", "flows"),
                c.flows_per_s,
                c.events_per_s,
                plural(c.alerts, "alert", "alerts"),
                plural(c.new_hosts, "new host", "new hosts"),
                c.dropped_hibernating,
                plural(c.drops, "drop", "drops"),
            ),
        );
    }
    row(
        "pipeline",
        format!(
            "{} QUIC flows held, {} DNS names cached",
            s.held_quic, s.dns_entries
        ),
    );
    if let Some(storage) = &s.storage {
        let target = |t: &pb::StorageTarget, label: String| {
            let detail = if t.detail.is_empty() {
                String::new()
            } else {
                format!(" ({})", t.detail)
            };
            format!("{label}: {} {}{detail}", t.kind, t.health)
        };
        let mut lines = Vec::new();
        if let Some(state) = &storage.state {
            lines.push(target(state, "state".into()));
        }
        for sink in &storage.sinks {
            lines.push(target(sink, format!("sink {}", sink.name)));
        }
        for (i, line) in lines.into_iter().enumerate() {
            row(if i == 0 { "storage" } else { "" }, line);
        }
    }
    for (i, m) in s.modules.iter().enumerate() {
        let state = if m.enabled {
            format!("{}, {}", m.state, m.health)
        } else {
            "not enabled".into()
        };
        row(
            if i == 0 { "modules" } else { "" },
            format!("{} {}: {state}", m.id, m.version),
        );
    }
    out
}

pub fn level_name(level: i32) -> &'static str {
    use pb::health_reply::Level;
    match Level::try_from(level) {
        Ok(Level::Healthy) => "healthy",
        Ok(Level::Degraded) => "degraded",
        _ => "unhealthy",
    }
}

/// `healthy`, `degraded: <reasons>` or `unhealthy: <reasons>`.
pub fn health(h: &pb::HealthReply) -> String {
    let level = level_name(h.level);
    if h.reasons.is_empty() {
        level.to_owned()
    } else {
        format!("{level}: {}", h.reasons.join("; "))
    }
}

pub fn health_json(level: &str, reasons: &[String]) -> serde_json::Value {
    serde_json::json!({ "level": level, "reasons": reasons })
}

pub fn hosts(page: &pb::HostPage) -> String {
    let rows: Vec<Vec<String>> = page
        .items
        .iter()
        .map(|h| {
            let mut seen = Vec::new();
            if h.tls_seen {
                seen.push("tls");
            }
            if h.plaintext_seen {
                seen.push("plain");
            }
            let mut flags = Vec::new();
            if h.on_list {
                flags.push("listed");
            }
            if h.unresolved {
                flags.push("unresolved");
            }
            if h.ech {
                flags.push("ech");
            }
            vec![
                h.name.clone(),
                h.conn_count.to_string(),
                h.req_count.to_string(),
                bytes(h.bytes_out),
                or_dash(Some(&seen.join(","))),
                rfc3339_ms(h.last_seen_ms),
                or_dash(Some(&flags.join(","))),
                or_dash(Some(&h.processes.join(", "))),
            ]
        })
        .collect();
    let mut out = table(
        &[
            "HOST",
            "CONNS",
            "REQUESTS",
            "SENT",
            "SEEN",
            "LAST SEEN",
            "FLAGS",
            "PROCESSES",
        ],
        &rows,
    );
    let total = page.total.unwrap_or(page.items.len() as u64);
    let _ = writeln!(out, "{}", plural(total, "host", "hosts"));
    out
}

/// Alerts with their notes (e.g. the URL) on the lines below.
pub fn alerts(page: &pb::AlertPage) -> String {
    if page.items.is_empty() {
        return "no alerts\n".into();
    }
    let rows: Vec<Vec<String>> = page
        .items
        .iter()
        .map(|a| {
            vec![
                a.id.to_string(),
                rfc3339_ms(a.ts_ms),
                a.score.to_string(),
                a.reason.clone(),
                a.dst.clone(),
                or_dash(a.host.as_deref()),
                or_dash(a.process_path.as_deref()),
                if a.acknowledged { "yes" } else { "no" }.into(),
            ]
        })
        .collect();
    let text = table(
        &[
            "ID",
            "TIME",
            "SCORE",
            "REASON",
            "DESTINATION",
            "HOST",
            "PROCESS",
            "ACKED",
        ],
        &rows,
    );
    let mut lines = text.lines();
    let mut out = String::new();
    if let Some(header) = lines.next() {
        out.push_str(header);
        out.push('\n');
    }
    for (line, alert) in lines.zip(&page.items) {
        out.push_str(line);
        out.push('\n');
        let mut notes: Vec<_> = alert.notes.iter().collect();
        notes.sort();
        for (k, v) in notes {
            let _ = writeln!(out, "    {k}: {v}");
        }
    }
    out
}

pub fn baseline(b: &pb::Baseline) -> String {
    let rows: Vec<Vec<String>> = b
        .entries
        .iter()
        .map(|e| vec![e.host.clone(), e.source.clone(), rfc3339_ms(e.added_at_ms)])
        .collect();
    let mut out = format!(
        "profile {}: {}\n",
        b.profile,
        plural(b.entries.len() as u64, "host", "hosts")
    );
    if !rows.is_empty() {
        out.push_str(&table(&["HOST", "SOURCE", "ADDED"], &rows));
    }
    out
}

pub fn modules(list: &pb::ModuleList) -> String {
    if list.items.is_empty() {
        return "no modules are built into this scribed\n".into();
    }
    let rows: Vec<Vec<String>> = list
        .items
        .iter()
        .map(|m| {
            vec![
                m.id.clone(),
                m.version.to_string(),
                if m.enabled { "yes" } else { "no" }.into(),
                m.state.clone(),
                m.health.clone(),
                m.over_budget.to_string(),
                m.drops.to_string(),
            ]
        })
        .collect();
    table(
        &[
            "MODULE",
            "VERSION",
            "ENABLED",
            "STATE",
            "HEALTH",
            "OVER BUDGET",
            "DROPS",
        ],
        &rows,
    )
}

pub fn edit(reply: &pb::EditBaselineReply) -> String {
    let mut out = String::new();
    for (label, hosts) in [
        ("added", &reply.added),
        ("removed", &reply.removed),
        ("unchanged", &reply.unchanged),
    ] {
        if !hosts.is_empty() {
            let _ = writeln!(out, "{label}: {}", hosts.join(", "));
        }
    }
    out
}

pub fn reset(reply: &pb::ResetReply) -> String {
    let mut out = format!("reset: {}\n", reply.done.join(", "));
    if reply.done.iter().any(|d| d == "config") {
        let applied = if reply.applied.is_empty() {
            "nothing changed".to_owned()
        } else {
            reply.applied.join(", ")
        };
        let _ = writeln!(out, "config applied: {applied}");
    }
    if !reply.needs_restart.is_empty() {
        let _ = writeln!(out, "needs a restart: {}", reply.needs_restart.join(", "));
    }
    out
}

/// After `hibernate` or `wakeup`: the run state and, while hibernating, since and until when.
pub fn run_state(s: &pb::Status) -> String {
    match s.hibernating_since_ms {
        Some(since) => format!(
            "hibernating since {} until {}\n",
            rfc3339_ms(since),
            s.hibernating_until_ms
                .map_or_else(|| "someone wakes it up".to_owned(), rfc3339_ms)
        ),
        None => format!("{}\n", s.run_state),
    }
}

/// `scribe audit verify`: intact, or what is wrong with the chain.
pub fn audit(r: &pb::AuditReport) -> String {
    let mut out = String::new();
    if r.problems.is_empty() {
        let _ = writeln!(
            out,
            "audit chain intact: {}, sequence {} to {} (last sealed {})",
            plural(r.records, "record", "records"),
            r.first_seq,
            r.last_seq,
            r.sealed_seq
        );
    } else {
        let _ = writeln!(
            out,
            "audit chain broken: {} ({} stored, sequence {} to {}, last sealed {})",
            plural(r.problems.len() as u64, "problem", "problems"),
            plural(r.records, "record", "records"),
            r.first_seq,
            r.last_seq,
            r.sealed_seq
        );
        for p in &r.problems {
            let line = match p.kind.as_str() {
                "gap" => format!("gap: records {} to {} are missing", p.seq + 1, p.next - 1),
                "mismatch" => format!(
                    "mismatch: record {} doesn't carry the HMAC of record {} (one of them was changed)",
                    p.seq,
                    p.seq.saturating_sub(1)
                ),
                "unlinked" => "unlinked: a record without a chain link".to_owned(),
                "missing_tail" => format!(
                    "missing tail: records {} to {} were sealed but are not stored",
                    p.seq + 1,
                    p.next
                ),
                other => format!("{other}: {} {}", p.seq, p.next),
            };
            let _ = writeln!(out, "  {line}");
        }
    }
    if r.first_seq > 1 {
        let _ = writeln!(
            out,
            "records before {} are not stored (retention removes old records)",
            r.first_seq
        );
    }
    out
}

/// `scribe hosts --hourly <host>`: one row per hour with traffic, then the totals.
pub fn host_hours(h: &pb::HostHours) -> String {
    if h.items.is_empty() {
        return format!("{}: no traffic counted in this period\n", h.host);
    }
    let rows: Vec<Vec<String>> = h
        .items
        .iter()
        .map(|b| {
            vec![
                rfc3339_ms(b.hour_ms),
                b.conn_count.to_string(),
                b.req_count.to_string(),
                bytes(b.bytes_out),
            ]
        })
        .collect();
    let mut out = format!("{}\n", h.host);
    out.push_str(&table(&["HOUR (UTC)", "CONNS", "REQUESTS", "SENT"], &rows));
    let (c, r, b) = h.items.iter().fold((0, 0, 0), |(c, r, b), x| {
        (c + x.conn_count, r + x.req_count, b + x.bytes_out)
    });
    let _ = writeln!(
        out,
        "{} over {}: {}, {} requests, {} sent",
        h.host,
        plural(h.items.len() as u64, "hour", "hours"),
        plural(c, "connection", "connections"),
        r,
        bytes(b)
    );
    out
}
