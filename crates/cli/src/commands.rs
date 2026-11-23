//! One function per command: call the API, print the answer, pick the exit code.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use scribe_api::pb;
use tokio_stream::StreamExt;

use crate::client::{call_failure, connect, Failure, CALL_TIMEOUT};
use crate::{
    output, AlertsAction, AuditCommand, BaselineAction, Command, DaemonCommand, StatusArgs,
};

type Outcome = Result<ExitCode, Failure>;

fn json<T: serde::Serialize>(value: &T) -> Result<String, Failure> {
    serde_json::to_string_pretty(value).map_err(|e| Failure::new(format!("cannot print JSON: {e}")))
}

fn print(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes());
    let _ = out.flush();
}

pub async fn run(command: &Command, socket: &Path) -> Outcome {
    match command {
        Command::Status(args) => status(socket, args).await,
        Command::Daemon { command } => daemon(command, socket).await,
        Command::Audit {
            command: AuditCommand::Verify { json: as_json },
        } => {
            let report = connect(socket, CALL_TIMEOUT)
                .await?
                .verify_audit(pb::VerifyAuditRequest {})
                .await
                .map_err(call_failure)?
                .into_inner();
            print(&if *as_json {
                json(&report)? + "\n"
            } else {
                output::audit(&report)
            });
            Ok(if report.problems.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(crate::EXIT_FAILURE)
            })
        }
        Command::Version => unreachable!("handled before connecting"),
        other => data(other, socket).await,
    }
}

/// Commands about the data scribed collected.
async fn data(command: &Command, socket: &Path) -> Outcome {
    let mut client = connect(socket, CALL_TIMEOUT).await?;
    match command {
        Command::Hosts {
            filter,
            json: as_json,
        } => {
            let page = client
                .list_hosts(pb::ListHostsRequest {
                    name_contains: filter.clone().unwrap_or_default(),
                    ..Default::default()
                })
                .await
                .map_err(call_failure)?
                .into_inner();
            print(&if *as_json {
                json(&page)? + "\n"
            } else {
                output::hosts(&page)
            });
        }
        Command::Mode { mode } => {
            let reply = client
                .set_mode(pb::SetModeRequest {
                    mode: scribe_api::mode_to_api(*mode),
                })
                .await
                .map_err(call_failure)?
                .into_inner();
            print(&format!("mode: {} -> {}\n", reply.previous, reply.mode));
        }
        Command::Alerts {
            action: None,
            json: as_json,
        } => {
            let page = client
                .list_alerts(pb::ListAlertsRequest::default())
                .await
                .map_err(call_failure)?
                .into_inner();
            print(&if *as_json {
                json(&page)? + "\n"
            } else {
                output::alerts(&page)
            });
        }
        Command::Alerts {
            action: Some(AlertsAction::Ack { id }),
            ..
        } => {
            let reply = client
                .ack_alert(pb::AckAlertRequest { id: *id })
                .await
                .map_err(call_failure)?
                .into_inner();
            print(&if reply.changed {
                format!("alert {id} acknowledged\n")
            } else {
                format!("alert {id} was already acknowledged\n")
            });
        }
        Command::Baseline {
            action: None,
            json: as_json,
        } => {
            let baseline = client
                .get_baseline(pb::GetBaselineRequest::default())
                .await
                .map_err(call_failure)?
                .into_inner();
            print(&if *as_json {
                json(&baseline)? + "\n"
            } else {
                output::baseline(&baseline)
            });
        }
        Command::Baseline {
            action: Some(action),
            ..
        } => {
            let request = match action {
                BaselineAction::Add { hosts } => pb::EditBaselineRequest {
                    add: hosts.clone(),
                    remove: vec![],
                },
                BaselineAction::Rm { hosts } => pb::EditBaselineRequest {
                    add: vec![],
                    remove: hosts.clone(),
                },
            };
            let reply = client
                .edit_baseline(request)
                .await
                .map_err(call_failure)?
                .into_inner();
            print(&output::edit(&reply));
        }
        Command::Export { output: file } => {
            let mut items = client
                .export(pb::ExportRequest {})
                .await
                .map_err(call_failure)?
                .into_inner();
            let mut hosts = Vec::new();
            let mut baseline = Vec::new();
            while let Some(item) = items.next().await {
                match item.map_err(call_failure)?.item {
                    Some(pb::export_item::Item::Host(h)) => hosts.push(h),
                    Some(pb::export_item::Item::BaselineEntry(e)) => baseline.push(e),
                    None => {}
                }
            }
            let doc = serde_json::json!({ "hosts": hosts, "baseline": baseline });
            let text = json(&doc)? + "\n";
            match file {
                Some(path) => {
                    write_private(path, &text)?;
                    eprintln!(
                        "exported {} hosts and {} baseline entries to {}",
                        hosts.len(),
                        baseline.len(),
                        path.display()
                    );
                }
                None => print(&text),
            }
        }
        Command::Modules { json: as_json } => {
            let list = client
                .list_modules(pb::ListModulesRequest {})
                .await
                .map_err(call_failure)?
                .into_inner();
            print(&if *as_json {
                json(&list)? + "\n"
            } else {
                output::modules(&list)
            });
        }
        Command::Status(_) | Command::Daemon { .. } | Command::Audit { .. } | Command::Version => {
            unreachable!("dispatched by run")
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Writes the export as the caller, readable only by them (it lists every host contacted).
fn write_private(path: &Path, text: &str) -> Result<(), Failure> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .map_err(|e| Failure::new(format!("cannot write {}: {e}", path.display())))
}

async fn status(socket: &Path, args: &StatusArgs) -> Outcome {
    let Some(every) = args.watch else {
        let mut client = connect(socket, CALL_TIMEOUT).await?;
        let s = client
            .get_status(pb::StatusRequest {})
            .await
            .map_err(call_failure)?
            .into_inner();
        warn_on_mismatch(&s);
        print(&render_status(&s, args.json)?);
        return Ok(ExitCode::SUCCESS);
    };
    let tty = std::io::stdout().is_terminal();
    let stop = tokio::signal::ctrl_c();
    tokio::pin!(stop);
    loop {
        let text = match connect(socket, CALL_TIMEOUT).await {
            Ok(mut client) => match client.get_status(pb::StatusRequest {}).await {
                Ok(s) => render_status(&s.into_inner(), args.json)?,
                Err(e) => format!("scribe: {}\n", call_failure(e).message),
            },
            Err(f) => format!("scribe: {}\n", f.message),
        };
        if tty && !args.json {
            print("\x1b[2J\x1b[H");
        }
        print(&text);
        tokio::select! {
            _ = &mut stop => return Ok(ExitCode::SUCCESS),
            _ = tokio::time::sleep(every) => {}
        }
    }
}

fn render_status(s: &pb::Status, as_json: bool) -> Result<String, Failure> {
    if as_json {
        // One object per line, so `--watch --json` is a stream of JSON lines.
        serde_json::to_string(s)
            .map(|t| t + "\n")
            .map_err(|e| Failure::new(format!("cannot print JSON: {e}")))
    } else {
        Ok(output::status(s, std::io::stdout().is_terminal()))
    }
}

fn warn_on_mismatch(s: &pb::Status) {
    if s.api_version != scribe_api::API_VERSION {
        eprintln!(
            "scribe: warning: scribed speaks API version {}, this scribe {}; update one of them",
            s.api_version,
            scribe_api::API_VERSION
        );
    }
}

async fn daemon(command: &DaemonCommand, socket: &Path) -> Outcome {
    match command {
        DaemonCommand::Status(args) => status(socket, args).await,
        DaemonCommand::Health { json, timeout } => Ok(health(socket, *json, *timeout).await),
        DaemonCommand::Reset {
            counters,
            caches,
            config,
        } => {
            let reply = connect(socket, CALL_TIMEOUT)
                .await?
                .reset(pb::ResetRequest {
                    counters: *counters,
                    caches: *caches,
                    config: *config,
                })
                .await
                .map_err(call_failure)?
                .into_inner();
            print(&output::reset(&reply));
            Ok(ExitCode::SUCCESS)
        }
        DaemonCommand::Hibernate { for_ } => {
            let s = connect(socket, CALL_TIMEOUT)
                .await?
                .hibernate(pb::HibernateRequest {
                    for_s: for_.map(|d| d.as_secs()),
                })
                .await
                .map_err(call_failure)?
                .into_inner();
            print(&output::run_state(&s));
            Ok(ExitCode::SUCCESS)
        }
        DaemonCommand::Wakeup => {
            let s = connect(socket, CALL_TIMEOUT)
                .await?
                .wakeup(pb::WakeupRequest {})
                .await
                .map_err(call_failure)?
                .into_inner();
            print(&output::run_state(&s));
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Exit 0 for healthy or degraded, 1 for unhealthy or unreachable; the answer goes to stdout
/// either way, for scripts and service managers.
async fn health(socket: &Path, as_json: bool, timeout: Duration) -> ExitCode {
    let answer = async {
        let mut client = connect(socket, timeout).await?;
        client
            .health(pb::HealthRequest {})
            .await
            .map(|r| r.into_inner())
            .map_err(call_failure)
    };
    let (level, reasons) = match tokio::time::timeout(timeout, answer).await {
        Ok(Ok(reply)) => (output::level_name(reply.level), reply.reasons),
        Ok(Err(failure)) => ("unhealthy", vec![failure.message]),
        Err(_) => (
            "unhealthy",
            vec![format!(
                "no answer within {}",
                scribe_core::time::human_duration(timeout)
            )],
        ),
    };
    if as_json {
        print(&format!("{}\n", output::health_json(level, &reasons)));
    } else {
        print(&format!(
            "{}\n",
            output::health(&pb::HealthReply {
                level: match level {
                    "healthy" => pb::health_reply::Level::Healthy,
                    "degraded" => pb::health_reply::Level::Degraded,
                    _ => pb::health_reply::Level::Unhealthy,
                } as i32,
                reasons,
            })
        ));
    }
    if level == "unhealthy" {
        ExitCode::from(crate::EXIT_FAILURE)
    } else {
        ExitCode::SUCCESS
    }
}
