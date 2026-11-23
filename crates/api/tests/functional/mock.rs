//! A small `Scribe` service for transport tests: `GetStatus` reports the caller, `SetMode` and
//! `EditBaseline` are control calls, the rest are unimplemented.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use scribe_api::access::{Access, AccessPolicy};
use scribe_api::pb::scribe_client::ScribeClient;
use scribe_api::pb::scribe_server::Scribe;
use scribe_api::pb::*;
use scribe_api::unix::{self, ServerCheck};
use tokio::sync::oneshot;
use tokio_stream::Stream;
use tonic::transport::Channel;
use tonic::{Request, Response, Status as RpcStatus};

type Reply<T> = Result<Response<T>, RpcStatus>;
type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, RpcStatus>> + Send>>;

pub struct Mock {
    pub policy: AccessPolicy,
}

fn unimplemented<T>() -> Reply<T> {
    Err(RpcStatus::unimplemented("not in the mock"))
}

#[tonic::async_trait]
impl Scribe for Mock {
    async fn get_status(&self, request: Request<StatusRequest>) -> Reply<Status> {
        let caller = self.policy.check(&request, Access::Read)?;
        Ok(Response::new(Status {
            api_version: scribe_api::API_VERSION,
            run_state: "running".into(),
            hibernated_by: caller.describe(),
            profile: caller.user.clone(),
            ..Default::default()
        }))
    }

    async fn health(&self, _: Request<HealthRequest>) -> Reply<HealthReply> {
        unimplemented()
    }

    async fn list_hosts(&self, _: Request<ListHostsRequest>) -> Reply<HostPage> {
        unimplemented()
    }

    async fn list_alerts(&self, _: Request<ListAlertsRequest>) -> Reply<AlertPage> {
        unimplemented()
    }

    type WatchAlertsStream = BoxStream<Alert>;

    async fn watch_alerts(&self, _: Request<WatchAlertsRequest>) -> Reply<Self::WatchAlertsStream> {
        unimplemented()
    }

    async fn get_baseline(&self, _: Request<GetBaselineRequest>) -> Reply<Baseline> {
        unimplemented()
    }

    type ExportStream = BoxStream<ExportItem>;

    async fn export(&self, _: Request<ExportRequest>) -> Reply<Self::ExportStream> {
        unimplemented()
    }

    async fn list_modules(&self, _: Request<ListModulesRequest>) -> Reply<ModuleList> {
        unimplemented()
    }

    async fn get_module(&self, _: Request<GetModuleRequest>) -> Reply<Module> {
        unimplemented()
    }

    async fn ack_alert(&self, _: Request<AckAlertRequest>) -> Reply<AckAlertReply> {
        unimplemented()
    }

    async fn set_mode(&self, request: Request<SetModeRequest>) -> Reply<SetModeReply> {
        self.policy.check(&request, Access::Control)?;
        let mode = scribe_api::mode_from_api(&request.get_ref().mode)
            .map_err(RpcStatus::invalid_argument)?;
        Ok(Response::new(SetModeReply {
            previous: "learn".into(),
            mode: scribe_api::mode_to_api(mode),
        }))
    }

    async fn edit_baseline(
        &self,
        request: Request<EditBaselineRequest>,
    ) -> Reply<EditBaselineReply> {
        self.policy.check(&request, Access::Control)?;
        Ok(Response::new(EditBaselineReply {
            added: request.into_inner().add,
            ..Default::default()
        }))
    }

    async fn reset(&self, _: Request<ResetRequest>) -> Reply<ResetReply> {
        unimplemented()
    }

    async fn hibernate(&self, _: Request<HibernateRequest>) -> Reply<Status> {
        unimplemented()
    }

    async fn wakeup(&self, _: Request<WakeupRequest>) -> Reply<Status> {
        unimplemented()
    }
}

/// A mock server on a socket in its own temp dir; stops when dropped.
pub struct Running {
    pub dir: tempfile::TempDir,
    pub socket: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Running {
    pub async fn start(policy: AccessPolicy) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let listener = unix::bind(&socket).unwrap();
        let routes = tonic::service::Routes::new(unix::service(Mock { policy }));
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            unix::serve(listener, routes, async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
        });
        Self {
            dir,
            socket,
            stop: Some(stop),
            task: Some(task),
        }
    }

    pub async fn client(&self) -> ScribeClient<Channel> {
        connect(&self.socket).await
    }

    pub async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.task.take().unwrap().await.unwrap();
    }
}

pub async fn connect(socket: &Path) -> ScribeClient<Channel> {
    unix::connect(socket, ServerCheck::RootOrSelf, Duration::from_secs(5))
        .await
        .unwrap()
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
