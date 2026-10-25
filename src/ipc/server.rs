// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IPC server side of ADR-029: one listener per channel, a thread per
//! connection, and one worker for administrative operations.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde::de::DeserializeOwned;

use super::frame::{MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, read_frame, write_frame};
use super::protocol::{
    ActionRefusal, AdminAction, AdminRequest, ConfirmRequest, Empty, ErrorKind, OperationId,
    OperationOutcome, OperationState, OperationView, Plan, PlanView, Response, SourceStatus,
    Started, StatusReport, StatusRequest, decode, encode, plan_digest,
};

/// How long a shown plan can still be confirmed.
pub const PLAN_LIFETIME: Duration = Duration::from_secs(600);
/// Finished operations kept for status queries.
const FINISHED_KEPT: usize = 256;

/// Who may connect to a channel; checked from `SO_PEERCRED` before the
/// first frame is read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRule {
    AnyUser,
    OnlyUid(u32),
}

impl PeerRule {
    pub(crate) const fn admits(self, uid: u32) -> bool {
        match self {
            Self::AnyUser => true,
            Self::OnlyUid(allowed) => uid == allowed,
        }
    }
}

/// Deadlines and connection limits of one channel (ADR-029 point 9).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// The first frame must arrive this soon after the accept.
    pub first_frame: Duration,
    /// An idle connection is closed after this long.
    pub idle: Duration,
    pub per_uid: usize,
    pub total: usize,
}

impl Limits {
    pub const STATUS: Self = Self {
        first_frame: Duration::from_secs(5),
        idle: Duration::from_secs(30),
        per_uid: 8,
        total: 64,
    };
    pub const ADMIN: Self = Self {
        first_frame: Duration::from_secs(5),
        idle: Duration::from_secs(30),
        per_uid: 4,
        total: 4,
    };
}

/// What the server asks of the service it fronts.
pub trait Service: Send + Sync + 'static {
    /// The plan shown to the administrator; the same state must give the
    /// same plan, so that its digest can be checked at confirmation.
    fn plan(&self, action: &AdminAction) -> Result<Plan, ActionRefusal>;
    /// Runs a confirmed action on the worker thread with the plan that was
    /// confirmed.
    fn run(&self, action: &AdminAction, plan: &Plan) -> Result<OperationOutcome, OperationOutcome>;
    /// The sources for a status response. Answered on the connection's own
    /// thread, so it must not wait for a running operation: serve a
    /// snapshot that operations refresh, not a query that takes their lock.
    fn sources(&self) -> Vec<SourceStatus>;
}

struct Operation {
    owner: u32,
    action: AdminAction,
    plan: Plan,
    state: OperationState,
    outcome: Option<OperationOutcome>,
    finished_at: Option<Instant>,
}

struct PendingPlan {
    owner: u32,
    action: AdminAction,
    shown_at: Instant,
}

struct Shared<S> {
    service: S,
    operations: Mutex<HashMap<OperationId, Operation>>,
    plans: Mutex<HashMap<String, PendingPlan>>,
    jobs: Mutex<Sender<OperationId>>,
}

/// Connection counters of one channel.
#[derive(Default)]
pub(crate) struct Counters {
    per_uid: HashMap<u32, usize>,
    total: usize,
}

/// Holds one connection slot; released on drop.
pub(crate) struct Slot {
    counters: Arc<Mutex<Counters>>,
    uid: u32,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut counters = self.counters.lock().unwrap_or_else(PoisonError::into_inner);
        counters.total = counters.total.saturating_sub(1);
        if let Some(count) = counters.per_uid.get_mut(&self.uid) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counters.per_uid.remove(&self.uid);
            }
        }
    }
}

pub(crate) fn take_slot(counters: &Arc<Mutex<Counters>>, uid: u32, limits: Limits) -> Option<Slot> {
    let mut guard = counters.lock().unwrap_or_else(PoisonError::into_inner);
    let mine = guard.per_uid.get(&uid).copied().unwrap_or(0);
    if guard.total >= limits.total || mine >= limits.per_uid {
        return None;
    }
    guard.total += 1;
    guard.per_uid.insert(uid, mine + 1);
    Some(Slot {
        counters: Arc::clone(counters),
        uid,
    })
}

/// What a request asks for, independent of its channel. Only the channel's
/// own request type can produce a value here, so the status channel can
/// never produce a plan or a confirmation.
enum Ask {
    Ping,
    Status,
    Operation(String),
    Plan(AdminAction),
    Confirm(ConfirmRequest),
}

trait ChannelRequest: DeserializeOwned {
    fn ask(self) -> Ask;
}

impl ChannelRequest for StatusRequest {
    fn ask(self) -> Ask {
        match self {
            Self::Ping(_) => Ask::Ping,
            Self::Status(_) => Ask::Status,
            Self::Operation(query) => Ask::Operation(query.operation_id),
        }
    }
}

impl ChannelRequest for AdminRequest {
    fn ask(self) -> Ask {
        match self {
            Self::Ping(_) => Ask::Ping,
            Self::Status(_) => Ask::Status,
            Self::Operation(query) => Ask::Operation(query.operation_id),
            Self::Plan(plan) => Ask::Plan(plan.action),
            Self::Confirm(confirm) => Ask::Confirm(confirm),
        }
    }
}

/// The IPC server of one service.
pub struct Server<S: Service> {
    shared: Arc<Shared<S>>,
}

impl<S: Service> Server<S> {
    /// Starts the operation worker.
    pub fn new(service: S) -> io::Result<Self> {
        let (sender, receiver) = mpsc::channel::<OperationId>();
        let shared = Arc::new(Shared {
            service,
            operations: Mutex::new(HashMap::new()),
            plans: Mutex::new(HashMap::new()),
            jobs: Mutex::new(sender),
        });
        let worker = Arc::clone(&shared);
        thread::Builder::new()
            .name("ipc-operations".to_owned())
            .spawn(move || {
                for id in receiver {
                    worker.run_operation(id);
                }
            })?;
        Ok(Self { shared })
    }

    /// Serves `status.sock`: read-only requests only.
    pub fn serve_status(
        &self,
        listener: UnixListener,
        rule: PeerRule,
        limits: Limits,
    ) -> io::Result<JoinHandle<()>> {
        serve::<S, StatusRequest>(
            Arc::clone(&self.shared),
            listener,
            rule,
            limits,
            "ipc-status",
        )
    }

    /// Serves `admin.sock`: read-only and administrative requests.
    pub fn serve_admin(
        &self,
        listener: UnixListener,
        rule: PeerRule,
        limits: Limits,
    ) -> io::Result<JoinHandle<()>> {
        serve::<S, AdminRequest>(
            Arc::clone(&self.shared),
            listener,
            rule,
            limits,
            "ipc-admin",
        )
    }
}

fn serve<S: Service, R: ChannelRequest>(
    shared: Arc<Shared<S>>,
    listener: UnixListener,
    rule: PeerRule,
    limits: Limits,
    name: &str,
) -> io::Result<JoinHandle<()>> {
    let counters = Arc::new(Mutex::new(Counters::default()));
    thread::Builder::new().name(name.to_owned()).spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else {
                continue;
            };
            // The peer is checked before anything is read; a refusal is a
            // close without a response.
            let Ok(credentials) = getsockopt(&stream, PeerCredentials) else {
                continue;
            };
            let uid = credentials.uid();
            if !rule.admits(uid) {
                continue;
            }
            let Some(slot) = take_slot(&counters, uid, limits) else {
                continue;
            };
            let shared = Arc::clone(&shared);
            let _ = thread::Builder::new()
                .name("ipc-connection".to_owned())
                .spawn(move || {
                    connection::<S, R>(&shared, stream, uid, limits);
                    drop(slot);
                });
        }
    })
}

fn connection<S: Service, R: ChannelRequest>(
    shared: &Shared<S>,
    mut stream: UnixStream,
    uid: u32,
    limits: Limits,
) {
    if stream.set_read_timeout(Some(limits.first_frame)).is_err()
        || stream.set_write_timeout(Some(limits.idle)).is_err()
    {
        return;
    }
    loop {
        // A clean close, a deadline, or a bad frame (empty, over the limit,
        // truncated, not UTF-8): close without a response (ADR-029 point 4).
        let Ok(text) = read_frame(&mut stream, MAX_REQUEST_BYTES) else {
            break;
        };
        if stream.set_read_timeout(Some(limits.idle)).is_err() {
            break;
        }
        let (response, close) = match decode::<R>(&text) {
            Ok(request) => (shared.answer(request.ask(), uid), false),
            Err(error) => (
                Response::error(error.kind(), "request refused; nothing was applied"),
                true,
            ),
        };
        if write_frame(&mut stream, &encode(&response), MAX_RESPONSE_BYTES).is_err() || close {
            break;
        }
    }
    // The response is already flushed; half-close so the client sees the
    // end of the stream after the last frame, then close (point 10).
    let _ = stream.shutdown(Shutdown::Write);
}

impl<S: Service> Shared<S> {
    fn answer(&self, ask: Ask, uid: u32) -> Response {
        match ask {
            Ask::Ping => Response::Pong(Empty {}),
            Ask::Status => {
                let operations = self
                    .operations
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let running = operations
                    .values()
                    .filter(|operation| {
                        matches!(
                            operation.state,
                            OperationState::Queued | OperationState::Running
                        )
                    })
                    .count();
                drop(operations);
                Response::Status(StatusReport {
                    service_version: env!("CARGO_PKG_VERSION").to_owned(),
                    operations_running: u32::try_from(running).unwrap_or(u32::MAX),
                    sources: self.service.sources(),
                })
            }
            Ask::Operation(text) => {
                let operations = self
                    .operations
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                // An unknown and a foreign identifier get the same answer.
                match OperationId::parse(&text)
                    .and_then(|id| operations.get(&id).map(|operation| (id, operation)))
                {
                    Some((id, operation)) if operation.owner == uid || uid == 0 => {
                        Response::Operation(OperationView {
                            operation_id: id.to_string(),
                            action: operation.action.clone(),
                            state: operation.state,
                            outcome: operation.outcome.clone(),
                        })
                    }
                    _ => Response::error(ErrorKind::UnknownOperation, "no such operation"),
                }
            }
            Ask::Plan(action) => {
                let plan = match self.service.plan(&action) {
                    Ok(plan) => plan,
                    Err(refusal) => return Response::Refused(refusal),
                };
                let digest = plan_digest(&action, &plan);
                let mut plans = self.plans.lock().unwrap_or_else(PoisonError::into_inner);
                plans.retain(|_, plan| plan.shown_at.elapsed() < PLAN_LIFETIME);
                plans.insert(
                    digest.clone(),
                    PendingPlan {
                        owner: uid,
                        action: action.clone(),
                        shown_at: Instant::now(),
                    },
                );
                Response::Plan(PlanView {
                    action,
                    plan_digest: digest,
                    summary: plan.summary,
                    changes: plan.changes,
                })
            }
            Ask::Confirm(confirm) => self.confirm(&confirm, uid),
        }
    }

    fn confirm(&self, confirm: &ConfirmRequest, uid: u32) -> Response {
        if !confirm.confirmed {
            return Response::error(ErrorKind::NotConfirmed, "confirmation is false");
        }
        let pending = {
            let mut plans = self.plans.lock().unwrap_or_else(PoisonError::into_inner);
            match plans.remove(&confirm.plan_digest) {
                Some(plan) if plan.owner == uid && plan.shown_at.elapsed() < PLAN_LIFETIME => plan,
                Some(plan) if plan.owner != uid => {
                    // Another caller's plan stays theirs.
                    plans.insert(confirm.plan_digest.clone(), plan);
                    return Response::error(ErrorKind::StalePlan, "no such plan");
                }
                _ => return Response::error(ErrorKind::StalePlan, "no such plan"),
            }
        };
        // The plan the server would run now must be the plan that was shown.
        let plan = match self.service.plan(&pending.action) {
            Ok(plan) if plan_digest(&pending.action, &plan) == confirm.plan_digest => plan,
            _ => {
                return Response::error(
                    ErrorKind::StalePlan,
                    "the plan changed since it was shown",
                );
            }
        };
        let Ok(id) = random_operation_id() else {
            return Response::error(ErrorKind::Internal, "no random source; nothing was started");
        };
        {
            let mut operations = self
                .operations
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            prune_finished(&mut operations);
            operations.insert(
                id,
                Operation {
                    owner: uid,
                    action: pending.action,
                    plan,
                    state: OperationState::Queued,
                    outcome: None,
                    finished_at: None,
                },
            );
        }
        let sent = self
            .jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send(id);
        if sent.is_err() {
            self.finish(
                id,
                Err(OperationOutcome {
                    message: "the operation worker is gone; nothing was run".to_owned(),
                    reason_codes: Vec::new(),
                }),
            );
        }
        Response::Started(Started {
            operation_id: id.to_string(),
        })
    }

    fn run_operation(&self, id: OperationId) {
        let job = {
            let mut operations = self
                .operations
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let Some(operation) = operations.get_mut(&id) else {
                return;
            };
            operation.state = OperationState::Running;
            (operation.action.clone(), operation.plan.clone())
        };
        let outcome = self.service.run(&job.0, &job.1);
        self.finish(id, outcome);
    }

    fn finish(&self, id: OperationId, outcome: Result<OperationOutcome, OperationOutcome>) {
        let mut operations = self
            .operations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(operation) = operations.get_mut(&id) {
            let (state, outcome) = match outcome {
                Ok(outcome) => (OperationState::Succeeded, outcome),
                Err(outcome) => (OperationState::Failed, outcome),
            };
            operation.state = state;
            operation.outcome = Some(outcome);
            operation.finished_at = Some(Instant::now());
        }
    }
}

/// Keeps at most [`FINISHED_KEPT`] finished operations, dropping the oldest.
fn prune_finished(operations: &mut HashMap<OperationId, Operation>) {
    let mut finished: Vec<(Instant, OperationId)> = operations
        .iter()
        .filter_map(|(id, operation)| operation.finished_at.map(|at| (at, *id)))
        .collect();
    if finished.len() < FINISHED_KEPT {
        return;
    }
    finished.sort();
    for (_, id) in finished.iter().take(finished.len() + 1 - FINISHED_KEPT) {
        operations.remove(id);
    }
}

/// 128 bits from the kernel's random source.
pub(crate) fn random_operation_id() -> io::Result<OperationId> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(OperationId::from_bytes(bytes))
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
