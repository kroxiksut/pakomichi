// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;
use crate::ipc::frame::FrameError;
use crate::ipc::protocol::{
    ConfirmRequest, ErrorBody, OperationQuery, PROTOCOL_VERSION, PlanRequest,
};

type TestResult = Result<(), Box<dyn Error>>;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> io::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "pakomichi-ipc-test-{}-{}-{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn uid(&self) -> io::Result<u32> {
        Ok(fs::metadata(&self.0)?.uid())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TestService {
    plan: Mutex<String>,
    run_for: Duration,
    runs: AtomicUsize,
}

impl Service for Arc<TestService> {
    fn plan(&self, action: &AdminAction) -> Result<Plan, ActionRefusal> {
        Ok(Plan {
            summary: format!(
                "{}: {}",
                action.as_str(),
                self.plan.lock().unwrap_or_else(PoisonError::into_inner)
            ),
            changes: Vec::new(),
        })
    }

    fn run(
        &self,
        _action: &AdminAction,
        _plan: &Plan,
    ) -> Result<OperationOutcome, OperationOutcome> {
        thread::sleep(self.run_for);
        self.runs.fetch_add(1, Ordering::SeqCst);
        Ok(OperationOutcome {
            message: "done".to_owned(),
            reason_codes: Vec::new(),
        })
    }

    fn sources(&self) -> Vec<SourceStatus> {
        Vec::new()
    }
}

struct Harness {
    _dir: TempDir,
    status: PathBuf,
    admin: PathBuf,
    service: Arc<TestService>,
    server: Server<Arc<TestService>>,
    uid: u32,
}

const FAST: Limits = Limits {
    first_frame: Duration::from_secs(2),
    idle: Duration::from_secs(2),
    per_uid: 8,
    total: 64,
};

fn start(
    rule_for: impl Fn(u32) -> PeerRule,
    status: Limits,
    admin: Limits,
    run_for: Duration,
) -> Result<Harness, Box<dyn Error>> {
    let dir = TempDir::new()?;
    let uid = dir.uid()?;
    let service = Arc::new(TestService {
        plan: Mutex::new("reset-failed pakomichi.socket; start pakomichi.socket".to_owned()),
        run_for,
        runs: AtomicUsize::new(0),
    });
    let server = Server::new(Arc::clone(&service))?;
    let status_path = dir.join("status.sock");
    let admin_path = dir.join("admin.sock");
    server.serve_status(UnixListener::bind(&status_path)?, rule_for(uid), status)?;
    server.serve_admin(UnixListener::bind(&admin_path)?, rule_for(uid), admin)?;
    Ok(Harness {
        _dir: dir,
        status: status_path,
        admin: admin_path,
        service,
        server,
        uid,
    })
}

fn harness() -> Result<Harness, Box<dyn Error>> {
    // The test process plays root on the administrative channel.
    start(PeerRule::OnlyUid, FAST, FAST, Duration::ZERO)
}

fn connect(path: &Path) -> io::Result<UnixStream> {
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    Ok(stream)
}

fn send_raw(stream: &mut UnixStream, text: &str) -> Result<(), FrameError> {
    write_frame(stream, text, MAX_REQUEST_BYTES)
}

fn ask(stream: &mut UnixStream, text: &str) -> Result<Response, Box<dyn Error>> {
    send_raw(stream, text)?;
    let reply = read_frame(stream, MAX_RESPONSE_BYTES)?;
    Ok(decode::<Response>(&reply)?)
}

fn request<T: serde::Serialize>(
    stream: &mut UnixStream,
    message: &T,
) -> Result<Response, Box<dyn Error>> {
    ask(stream, &encode(message))
}

/// The server closed the connection without sending a frame.
fn closed_without_response(stream: &mut UnixStream) -> bool {
    matches!(
        read_frame(stream, MAX_RESPONSE_BYTES),
        Err(FrameError::Closed | FrameError::Io(_))
    )
}

fn error_kind(response: &Response) -> Option<ErrorKind> {
    match response {
        Response::Error(ErrorBody { error, .. }) => Some(*error),
        _ => None,
    }
}

#[test]
fn ping_and_status_answer_on_both_channels() -> TestResult {
    let harness = harness()?;
    for path in [&harness.status, &harness.admin] {
        let mut stream = connect(path)?;
        assert_eq!(
            request(&mut stream, &StatusRequest::Ping(Empty {}))?,
            Response::Pong(Empty {})
        );
        // Several requests on one connection, one at a time.
        let Response::Status(report) = request(&mut stream, &StatusRequest::Status(Empty {}))?
        else {
            return Err("expected a status report".into());
        };
        assert_eq!(report.operations_running, 0);
        assert_eq!(report.service_version, env!("CARGO_PKG_VERSION"));
    }
    Ok(())
}

#[test]
fn a_peer_with_another_uid_is_refused_on_every_channel() -> TestResult {
    let harness = start(|uid| PeerRule::OnlyUid(uid + 1), FAST, FAST, Duration::ZERO)?;
    for path in [&harness.status, &harness.admin] {
        let mut stream = connect(path)?;
        let _ = send_raw(&mut stream, &encode(&StatusRequest::Ping(Empty {})));
        assert!(closed_without_response(&mut stream), "{}", path.display());
    }
    Ok(())
}

#[test]
fn administrative_requests_are_unknown_on_the_status_channel() -> TestResult {
    let harness = harness()?;
    let mut stream = connect(&harness.status)?;
    let plan = encode(&AdminRequest::Plan(PlanRequest {
        action: AdminAction::DoctorRepair(Empty {}),
    }));
    let response = ask(&mut stream, &plan)?;
    assert_eq!(error_kind(&response), Some(ErrorKind::Malformed));
    assert!(
        closed_without_response(&mut stream),
        "a refused request closes the connection"
    );

    let mut stream = connect(&harness.status)?;
    let confirm = encode(&AdminRequest::Confirm(ConfirmRequest {
        plan_digest: "ab".repeat(32),
        confirmed: true,
    }));
    assert_eq!(
        error_kind(&ask(&mut stream, &confirm)?),
        Some(ErrorKind::Malformed)
    );
    assert_eq!(harness.service.runs.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn bad_frames_close_the_connection_without_parsing() -> TestResult {
    let harness = harness()?;
    let cases: [&[u8]; 4] = [
        &[0, 0, 0, 0],
        &[0x7f, 0xff, 0xff, 0xff],
        &[0, 0, 0, 10, b'{', b'"', b'a'],
        &[0, 0, 0, 2, 0xc3, 0x28],
    ];
    for bytes in cases {
        let mut stream = connect(&harness.status)?;
        stream.write_all(bytes)?;
        stream.shutdown(Shutdown::Write)?;
        assert!(closed_without_response(&mut stream), "{bytes:?}");
    }
    Ok(())
}

#[test]
fn an_unknown_version_is_answered_with_the_supported_ones() -> TestResult {
    let harness = harness()?;
    let mut stream = connect(&harness.status)?;
    let response = ask(&mut stream, r#"{"schema_version":2,"type":"ping"}"#)?;
    let Response::Error(body) = response else {
        return Err("expected an error".into());
    };
    assert_eq!(body.error, ErrorKind::UnsupportedVersion);
    assert_eq!(body.supported_versions, vec![PROTOCOL_VERSION]);
    assert!(closed_without_response(&mut stream));
    Ok(())
}

#[test]
fn a_confirmation_without_its_field_or_with_false_starts_nothing() -> TestResult {
    let harness = harness()?;
    let mut stream = connect(&harness.admin)?;
    let Response::Plan(plan) = request(
        &mut stream,
        &AdminRequest::Plan(PlanRequest {
            action: AdminAction::DoctorRepair(Empty {}),
        }),
    )?
    else {
        return Err("expected a plan".into());
    };
    let missing = format!(
        r#"{{"plan_digest":"{}","schema_version":1,"type":"confirm"}}"#,
        plan.plan_digest
    );
    assert_eq!(
        error_kind(&ask(&mut stream, &missing)?),
        Some(ErrorKind::Malformed)
    );

    let mut stream = connect(&harness.admin)?;
    let refused = AdminRequest::Confirm(ConfirmRequest {
        plan_digest: plan.plan_digest,
        confirmed: false,
    });
    assert_eq!(
        error_kind(&request(&mut stream, &refused)?),
        Some(ErrorKind::NotConfirmed)
    );
    thread::sleep(Duration::from_millis(100));
    assert_eq!(harness.service.runs.load(Ordering::SeqCst), 0);
    Ok(())
}

fn wait_for_state(
    stream: &mut UnixStream,
    id: &str,
    wanted: OperationState,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let response = request(
            stream,
            &AdminRequest::Operation(OperationQuery {
                operation_id: id.to_owned(),
            }),
        )?;
        if let Response::Operation(view) = &response
            && view.state == wanted
        {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!("operation never reached {wanted:?}: {response:?}").into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_confirmed_plan_runs_once_as_an_operation() -> TestResult {
    let harness = harness()?;
    let mut stream = connect(&harness.admin)?;
    let Response::Plan(plan) = request(
        &mut stream,
        &AdminRequest::Plan(PlanRequest {
            action: AdminAction::DoctorRepair(Empty {}),
        }),
    )?
    else {
        return Err("expected a plan".into());
    };
    assert_eq!(
        plan.plan_digest,
        plan_digest(
            &AdminAction::DoctorRepair(Empty {}),
            &Plan {
                summary: plan.summary.clone(),
                changes: plan.changes.clone(),
            }
        )
    );
    let confirm = AdminRequest::Confirm(ConfirmRequest {
        plan_digest: plan.plan_digest.clone(),
        confirmed: true,
    });
    let Response::Started(started) = request(&mut stream, &confirm)? else {
        return Err("expected a started operation".into());
    };
    assert!(OperationId::parse(&started.operation_id).is_some());
    wait_for_state(
        &mut stream,
        &started.operation_id,
        OperationState::Succeeded,
    )?;
    assert_eq!(harness.service.runs.load(Ordering::SeqCst), 1);

    // The same confirmation cannot start it twice.
    assert_eq!(
        error_kind(&request(&mut stream, &confirm)?),
        Some(ErrorKind::StalePlan)
    );
    // The operation is visible on the status channel to the same uid.
    let mut status = connect(&harness.status)?;
    let response = request(
        &mut status,
        &StatusRequest::Operation(OperationQuery {
            operation_id: started.operation_id,
        }),
    )?;
    assert!(
        matches!(response, Response::Operation(view) if view.state == OperationState::Succeeded)
    );
    Ok(())
}

#[test]
fn a_plan_that_changed_since_it_was_shown_is_refused() -> TestResult {
    let harness = harness()?;
    let mut stream = connect(&harness.admin)?;
    let Response::Plan(plan) = request(
        &mut stream,
        &AdminRequest::Plan(PlanRequest {
            action: AdminAction::DoctorRepair(Empty {}),
        }),
    )?
    else {
        return Err("expected a plan".into());
    };
    *harness
        .service
        .plan
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = "something else".to_owned();
    let confirm = AdminRequest::Confirm(ConfirmRequest {
        plan_digest: plan.plan_digest,
        confirmed: true,
    });
    assert_eq!(
        error_kind(&request(&mut stream, &confirm)?),
        Some(ErrorKind::StalePlan)
    );
    let unknown = AdminRequest::Confirm(ConfirmRequest {
        plan_digest: "00".repeat(32),
        confirmed: true,
    });
    assert_eq!(
        error_kind(&request(&mut stream, &unknown)?),
        Some(ErrorKind::StalePlan)
    );
    thread::sleep(Duration::from_millis(100));
    assert_eq!(harness.service.runs.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn unknown_and_foreign_operations_get_the_same_answer() -> TestResult {
    let harness = harness()?;
    let mut stream = connect(&harness.admin)?;
    let Response::Plan(plan) = request(
        &mut stream,
        &AdminRequest::Plan(PlanRequest {
            action: AdminAction::DoctorRepair(Empty {}),
        }),
    )?
    else {
        return Err("expected a plan".into());
    };
    let Response::Started(started) = request(
        &mut stream,
        &AdminRequest::Confirm(ConfirmRequest {
            plan_digest: plan.plan_digest,
            confirmed: true,
        }),
    )?
    else {
        return Err("expected a started operation".into());
    };
    let shared = &harness.server.shared;
    let foreign = shared.answer(
        Ask::Operation(started.operation_id.clone()),
        harness.uid + 1,
    );
    let unknown = shared.answer(Ask::Operation("0f".repeat(16)), harness.uid + 1);
    let garbage = shared.answer(Ask::Operation("not an id".to_owned()), harness.uid + 1);
    assert_eq!(foreign, unknown);
    assert_eq!(unknown, garbage);
    assert_eq!(error_kind(&foreign), Some(ErrorKind::UnknownOperation));
    // The owner and uid 0 see it.
    assert!(matches!(
        shared.answer(Ask::Operation(started.operation_id.clone()), harness.uid),
        Response::Operation(_)
    ));
    assert!(matches!(
        shared.answer(Ask::Operation(started.operation_id), 0),
        Response::Operation(_)
    ));
    Ok(())
}

#[test]
fn ping_answers_while_a_long_operation_runs() -> TestResult {
    let harness = start(PeerRule::OnlyUid, FAST, FAST, Duration::from_millis(1500))?;
    let mut admin = connect(&harness.admin)?;
    let Response::Plan(plan) = request(
        &mut admin,
        &AdminRequest::Plan(PlanRequest {
            action: AdminAction::DoctorRepair(Empty {}),
        }),
    )?
    else {
        return Err("expected a plan".into());
    };
    let started = Instant::now();
    let Response::Started(_) = request(
        &mut admin,
        &AdminRequest::Confirm(ConfirmRequest {
            plan_digest: plan.plan_digest,
            confirmed: true,
        }),
    )?
    else {
        return Err("expected a started operation".into());
    };
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "starting does not wait for the work"
    );
    thread::sleep(Duration::from_millis(100));
    for path in [&harness.status, &harness.admin] {
        let mut stream = connect(path)?;
        let asked = Instant::now();
        assert_eq!(
            request(&mut stream, &StatusRequest::Ping(Empty {}))?,
            Response::Pong(Empty {})
        );
        assert!(
            asked.elapsed() < Duration::from_millis(300),
            "ping took {:?}",
            asked.elapsed()
        );
        let Response::Status(report) = request(&mut stream, &StatusRequest::Status(Empty {}))?
        else {
            return Err("expected a status report".into());
        };
        assert_eq!(report.operations_running, 1);
    }
    Ok(())
}

#[test]
fn a_silent_client_is_cut_at_the_first_frame_deadline() -> TestResult {
    let quick = Limits {
        first_frame: Duration::from_millis(200),
        idle: Duration::from_millis(400),
        ..FAST
    };
    let harness = start(PeerRule::OnlyUid, quick, quick, Duration::ZERO)?;
    let mut silent = connect(&harness.status)?;
    let begun = Instant::now();
    assert!(closed_without_response(&mut silent));
    assert!(begun.elapsed() < Duration::from_secs(2));

    // After one request, the idle deadline applies.
    let mut idle = connect(&harness.status)?;
    assert_eq!(
        request(&mut idle, &StatusRequest::Ping(Empty {}))?,
        Response::Pong(Empty {})
    );
    let begun = Instant::now();
    assert!(closed_without_response(&mut idle));
    assert!(begun.elapsed() >= Duration::from_millis(300));
    Ok(())
}

#[test]
fn the_per_uid_limit_holds_and_frees_its_slots() -> TestResult {
    let two = Limits { per_uid: 2, ..FAST };
    let harness = start(PeerRule::OnlyUid, two, two, Duration::ZERO)?;
    let mut first = connect(&harness.status)?;
    let mut second = connect(&harness.status)?;
    assert_eq!(
        request(&mut first, &StatusRequest::Ping(Empty {}))?,
        Response::Pong(Empty {})
    );
    assert_eq!(
        request(&mut second, &StatusRequest::Ping(Empty {}))?,
        Response::Pong(Empty {})
    );
    let mut third = connect(&harness.status)?;
    let _ = send_raw(&mut third, &encode(&StatusRequest::Ping(Empty {})));
    assert!(closed_without_response(&mut third), "over the limit");

    drop(first);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut fourth = connect(&harness.status)?;
        if send_raw(&mut fourth, &encode(&StatusRequest::Ping(Empty {}))).is_ok()
            && read_frame(&mut fourth, MAX_RESPONSE_BYTES).is_ok()
        {
            break;
        }
        if Instant::now() > deadline {
            return Err("the slot was never released".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    drop(second);
    Ok(())
}

#[test]
fn a_large_response_is_read_completely_before_the_close() -> TestResult {
    let harness = harness()?;
    *harness
        .service
        .plan
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = "x".repeat(3 * 1024 * 1024);
    let mut stream = connect(&harness.admin)?;
    let Response::Plan(plan) = request(
        &mut stream,
        &AdminRequest::Plan(PlanRequest {
            action: AdminAction::DoctorRepair(Empty {}),
        }),
    )?
    else {
        return Err("expected a plan".into());
    };
    assert_eq!(
        plan.summary.len(),
        "doctor_repair: ".len() + 3 * 1024 * 1024
    );
    stream.shutdown(Shutdown::Write)?;
    assert!(matches!(
        read_frame(&mut stream, MAX_RESPONSE_BYTES),
        Err(FrameError::Closed)
    ));
    Ok(())
}
