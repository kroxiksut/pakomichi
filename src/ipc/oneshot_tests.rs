// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::ipc::channels::{FetchRequest, ObjectRef, SignRequest, SignText, Stored};
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SHA: &str = "a59a5cfd27b6b5090de79452c96ca6526cfddda93b1b2fab559f08ac8bdf41f9";

fn own_uid() -> Result<u32, Box<dyn std::error::Error>> {
    let (left, _right) = UnixStream::pair()?;
    Ok(peer_uid(&left)?)
}

fn fetch() -> FetchRequest {
    FetchRequest::Fetch(ObjectRef {
        sha256: SHA.to_owned(),
        size: 800,
    })
}

fn channel(
    dir: &TempDir,
    rule: PeerRule,
    calls: Arc<AtomicUsize>,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("fetch.sock");
    let listener = UnixListener::bind(&path)?;
    serve_channel(
        listener,
        rule,
        FETCH_LIMITS,
        move |request: FetchRequest, _uid| {
            calls.fetch_add(1, Ordering::SeqCst);
            let FetchRequest::Fetch(object) = request;
            FetchResponse::Stored(Stored {
                sha256: object.sha256,
            })
        },
    )?;
    Ok(path)
}

#[test]
fn a_peer_of_another_uid_gets_no_answer_and_runs_nothing() -> TestResult {
    let dir = TempDir::new()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let path = channel(
        &dir,
        PeerRule::OnlyUid(own_uid()?.wrapping_add(1)),
        Arc::clone(&calls),
    )?;
    let result = call::<_, FetchResponse>(&path, &fetch(), Duration::from_secs(5));
    assert!(
        matches!(
            result,
            Err(CallError::Frame(_)) | Err(CallError::Connect(_))
        ),
        "{result:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn the_admitted_peer_gets_one_answer_per_connection() -> TestResult {
    let dir = TempDir::new()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let path = channel(&dir, PeerRule::OnlyUid(own_uid()?), Arc::clone(&calls))?;
    for _ in 0..3 {
        let response: FetchResponse = call(&path, &fetch(), Duration::from_secs(5))?;
        assert_eq!(
            response,
            FetchResponse::Stored(Stored {
                sha256: SHA.to_owned()
            })
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    Ok(())
}

#[test]
fn a_request_of_another_channel_is_refused_before_the_handler() -> TestResult {
    let dir = TempDir::new()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let path = channel(&dir, PeerRule::OnlyUid(own_uid()?), Arc::clone(&calls))?;
    let sign = SignRequest::Clearsign(SignText {
        text: "Origin: Pakomichi\n".to_owned(),
    });
    let response: FetchResponse = call(&path, &sign, Duration::from_secs(5))?;
    assert!(
        matches!(&response, FetchResponse::Error(body) if body.error == ErrorKind::Malformed),
        "{response:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn an_instance_checks_the_peer_of_its_own_connection_before_reading() -> TestResult {
    // An `Accept=yes` instance: standard input and output are one socket.
    let (server, mut client) = UnixStream::pair()?;
    write_frame(&mut client, &encode(&fetch()), MAX_REQUEST_BYTES)?;
    let calls = AtomicUsize::new(0);
    let refused = serve_one(
        server.try_clone()?,
        server.try_clone()?,
        server.try_clone()?,
        PeerRule::OnlyUid(own_uid()?.wrapping_add(1)),
        |_request: FetchRequest, _uid| {
            calls.fetch_add(1, Ordering::SeqCst);
            FetchResponse::refused(refusal(ErrorKind::Internal))
        },
    );
    assert!(
        matches!(refused, Err(ServeError::PeerRefused { .. })),
        "{refused:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // The admitted peer: one answer, then the end of the stream.
    serve_one(
        server.try_clone()?,
        server.try_clone()?,
        server.try_clone()?,
        PeerRule::OnlyUid(own_uid()?),
        |request: FetchRequest, _uid| {
            let FetchRequest::Fetch(object) = request;
            FetchResponse::Stored(Stored {
                sha256: object.sha256,
            })
        },
    )?;
    let text = read_frame(&mut client, MAX_RESPONSE_BYTES)?;
    assert!(matches!(
        decode::<FetchResponse>(&text)?,
        FetchResponse::Stored(_)
    ));
    let mut rest = Vec::new();
    client.read_to_end(&mut rest)?;
    assert!(rest.is_empty(), "nothing after the response");
    Ok(())
}
