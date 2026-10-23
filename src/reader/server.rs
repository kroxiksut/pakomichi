// SPDX-License-Identifier: MIT OR Apache-2.0

//! The loopback HTTP/1.1 endpoint of the repository reader.
//!
//! Only `GET` and `HEAD` exist; there is no route that changes anything
//! (N-025). A request with a body, without exactly one accepted `Host`, or
//! with a target outside origin form is refused before any lookup. An
//! object is hashed in full before its first byte is sent, and the bytes
//! sent come from the same open file that was hashed (N-017).

use std::convert::Infallible;
use std::io::{self, Read};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{self, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use super::route::{Lookup, Repositories};
use super::target::host_allowed;
use crate::cas::VerifiedObject;

/// Connection limits of the endpoint.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Connections served at once; further connections wait in the
    /// listen backlog.
    pub max_connections: usize,
    /// Time allowed for a request head to arrive, shorter than the 10 s
    /// that let slow clients hold connections in R-004 (ADR-024 point 5).
    pub header_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            header_timeout: Duration::from_secs(5),
        }
    }
}

/// Bytes read from an object per frame.
const CHUNK_BYTES: usize = 64 * 1024;

/// Refuses a listener that is not bound to a loopback address.
pub fn check_loopback(listener: &TcpListener) -> io::Result<u16> {
    let local = listener.local_addr()?;
    if !local.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to serve on non-loopback address {local}"),
        ));
    }
    Ok(local.port())
}

/// Serves `repositories` on `listener` until the task is dropped. Accept
/// errors (for example, too many open files) are logged and retried; they
/// never end the loop.
pub async fn serve(
    listener: TcpListener,
    repositories: Arc<Repositories>,
    limits: Limits,
) -> io::Result<()> {
    let port = check_loopback(&listener)?;
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
            return Ok(());
        };
        let stream = match listener.accept().await {
            Ok((stream, _peer)) => stream,
            Err(error) => {
                eprintln!("event=accept-error error={error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let repositories = Arc::clone(&repositories);
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(move |request| {
                let repositories = Arc::clone(&repositories);
                async move { Ok::<_, Infallible>(handle(request, &repositories, port).await) }
            });
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(limits.header_timeout)
                .keep_alive(true);
            if let Err(error) = builder
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                eprintln!("event=connection-error error={error}");
            }
        });
    }
}

/// Answers one request.
pub async fn handle(
    request: Request<Incoming>,
    repositories: &Arc<Repositories>,
    port: u16,
) -> Response<ReplyBody> {
    let method = request.method().clone();
    let shown = shown_target(request.uri().to_string().as_str());
    let response = match check_request(&request, port) {
        Err(response) => *response,
        Ok(target) => {
            let repositories = Arc::clone(repositories);
            let lookup = tokio::task::spawn_blocking(move || {
                repositories.lookup(&target, SystemTime::now())
            })
            .await;
            match lookup {
                Ok(lookup) => respond(lookup, method == Method::HEAD, &shown),
                Err(error) => {
                    eprintln!("event=lookup-failed target={shown} error={error}");
                    status(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n", true)
                }
            }
        }
    };
    eprintln!(
        "event=request method={} target={shown} status={}",
        shown_target(method.as_str()),
        response.status().as_u16()
    );
    response
}

/// Checks everything that does not need the store; returns the target.
fn check_request(
    request: &Request<Incoming>,
    port: u16,
) -> Result<String, Box<Response<ReplyBody>>> {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        let mut response = status(StatusCode::METHOD_NOT_ALLOWED, "read-only service\n", true);
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return Err(Box::new(response));
    }
    let headers = request.headers();
    let has_body = headers.contains_key(header::TRANSFER_ENCODING)
        || headers
            .get_all(header::CONTENT_LENGTH)
            .iter()
            .any(|value| value.as_bytes() != b"0");
    if has_body {
        return Err(Box::new(status(
            StatusCode::BAD_REQUEST,
            "request bodies are not accepted\n",
            true,
        )));
    }
    let mut hosts = headers.get_all(header::HOST).iter();
    let host_ok = match (hosts.next(), hosts.next()) {
        (Some(host), None) => host.to_str().is_ok_and(|host| host_allowed(host, port)),
        _ => false,
    };
    if !host_ok {
        return Err(Box::new(status(
            StatusCode::BAD_REQUEST,
            "unexpected Host\n",
            true,
        )));
    }
    let uri = request.uri();
    if uri.scheme().is_some() || uri.authority().is_some() {
        return Err(Box::new(status(
            StatusCode::BAD_REQUEST,
            "origin-form targets only\n",
            true,
        )));
    }
    Ok(uri.path_and_query().map_or_else(
        || uri.path().to_owned(),
        |target| target.as_str().to_owned(),
    ))
}

fn respond(lookup: Lookup, head: bool, shown: &str) -> Response<ReplyBody> {
    match lookup {
        Lookup::Found { object, .. } => {
            let size = object.size();
            let body = if head {
                ReplyBody::empty()
            } else {
                ReplyBody::object(object)
            };
            let mut response = Response::new(body);
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Lookup::NotFound => status(StatusCode::NOT_FOUND, "not found\n", false),
        Lookup::ObjectRefused(error) => {
            eprintln!("event=object-refused target={shown} error={error}");
            status(
                StatusCode::INTERNAL_SERVER_ERROR,
                "object unavailable\n",
                false,
            )
        }
        Lookup::Unavailable(error) => {
            eprintln!("event=store-unavailable target={shown} error={error}");
            status(
                StatusCode::SERVICE_UNAVAILABLE,
                "repository unavailable\n",
                false,
            )
        }
    }
}

fn status(code: StatusCode, text: &'static str, close: bool) -> Response<ReplyBody> {
    let mut response = Response::new(ReplyBody::text(text));
    *response.status_mut() = code;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if close {
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

/// A target for the log: at most 200 characters, control characters and
/// spaces escaped, so a request cannot forge log lines.
fn shown_target(target: &str) -> String {
    target
        .chars()
        .take(200)
        .flat_map(|character| {
            if character.is_control() || character == ' ' {
                character.escape_default().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}

/// One chunk read on the blocking pool, with the object handed back.
type PendingRead = JoinHandle<io::Result<(VerifiedObject, Vec<u8>)>>;

/// A response body: a short text, nothing, or a verified object read in
/// chunks on the blocking pool.
#[derive(Debug)]
pub struct ReplyBody(BodyState);

#[derive(Debug)]
enum BodyState {
    Text(Option<Bytes>),
    Object {
        file: Option<VerifiedObject>,
        remaining: u64,
        pending: Option<PendingRead>,
    },
}

impl ReplyBody {
    fn text(text: &'static str) -> Self {
        Self(BodyState::Text(Some(Bytes::from_static(text.as_bytes()))))
    }

    fn empty() -> Self {
        Self(BodyState::Text(None))
    }

    fn object(object: VerifiedObject) -> Self {
        let remaining = object.size();
        Self(BodyState::Object {
            file: Some(object),
            remaining,
            pending: None,
        })
    }
}

impl Body for ReplyBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match &mut self.get_mut().0 {
            BodyState::Text(text) => Poll::Ready(text.take().map(|bytes| Ok(Frame::data(bytes)))),
            BodyState::Object {
                file,
                remaining,
                pending,
            } => loop {
                if let Some(read) = pending {
                    let result = match Pin::new(read).poll(context) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => result,
                    };
                    *pending = None;
                    let (object, chunk) = match result {
                        Ok(Ok(read)) => read,
                        Ok(Err(error)) => return Poll::Ready(Some(Err(error))),
                        Err(error) => return Poll::Ready(Some(Err(io::Error::other(error)))),
                    };
                    let length = chunk.len() as u64;
                    if length == 0 || length > *remaining {
                        return Poll::Ready(Some(Err(io::Error::other(
                            "object changed size while it was sent",
                        ))));
                    }
                    *remaining -= length;
                    *file = Some(object);
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(chunk)))));
                }
                if *remaining == 0 {
                    return Poll::Ready(None);
                }
                let Some(mut object) = file.take() else {
                    return Poll::Ready(None);
                };
                let wanted = usize::try_from(*remaining)
                    .unwrap_or(CHUNK_BYTES)
                    .min(CHUNK_BYTES);
                *pending = Some(tokio::task::spawn_blocking(move || {
                    let mut chunk = vec![0; wanted];
                    let read = loop {
                        match object.read(&mut chunk) {
                            Ok(read) => break read,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                            Err(error) => return Err(error),
                        }
                    };
                    chunk.truncate(read);
                    Ok((object, chunk))
                }));
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.0 {
            BodyState::Text(text) => text.is_none(),
            BodyState::Object { remaining, .. } => *remaining == 0,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.0 {
            BodyState::Text(text) => {
                SizeHint::with_exact(text.as_ref().map_or(0, |bytes| bytes.len() as u64))
            }
            BodyState::Object { remaining, .. } => SizeHint::with_exact(*remaining),
        }
    }
}
