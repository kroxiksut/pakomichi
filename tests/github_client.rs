// SPDX-License-Identifier: MIT OR Apache-2.0

//! P2-001 acceptance tests: identity pinning (rename, transfer, replacement),
//! conditional requests, rate limits, pagination, and response validation.
//! A fake transport replays synthetic GitHub-shaped responses; no network,
//! no root. The fixtures carry extra fields as real responses do.

use std::collections::VecDeque;
use std::error::Error;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pakomichi::error::{ObjectKind, ObjectReference, ReasonCode, SafeIdentifier};
use pakomichi::github::{
    ApiRequest, ApiResponse, ClientConfig, Clock, EtagCache, Freshness, GitHubClient, GitHubError,
    GitObjectId, IdentityOutcome, OwnerId, OwnerLogin, PaginationError, PinnedRepository,
    RateLimitKind, RateLimited, RepositoryId, RepositoryIdentity, RepositoryName, ResponseHeaders,
    TagObjectKind, TagRef, Token, Transport, TransportError, WireError,
};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn Error>>;

/// Removes one field from a fixture.
type Mutation = fn(&mut Value);

const NOW: u64 = 1_800_000_000;

// ---------------------------------------------------------------- fakes

#[derive(Default)]
struct FakeState {
    replies: VecDeque<ApiResponse>,
    requests: Vec<ApiRequest>,
}

/// Replays queued responses and records every request it receives.
#[derive(Clone, Default)]
struct FakeTransport(Arc<Mutex<FakeState>>);

impl FakeTransport {
    fn push(&self, response: ApiResponse) -> &Self {
        self.state().replies.push_back(response);
        self
    }

    fn requests(&self) -> Vec<ApiRequest> {
        self.state().requests.clone()
    }

    fn paths(&self) -> Vec<String> {
        self.requests()
            .iter()
            .map(|request| request.path().to_owned())
            .collect()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Transport for FakeTransport {
    async fn send(
        &self,
        request: ApiRequest,
        _max_body_bytes: usize,
    ) -> Result<ApiResponse, TransportError> {
        let mut state = self.state();
        state.requests.push(request);
        state.replies.pop_front().ok_or(TransportError::Connect)
    }
}

struct TestClock(Mutex<SystemTime>);

impl TestClock {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(UNIX_EPOCH + Duration::from_secs(NOW))))
    }

    fn advance(&self, by: Duration) {
        let mut now = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *now += by;
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

// ------------------------------------------------------------- fixtures

fn repository(id: u64, owner_id: u64, login: &str, name: &str) -> Value {
    json!({
        "id": id,
        "node_id": "R_kgDOsynthetic",
        "name": name,
        "full_name": format!("{login}/{name}"),
        "private": false,
        "owner": {
            "login": login,
            "id": owner_id,
            "node_id": "U_kgDOsynthetic",
            "type": "User",
            "site_admin": false
        },
        "html_url": format!("https://github.com/{login}/{name}"),
        "fork": false,
        "archived": false,
        "default_branch": "main",
        "topics": ["packaging"],
        "stargazers_count": 3,
        "some_future_field": {"nested": [1, 2, 3]}
    })
}

fn asset(id: u64, name: &str, digest: Option<&str>) -> Value {
    let mut value = json!({
        "url": format!("https://api.github.com/repos/alice/tool/releases/assets/{id}"),
        "id": id,
        "node_id": "RA_synthetic",
        "name": name,
        "label": null,
        "content_type": "application/vnd.debian.binary-package",
        "state": "uploaded",
        "size": 123_456,
        "download_count": 7,
        "created_at": "2026-10-01T12:00:00Z",
        "updated_at": "2026-10-01T12:00:05Z",
        "browser_download_url": format!("https://github.com/alice/tool/releases/download/v1.0.0/{name}")
    });
    if let (Some(digest), Some(object)) = (digest, value.as_object_mut()) {
        object.insert("digest".to_owned(), json!(digest));
    }
    value
}

fn release(id: u64, tag: &str, assets: Vec<Value>) -> Value {
    json!({
        "url": format!("https://api.github.com/repos/alice/tool/releases/{id}"),
        "id": id,
        "node_id": "RE_synthetic",
        "tag_name": tag,
        "target_commitish": "main",
        "name": tag,
        "body": "Release notes with **markdown** and <b>html</b> that is never parsed.",
        "draft": false,
        "prerelease": false,
        "immutable": true,
        "created_at": "2026-10-01T11:59:00Z",
        "published_at": "2026-10-01T12:00:00Z",
        "author": {"login": "alice", "id": 10},
        "assets": assets,
        "reactions": {"+1": 2}
    })
}

fn response(status: u16, body: &Value) -> ApiResponse {
    ApiResponse {
        status,
        headers: ResponseHeaders::default(),
        body: body.to_string().into_bytes(),
    }
}

fn with_etag(mut response: ApiResponse, etag: &str) -> ApiResponse {
    response.headers.etag = Some(etag.to_owned());
    response
}

fn not_modified(etag: Option<&str>) -> ApiResponse {
    ApiResponse {
        status: 304,
        headers: ResponseHeaders {
            etag: etag.map(str::to_owned),
            ..ResponseHeaders::default()
        },
        body: Vec::new(),
    }
}

fn status_only(status: u16, headers: ResponseHeaders, body: &str) -> ApiResponse {
    ApiResponse {
        status,
        headers,
        body: body.as_bytes().to_vec(),
    }
}

fn identity(
    id: u64,
    owner_id: u64,
    login: &str,
    name: &str,
) -> Result<RepositoryIdentity, Box<dyn Error>> {
    Ok(RepositoryIdentity::new(
        RepositoryId::new(id)?,
        OwnerId::new(owner_id)?,
        OwnerLogin::new(login)?,
        RepositoryName::new(name)?,
    ))
}

fn pinned() -> Result<PinnedRepository, Box<dyn Error>> {
    Ok(PinnedRepository::pin(identity(100, 10, "alice", "tool")?))
}

fn client(fake: &FakeTransport) -> GitHubClient<FakeTransport> {
    GitHubClient::new(fake.clone(), None)
}

fn source() -> Result<ObjectReference, Box<dyn Error>> {
    Ok(ObjectReference::new(
        ObjectKind::Source,
        SafeIdentifier::new("source-1")?,
    ))
}

// ------------------------------------------------------------- identity

#[tokio::test]
async fn first_resolution_pins_the_numeric_ids() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(response(200, &repository(100, 10, "alice", "tool")));
    let pinned = client(&fake)
        .pin_source(&OwnerLogin::new("alice")?, &RepositoryName::new("tool")?)
        .await?;
    assert_eq!(pinned.repository_id().get(), 100);
    assert_eq!(pinned.owner_id().get(), 10);
    assert_eq!(pinned.repository_id().to_string(), "100");
    assert_eq!(
        pinned.identity().canonical_url(),
        "https://github.com/alice/tool"
    );
    assert_eq!(fake.paths(), ["/repos/alice/tool"]);
    Ok(())
}

#[tokio::test]
async fn rename_with_the_same_ids_is_followed_and_recorded() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(response(200, &repository(100, 10, "alice", "tool-ng")));
    let pinned = pinned()?;

    let outcome = client(&fake).reconcile(&pinned).await?;
    assert_eq!(fake.paths(), ["/repositories/100"]);
    assert!(outcome.is_accepted());
    assert_eq!(outcome.reason_code(), None);
    assert_eq!(outcome.reason(source()?)?, None);

    let (renamed, previous_url) = pinned
        .follow_rename(outcome)
        .map_err(|other| format!("rename not followed: {other:?}"))?;
    assert_eq!(previous_url, "https://github.com/alice/tool");
    assert_eq!(renamed.identity().full_name(), "alice/tool-ng");
    assert_eq!(renamed.repository_id(), pinned.repository_id());
    Ok(())
}

#[tokio::test]
async fn the_old_name_redirects_to_the_same_id_after_a_rename() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(status_only(
        301,
        ResponseHeaders {
            location: Some("https://api.github.com/repositories/100".to_owned()),
            ..ResponseHeaders::default()
        },
        r#"{"message":"Moved Permanently","url":"https://api.github.com/repositories/100"}"#,
    ))
    .push(response(200, &repository(100, 10, "alice", "tool-ng")));

    let outcome = client(&fake)
        .check_address(
            &pinned()?,
            &OwnerLogin::new("alice")?,
            &RepositoryName::new("tool")?,
        )
        .await?;
    assert_eq!(fake.paths(), ["/repos/alice/tool", "/repositories/100"]);
    match outcome {
        IdentityOutcome::Renamed {
            previous_url,
            current,
        } => {
            assert_eq!(previous_url, "https://github.com/alice/tool");
            assert_eq!(current.full_name(), "alice/tool-ng");
        }
        other => return Err(format!("expected a rename, got {other:?}").into()),
    }
    Ok(())
}

#[tokio::test]
async fn a_new_repository_under_the_old_name_is_refused() -> TestResult {
    let fake = FakeTransport::default();
    // Someone created a fresh `alice/tool` after the original was renamed.
    fake.push(response(200, &repository(200, 10, "alice", "tool")));

    let outcome = client(&fake)
        .check_address(
            &pinned()?,
            &OwnerLogin::new("alice")?,
            &RepositoryName::new("tool")?,
        )
        .await?;
    assert_eq!(
        outcome,
        IdentityOutcome::Replaced {
            expected: RepositoryId::new(100)?,
            observed: RepositoryId::new(200)?
        }
    );
    assert!(!outcome.is_accepted());
    assert_eq!(outcome.reason_code(), Some(ReasonCode::ERepoIdChanged));
    let reason = outcome.reason(source()?)?.ok_or("no reason")?;
    assert_eq!(reason.code(), ReasonCode::ERepoIdChanged);
    assert!(pinned()?.follow_rename(outcome).is_err());
    Ok(())
}

#[tokio::test]
async fn an_id_mismatch_on_the_id_endpoint_is_refused() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(response(200, &repository(101, 10, "alice", "tool")));
    let outcome = client(&fake).reconcile(&pinned()?).await?;
    assert_eq!(outcome.reason_code(), Some(ReasonCode::ERepoIdChanged));
    Ok(())
}

#[tokio::test]
async fn a_transfer_is_a_distinct_blocking_outcome() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(response(200, &repository(100, 77, "new-org", "tool")));
    let outcome = client(&fake).reconcile(&pinned()?).await?;
    match &outcome {
        IdentityOutcome::Transferred {
            previous_owner_id,
            current,
        } => {
            assert_eq!(previous_owner_id.get(), 10);
            assert_eq!(current.owner_id().get(), 77);
        }
        other => return Err(format!("expected a transfer, got {other:?}").into()),
    }
    assert!(!outcome.is_accepted());
    assert_eq!(outcome.reason_code(), Some(ReasonCode::EOwnerTransfer));
    let reason = outcome.reason(source()?)?.ok_or("no reason")?;
    assert!(!reason.message().as_str().contains("new-org"));
    Ok(())
}

#[tokio::test]
async fn redirects_elsewhere_are_refused() -> TestResult {
    for location in [
        "https://evil.example/repositories/100",
        "http://api.github.com/repositories/100",
        "https://api.github.com/repos/bob/tool",
    ] {
        let fake = FakeTransport::default();
        fake.push(status_only(
            301,
            ResponseHeaders {
                location: Some(location.to_owned()),
                ..ResponseHeaders::default()
            },
            "",
        ));
        let result = client(&fake)
            .resolve_by_name(&OwnerLogin::new("alice")?, &RepositoryName::new("tool")?)
            .await;
        assert_eq!(result, Err(GitHubError::RedirectRefused), "{location}");
        assert_eq!(fake.requests().len(), 1);
    }
    // The ID endpoint never follows a redirect.
    let fake = FakeTransport::default();
    fake.push(status_only(
        301,
        ResponseHeaders {
            location: Some("https://api.github.com/repositories/100".to_owned()),
            ..ResponseHeaders::default()
        },
        "",
    ));
    assert_eq!(
        client(&fake).reconcile(&pinned()?).await,
        Err(GitHubError::RedirectRefused)
    );
    Ok(())
}

// ---------------------------------------------------------- conditional

#[tokio::test]
async fn a_304_for_our_stored_etag_confirms_unchanged() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(with_etag(
        response(200, &repository(100, 10, "alice", "tool")),
        "W/\"v1\"",
    ))
    .push(not_modified(Some("W/\"v1\"")));
    let client = client(&fake);
    let id = RepositoryId::new(100)?;

    let first = client.repository_by_id(id).await?;
    assert_eq!(first.freshness, Freshness::Modified);
    let second = client.repository_by_id(id).await?;
    assert_eq!(second.freshness, Freshness::Unchanged);
    assert_eq!(second.value, first.value);

    let requests = fake.requests();
    assert_eq!(requests[0].if_none_match(), None);
    assert_eq!(requests[1].if_none_match(), Some("W/\"v1\""));
    Ok(())
}

#[tokio::test]
async fn a_304_without_our_conditional_header_confirms_nothing() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(not_modified(Some("W/\"v1\"")));
    let result = client(&fake)
        .repository_by_id(RepositoryId::new(100)?)
        .await;
    assert_eq!(result, Err(GitHubError::UnexpectedNotModified));
    assert_eq!(fake.requests()[0].if_none_match(), None);
    Ok(())
}

#[tokio::test]
async fn a_304_for_another_url_confirms_nothing() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(with_etag(
        response(200, &repository(100, 10, "alice", "tool")),
        "W/\"v1\"",
    ))
    .push(not_modified(Some("W/\"v1\"")));
    let client = client(&fake);
    client.repository_by_id(RepositoryId::new(100)?).await?;
    let result = client.repository_by_id(RepositoryId::new(101)?).await;
    assert_eq!(result, Err(GitHubError::UnexpectedNotModified));
    assert_eq!(fake.requests()[1].if_none_match(), None);
    Ok(())
}

#[tokio::test]
async fn a_304_for_another_credential_confirms_nothing() -> TestResult {
    let cache = Arc::new(EtagCache::default());
    let fake = FakeTransport::default();
    fake.push(with_etag(
        response(200, &repository(100, 10, "alice", "tool")),
        "W/\"v1\"",
    ))
    .push(not_modified(Some("W/\"v1\"")));
    let anonymous = GitHubClient::new(fake.clone(), None).with_etag_cache(Arc::clone(&cache));
    let token = Token::new("sample-credential-value".to_owned())?;
    let authenticated =
        GitHubClient::new(fake.clone(), Some(token)).with_etag_cache(Arc::clone(&cache));

    anonymous.repository_by_id(RepositoryId::new(100)?).await?;
    let result = authenticated
        .repository_by_id(RepositoryId::new(100)?)
        .await;
    assert_eq!(result, Err(GitHubError::UnexpectedNotModified));
    let requests = fake.requests();
    assert_eq!(requests[1].if_none_match(), None);
    assert!(requests[1].token().is_some());
    Ok(())
}

#[tokio::test]
async fn a_304_naming_a_different_etag_confirms_nothing() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(with_etag(
        response(200, &repository(100, 10, "alice", "tool")),
        "W/\"v1\"",
    ))
    .push(not_modified(Some("W/\"v2\"")));
    let client = client(&fake);
    client.repository_by_id(RepositoryId::new(100)?).await?;
    let result = client.repository_by_id(RepositoryId::new(100)?).await;
    assert_eq!(result, Err(GitHubError::UnexpectedNotModified));
    Ok(())
}

#[tokio::test]
async fn an_etag_is_stored_only_after_validation() -> TestResult {
    let fake = FakeTransport::default();
    let mut broken = repository(100, 10, "alice", "tool");
    if let Some(object) = broken.as_object_mut() {
        object.remove("owner");
    }
    fake.push(with_etag(response(200, &broken), "W/\"bad\""))
        .push(not_modified(Some("W/\"bad\"")));
    let client = client(&fake);
    assert!(matches!(
        client.repository_by_id(RepositoryId::new(100)?).await,
        Err(GitHubError::Wire(_))
    ));
    let result = client.repository_by_id(RepositoryId::new(100)?).await;
    assert_eq!(result, Err(GitHubError::UnexpectedNotModified));
    assert_eq!(fake.requests()[1].if_none_match(), None);
    Ok(())
}

// ------------------------------------------------------------ wire data

#[tokio::test]
async fn missing_asset_digest_stays_none_and_extra_fields_are_tolerated() -> TestResult {
    let fake = FakeTransport::default();
    let digest = format!("sha256:{}", "ab".repeat(32));
    let mut nulled = asset(3, "tool_1.0.0_arm64.deb", None);
    if let Some(object) = nulled.as_object_mut() {
        object.insert("digest".to_owned(), Value::Null);
    }
    let mut body = release(
        500,
        "v1.0.0",
        vec![
            asset(1, "tool_1.0.0_amd64.deb", Some(&digest)),
            asset(2, "tool-1.0.0-1.x86_64.rpm", None),
            nulled,
        ],
    );
    if let Some(object) = body.as_object_mut() {
        object.remove("immutable");
    }
    fake.push(response(200, &body));

    let release = client(&fake)
        .latest_release(&pinned()?)
        .await?
        .ok_or("no release")?
        .value;
    assert_eq!(fake.paths(), ["/repositories/100/releases/latest"]);
    assert_eq!(release.id.get(), 500);
    assert_eq!(release.immutable, None);
    assert_eq!(release.assets.len(), 3);
    assert_eq!(
        release.assets[0].api_digest.map(|digest| digest.to_hex()),
        Some("ab".repeat(32))
    );
    assert_eq!(release.assets[1].api_digest, None);
    assert_eq!(release.assets[2].api_digest, None);
    assert!(
        release
            .assets
            .iter()
            .all(|asset| asset.uploaded && asset.size == 123_456)
    );
    Ok(())
}

#[tokio::test]
async fn a_missing_required_field_is_an_error() -> TestResult {
    let cases: [(&str, Mutation); 4] = [
        ("repository id", |value| {
            if let Some(object) = value.as_object_mut() {
                object.remove("id");
            }
        }),
        ("owner id", |value| {
            if let Some(owner) = value.get_mut("owner").and_then(Value::as_object_mut) {
                owner.remove("id");
            }
        }),
        ("owner login", |value| {
            if let Some(owner) = value.get_mut("owner").and_then(Value::as_object_mut) {
                owner.remove("login");
            }
        }),
        ("full name", |value| {
            if let Some(object) = value.as_object_mut() {
                object.remove("full_name");
            }
        }),
    ];
    for (label, mutate) in cases {
        let fake = FakeTransport::default();
        let mut body = repository(100, 10, "alice", "tool");
        mutate(&mut body);
        fake.push(response(200, &body));
        let result = client(&fake).reconcile(&pinned()?).await;
        assert!(
            matches!(result, Err(GitHubError::Wire(WireError::Json { .. }))),
            "{label}: {result:?}"
        );
    }

    let fake = FakeTransport::default();
    let mut body = release(500, "v1.0.0", vec![asset(1, "a.deb", None)]);
    if let Some(asset) = body["assets"][0].as_object_mut() {
        asset.remove("size");
    }
    fake.push(response(200, &body));
    let result = client(&fake).latest_release(&pinned()?).await;
    assert!(matches!(result, Err(GitHubError::Wire(_))), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn mistyped_or_inconsistent_fields_are_errors() -> TestResult {
    let mutations: [(&str, Value); 5] = [
        ("id", json!(100.0)),
        ("id", json!("100")),
        ("id", json!(-100)),
        ("id", json!(0)),
        ("full_name", json!("mallory/tool")),
    ];
    for (field, replacement) in mutations {
        let fake = FakeTransport::default();
        let mut body = repository(100, 10, "alice", "tool");
        body[field] = replacement.clone();
        fake.push(response(200, &body));
        let result = client(&fake).reconcile(&pinned()?).await;
        assert!(
            matches!(result, Err(GitHubError::Wire(_))),
            "{field}={replacement}: {result:?}"
        );
    }

    for (field, replacement) in [
        ("size", json!(1.0)),
        ("size", json!(-1)),
        ("digest", json!("sha256:XYZ")),
        ("name", json!("../evil.deb")),
        ("browser_download_url", json!("http://github.com/x.deb")),
    ] {
        let fake = FakeTransport::default();
        let mut body = release(500, "v1.0.0", vec![asset(1, "a.deb", None)]);
        body["assets"][0][field] = replacement.clone();
        fake.push(response(200, &body));
        let result = client(&fake).latest_release(&pinned()?).await;
        assert!(
            matches!(result, Err(GitHubError::Wire(_))),
            "{field}={replacement}: {result:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_oversized_body_is_refused_before_parsing() -> TestResult {
    let fake = FakeTransport::default();
    // Not even JSON: a parse attempt would report a syntax error instead.
    fake.push(status_only(
        200,
        ResponseHeaders::default(),
        &"x".repeat(2_049),
    ));
    let client = GitHubClient::new(fake.clone(), None).with_config(ClientConfig {
        max_body_bytes: 2_048,
        ..ClientConfig::default()
    });
    let result = client.reconcile(&pinned()?).await;
    assert_eq!(
        result,
        Err(GitHubError::BodyTooLarge {
            length: 2_049,
            limit: 2_048
        })
    );
    assert_eq!(
        result.map_err(|error| error.reason_code()),
        Err(ReasonCode::EForgeUnavailable)
    );
    Ok(())
}

#[tokio::test]
async fn missing_releases_and_tags_are_none_and_tags_are_encoded() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(status_only(
        404,
        ResponseHeaders::default(),
        r#"{"message":"Not Found"}"#,
    ))
    .push(status_only(
        404,
        ResponseHeaders::default(),
        r#"{"message":"Not Found"}"#,
    ));
    let client = client(&fake);
    assert_eq!(client.latest_release(&pinned()?).await?, None);
    assert_eq!(
        client.release_by_tag(&pinned()?, "release/1.0+b").await?,
        None
    );
    assert_eq!(
        fake.paths(),
        [
            "/repositories/100/releases/latest",
            "/repositories/100/releases/tags/release%2F1.0%2Bb"
        ]
    );
    assert_eq!(
        client.release_by_tag(&pinned()?, "bad\ntag").await,
        Err(GitHubError::InvalidArgument("tag"))
    );
    Ok(())
}

// ---------------------------------------------------------- tag references

/// `github/github-mcp-server` v2.0.2 as observed on 2026-10-22.
const MCP_REPOSITORY: u64 = 942_771_284;
const MCP_TAG_OBJECT: &str = "503622d154b505a9cebff296a13bc6c9259ea993";
const MCP_COMMIT: &str = "eb47a99ddb866ca2b8a162920e6bda9521f33ebb";

fn tag_ref_body(tag: &str, sha: &str, kind: &str) -> Value {
    json!({
        "ref": format!("refs/tags/{tag}"),
        "node_id": "REF_synthetic",
        "url": format!("https://api.github.com/repos/alice/tool/git/refs/tags/{tag}"),
        "object": {
            "sha": sha,
            "type": kind,
            "url": format!("https://api.github.com/repos/alice/tool/git/tags/{sha}")
        }
    })
}

fn tag_object_body(sha: &str, tag: &str, target: &str, kind: &str) -> Value {
    json!({
        "node_id": "TAG_synthetic",
        "sha": sha,
        "url": format!("https://api.github.com/repos/alice/tool/git/tags/{sha}"),
        "tagger": {"name": "alice", "email": "alice@example.invalid", "date": "2026-10-01T12:00:00Z"},
        "object": {"sha": target, "type": kind, "url": "https://api.github.com/x"},
        "tag": tag,
        "message": "v2.0.2\n",
        "verification": {"verified": false, "reason": "unsigned"}
    })
}

fn mcp() -> Result<RepositoryId, Box<dyn Error>> {
    Ok(RepositoryId::new(MCP_REPOSITORY)?)
}

#[tokio::test]
async fn a_lightweight_tag_names_its_commit() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(response(200, &tag_ref_body("v1.0.0", MCP_COMMIT, "commit")))
        .push(response(200, &tag_ref_body("v1.0.0", MCP_COMMIT, "commit")));
    let client = client(&fake);
    let fetched = client
        .tag_ref(mcp()?, "v1.0.0")
        .await?
        .ok_or("tag missing")?;
    assert_eq!(fetched.freshness, Freshness::Modified);
    assert_eq!(
        fetched.value,
        TagRef {
            ref_name: "refs/tags/v1.0.0".to_owned(),
            object: GitObjectId::from_hex(MCP_COMMIT)?,
            kind: TagObjectKind::Commit,
        }
    );
    assert_eq!(
        client.peeled_commit(mcp()?, "v1.0.0").await?,
        Some(GitObjectId::from_hex(MCP_COMMIT)?)
    );
    // A lightweight tag needs no tag-object read.
    assert_eq!(
        fake.paths(),
        [
            "/repositories/942771284/git/ref/tags/v1.0.0",
            "/repositories/942771284/git/ref/tags/v1.0.0"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn an_annotated_tag_ref_is_the_tag_object_and_peels_to_the_commit() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(response(
        200,
        &tag_ref_body("v2.0.2", MCP_TAG_OBJECT, "tag"),
    ))
    .push(response(
        200,
        &tag_ref_body("v2.0.2", MCP_TAG_OBJECT, "tag"),
    ))
    .push(response(
        200,
        &tag_object_body(MCP_TAG_OBJECT, "v2.0.2", MCP_COMMIT, "commit"),
    ));
    let client = client(&fake);
    let reference = client
        .tag_ref(mcp()?, "v2.0.2")
        .await?
        .ok_or("tag missing")?
        .value;
    // Never peeled: the Strict check needs the tag object itself.
    assert_eq!(reference.object, GitObjectId::from_hex(MCP_TAG_OBJECT)?);
    assert_eq!(reference.kind, TagObjectKind::Tag);
    assert_eq!(
        client.peeled_commit(mcp()?, "v2.0.2").await?,
        Some(GitObjectId::from_hex(MCP_COMMIT)?)
    );
    assert_eq!(
        fake.paths(),
        [
            "/repositories/942771284/git/ref/tags/v2.0.2",
            "/repositories/942771284/git/ref/tags/v2.0.2",
            format!("/repositories/942771284/git/tags/{MCP_TAG_OBJECT}").as_str()
        ]
    );
    Ok(())
}

#[tokio::test]
async fn a_ref_for_another_tag_is_refused() -> TestResult {
    let fake = FakeTransport::default();
    // GitHub's prefix match: `v1` answered with `v1.0.0`.
    fake.push(response(200, &tag_ref_body("v1.0.0", MCP_COMMIT, "commit")))
        .push(response(
            200,
            &json!({"ref": "refs/heads/v1", "object": {"sha": MCP_COMMIT, "type": "commit"}}),
        ))
        .push(response(
            200,
            &json!([tag_ref_body("v1.0.0", MCP_COMMIT, "commit")]),
        ));
    let client = client(&fake);
    assert!(matches!(
        client.tag_ref(mcp()?, "v1").await,
        Err(GitHubError::Wire(WireError::Invalid { field: "ref", .. }))
    ));
    assert!(matches!(
        client.tag_ref(mcp()?, "v1").await,
        Err(GitHubError::Wire(WireError::Invalid { field: "ref", .. }))
    ));
    assert!(matches!(
        client.tag_ref(mcp()?, "v1").await,
        Err(GitHubError::Wire(WireError::Json { .. }))
    ));
    Ok(())
}

#[tokio::test]
async fn a_tag_naming_a_tree_or_blob_is_refused() -> TestResult {
    let fake = FakeTransport::default();
    for kind in ["tree", "blob", "Commit"] {
        fake.push(response(200, &tag_ref_body("v1", MCP_COMMIT, kind)));
    }
    let client = client(&fake);
    for kind in ["tree", "blob", "Commit"] {
        assert_eq!(
            client.tag_ref(mcp()?, "v1").await,
            Err(GitHubError::Wire(WireError::Invalid {
                field: "object.type",
                problem: "neither a commit nor a tag",
            })),
            "{kind}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn uppercase_or_short_object_ids_are_refused() -> TestResult {
    let fake = FakeTransport::default();
    let upper = MCP_COMMIT.to_ascii_uppercase();
    let short = &MCP_COMMIT[..7];
    fake.push(response(200, &tag_ref_body("v1", &upper, "commit")))
        .push(response(200, &tag_ref_body("v1", short, "commit")))
        .push(response(200, &tag_ref_body("v1", MCP_TAG_OBJECT, "tag")))
        .push(response(
            200,
            &tag_object_body(MCP_TAG_OBJECT, "v1", short, "commit"),
        ));
    let client = client(&fake);
    for _ in 0..2 {
        assert!(matches!(
            client.tag_ref(mcp()?, "v1").await,
            Err(GitHubError::Wire(WireError::Invalid {
                field: "object.sha",
                ..
            }))
        ));
    }
    assert!(matches!(
        client.peeled_commit(mcp()?, "v1").await,
        Err(GitHubError::Wire(WireError::Invalid {
            field: "object.sha",
            ..
        }))
    ));
    Ok(())
}

#[tokio::test]
async fn a_tag_of_a_tag_is_not_peeled() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(response(
        200,
        &tag_ref_body("v2.0.2", MCP_TAG_OBJECT, "tag"),
    ))
    .push(response(
        200,
        &tag_object_body(MCP_TAG_OBJECT, "v2.0.2", MCP_COMMIT, "tag"),
    ));
    let client = client(&fake);
    assert!(matches!(
        client.peeled_commit(mcp()?, "v2.0.2").await,
        Err(GitHubError::Wire(WireError::Invalid {
            field: "object.type",
            ..
        }))
    ));
    // Exactly one tag-object read, no second level.
    assert_eq!(fake.paths().len(), 2);
    Ok(())
}

#[tokio::test]
async fn a_tag_object_for_another_tag_or_sha_is_refused() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(response(
        200,
        &tag_ref_body("v2.0.2", MCP_TAG_OBJECT, "tag"),
    ))
    .push(response(
        200,
        &tag_object_body(MCP_TAG_OBJECT, "v2.0.1", MCP_COMMIT, "commit"),
    ))
    .push(response(
        200,
        &tag_ref_body("v2.0.2", MCP_TAG_OBJECT, "tag"),
    ))
    .push(response(
        200,
        &tag_object_body(MCP_COMMIT, "v2.0.2", MCP_COMMIT, "commit"),
    ));
    let client = client(&fake);
    assert!(matches!(
        client.peeled_commit(mcp()?, "v2.0.2").await,
        Err(GitHubError::Wire(WireError::Invalid { field: "tag", .. }))
    ));
    assert!(matches!(
        client.peeled_commit(mcp()?, "v2.0.2").await,
        Err(GitHubError::Wire(WireError::Invalid { field: "sha", .. }))
    ));
    Ok(())
}

#[tokio::test]
async fn tag_refs_are_encoded_per_segment_and_missing_tags_are_none() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(response(
        200,
        &tag_ref_body("release/1.0+b", MCP_COMMIT, "commit"),
    ))
    .push(status_only(
        404,
        ResponseHeaders::default(),
        r#"{"message":"Not Found"}"#,
    ))
    .push(status_only(
        404,
        ResponseHeaders::default(),
        r#"{"message":"Not Found"}"#,
    ));
    let client = client(&fake);
    let fetched = client
        .tag_ref(mcp()?, "release/1.0+b")
        .await?
        .ok_or("tag missing")?;
    assert_eq!(fetched.value.ref_name, "refs/tags/release/1.0+b");
    assert_eq!(client.tag_ref(mcp()?, "v9").await?, None);
    assert_eq!(client.peeled_commit(mcp()?, "v9").await?, None);
    assert_eq!(
        fake.paths(),
        [
            "/repositories/942771284/git/ref/tags/release/1.0%2Bb",
            "/repositories/942771284/git/ref/tags/v9",
            "/repositories/942771284/git/ref/tags/v9"
        ]
    );
    for tag in ["", "bad\ntag", "a//b", "/v1"] {
        assert_eq!(
            client.tag_ref(mcp()?, tag).await,
            Err(GitHubError::InvalidArgument("tag")),
            "{tag:?}"
        );
    }
    // Refused before any request.
    assert_eq!(fake.paths().len(), 3);
    Ok(())
}

// ----------------------------------------------------------- rate limits

#[tokio::test]
async fn primary_exhaustion_stops_requests_until_reset() -> TestResult {
    let clock = TestClock::new();
    let fake = FakeTransport::default();
    let reset = NOW + 900;
    fake.push(status_only(
        403,
        ResponseHeaders {
            ratelimit_limit: Some("60".to_owned()),
            ratelimit_remaining: Some("0".to_owned()),
            ratelimit_reset: Some(reset.to_string()),
            ratelimit_resource: Some("core".to_owned()),
            ..ResponseHeaders::default()
        },
        r#"{"message":"API rate limit exceeded for 192.0.2.1."}"#,
    ))
    .push(response(200, &repository(100, 10, "alice", "tool")));
    let client = GitHubClient::new(fake.clone(), None).with_clock(clock.clone());
    let expected = RateLimited {
        kind: RateLimitKind::Primary,
        until: UNIX_EPOCH + Duration::from_secs(reset),
    };

    assert_eq!(
        client.reconcile(&pinned()?).await,
        Err(GitHubError::RateLimited(expected))
    );
    assert_eq!(client.quota().remaining, Some(0));
    // No retry storm: further calls fail locally without a request.
    for _ in 0..50 {
        assert_eq!(
            client.reconcile(&pinned()?).await,
            Err(GitHubError::RateLimited(expected))
        );
    }
    assert_eq!(fake.requests().len(), 1);

    clock.advance(Duration::from_secs(900));
    assert_eq!(
        client.reconcile(&pinned()?).await?,
        IdentityOutcome::Unchanged
    );
    assert_eq!(fake.requests().len(), 2);
    assert_eq!(
        GitHubError::RateLimited(expected).reason_code(),
        ReasonCode::EForgeUnavailable
    );
    Ok(())
}

#[tokio::test]
async fn a_success_that_exhausts_the_quota_blocks_the_next_request() -> TestResult {
    let clock = TestClock::new();
    let fake = FakeTransport::default();
    let mut last = response(200, &repository(100, 10, "alice", "tool"));
    last.headers.ratelimit_remaining = Some("0".to_owned());
    last.headers.ratelimit_reset = Some((NOW + 60).to_string());
    fake.push(last);
    let client = GitHubClient::new(fake.clone(), None).with_clock(clock.clone());

    assert_eq!(
        client.reconcile(&pinned()?).await?,
        IdentityOutcome::Unchanged
    );
    assert!(matches!(
        client.reconcile(&pinned()?).await,
        Err(GitHubError::RateLimited(RateLimited {
            kind: RateLimitKind::Primary,
            ..
        }))
    ));
    assert_eq!(fake.requests().len(), 1);
    Ok(())
}

#[tokio::test]
async fn secondary_limits_honour_retry_after_and_back_off() -> TestResult {
    let clock = TestClock::new();
    let fake = FakeTransport::default();
    fake.push(status_only(
        429,
        ResponseHeaders {
            retry_after: Some("30".to_owned()),
            ..ResponseHeaders::default()
        },
        "",
    ))
    .push(status_only(
        403,
        ResponseHeaders::default(),
        r#"{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}"#,
    ))
    .push(status_only(403, ResponseHeaders::default(), r#"{"message":"You have exceeded a secondary rate limit."}"#));
    let client = GitHubClient::new(fake.clone(), None).with_clock(clock.clone());
    let at = |seconds: u64| UNIX_EPOCH + Duration::from_secs(seconds);

    let first = client.reconcile(&pinned()?).await;
    assert_eq!(
        first,
        Err(GitHubError::RateLimited(RateLimited {
            kind: RateLimitKind::Secondary,
            until: at(NOW + 30)
        }))
    );
    clock.advance(Duration::from_secs(30));
    let second = client.reconcile(&pinned()?).await;
    assert_eq!(
        second,
        Err(GitHubError::RateLimited(RateLimited {
            kind: RateLimitKind::Secondary,
            until: at(NOW + 30 + 60)
        }))
    );
    clock.advance(Duration::from_secs(60));
    let third = client.reconcile(&pinned()?).await;
    assert_eq!(
        third,
        Err(GitHubError::RateLimited(RateLimited {
            kind: RateLimitKind::Secondary,
            until: at(NOW + 90 + 120)
        }))
    );
    assert_eq!(fake.requests().len(), 3);
    Ok(())
}

#[tokio::test]
async fn a_plain_403_is_forbidden_not_a_rate_limit() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(status_only(
        403,
        ResponseHeaders {
            ratelimit_remaining: Some("42".to_owned()),
            ..ResponseHeaders::default()
        },
        r#"{"message":"Resource not accessible by integration"}"#,
    ))
    .push(response(200, &repository(100, 10, "alice", "tool")));
    let client = client(&fake);
    assert_eq!(
        client.reconcile(&pinned()?).await,
        Err(GitHubError::Forbidden)
    );
    assert_eq!(
        client.reconcile(&pinned()?).await?,
        IdentityOutcome::Unchanged
    );
    Ok(())
}

// ------------------------------------------------------------ pagination

fn release_page(first_id: u64, count: u64, next_page: Option<u32>) -> ApiResponse {
    let releases: Vec<Value> = (first_id..first_id + count)
        .map(|id| release(id, &format!("v{id}"), vec![asset(id * 10, "a.deb", None)]))
        .collect();
    let mut page = response(200, &Value::Array(releases));
    page.headers.link = next_page.map(|next| {
        format!(
            "<https://api.github.com/repositories/100/releases?per_page=2&page={next}>; rel=\"next\", <https://api.github.com/repositories/100/releases?per_page=2&page=9>; rel=\"last\""
        )
    });
    page
}

fn small_pages(fake: &FakeTransport, max_pages: u32) -> GitHubClient<FakeTransport> {
    GitHubClient::new(fake.clone(), None).with_config(ClientConfig {
        per_page: 2,
        max_pages,
        ..ClientConfig::default()
    })
}

#[tokio::test]
async fn pages_are_followed_until_the_last() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(release_page(1, 2, Some(2)))
        .push(release_page(3, 2, Some(3)))
        .push(release_page(5, 1, None));
    let listing = small_pages(&fake, 10).list_releases(&pinned()?).await?;
    assert_eq!(listing.releases.len(), 5);
    assert!(!listing.truncated);
    assert!(!listing.unchanged);
    assert_eq!(
        fake.paths(),
        [
            "/repositories/100/releases?per_page=2",
            "/repositories/100/releases?per_page=2&page=2",
            "/repositories/100/releases?per_page=2&page=3"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn the_page_cap_truncates_without_further_requests() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(release_page(1, 2, Some(2)))
        .push(release_page(3, 2, Some(3)))
        .push(release_page(5, 2, Some(4)));
    let listing = small_pages(&fake, 2).list_releases(&pinned()?).await?;
    assert_eq!(listing.releases.len(), 4);
    assert!(listing.truncated);
    assert_eq!(fake.requests().len(), 2);
    Ok(())
}

#[tokio::test]
async fn a_looping_or_foreign_link_stops_pagination() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(release_page(1, 2, Some(1)));
    assert_eq!(
        small_pages(&fake, 10).list_releases(&pinned()?).await,
        Err(GitHubError::Pagination(PaginationError::UnexpectedPage))
    );

    let fake = FakeTransport::default();
    let mut page = release_page(1, 2, None);
    page.headers.link = Some(
        "<https://api.github.com/repositories/999/releases?per_page=2&page=2>; rel=\"next\""
            .to_owned(),
    );
    fake.push(page);
    assert_eq!(
        small_pages(&fake, 10).list_releases(&pinned()?).await,
        Err(GitHubError::Pagination(PaginationError::ForeignLink))
    );
    assert_eq!(fake.requests().len(), 1);
    Ok(())
}

#[tokio::test]
async fn unchanged_pages_reuse_their_verified_bodies() -> TestResult {
    let fake = FakeTransport::default();
    fake.push(with_etag(release_page(1, 2, Some(2)), "W/\"p1\""))
        .push(with_etag(release_page(3, 1, None), "W/\"p2\""))
        .push(not_modified(Some("W/\"p1\"")))
        .push(not_modified(Some("W/\"p2\"")));
    let client = small_pages(&fake, 10);
    let first = client.list_releases(&pinned()?).await?;
    let second = client.list_releases(&pinned()?).await?;
    assert!(!first.unchanged);
    assert!(second.unchanged);
    assert_eq!(second.releases, first.releases);
    let requests = fake.requests();
    assert_eq!(requests[2].if_none_match(), Some("W/\"p1\""));
    assert_eq!(requests[3].if_none_match(), Some("W/\"p2\""));
    Ok(())
}

// ---------------------------------------------------------------- tokens

#[tokio::test]
async fn the_token_reaches_only_the_request_and_never_debug_output() -> TestResult {
    const SECRET: &str = "sample-credential-value-0123456789";
    let fake = FakeTransport::default();
    fake.push(status_only(
        401,
        ResponseHeaders::default(),
        r#"{"message":"Bad credentials"}"#,
    ));
    let client = GitHubClient::new(fake.clone(), Some(Token::new(SECRET.to_owned())?));
    let result = client.reconcile(&pinned()?).await;
    assert_eq!(result, Err(GitHubError::Unauthorized));

    let request = &fake.requests()[0];
    assert_eq!(request.token().map(Token::expose_secret), Some(SECRET));
    assert!(!request.path().contains(SECRET));
    for text in [
        format!("{request:?}"),
        format!("{client:?}"),
        format!("{result:?}"),
        result
            .map_err(|error| error.to_string())
            .err()
            .unwrap_or_default(),
    ] {
        assert!(!text.contains(SECRET), "{text}");
    }
    Ok(())
}
