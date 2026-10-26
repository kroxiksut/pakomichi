// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::*;
use crate::attest::{SignerRef, TrustedRoots, ensure_crypto_provider};
use crate::github::{ApiRequest, ApiResponse, ResponseHeaders, TransportError};
use crate::ipc::protocol::{ActivationPolicy, SourceActivate, SourceAdd};
use crate::state::test_support::TempDir;
use crate::sync::selection::SourceAptView;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const URL: &str = "https://github.com/kroxiksut/pchi-test";
const REPO_ID: u64 = 1_429_109_739;
/// Release v0.1.0 of the owner's test repository, recorded by R-003: the
/// release attestation and the SLSA provenance of its one asset.
const V1: &str = include_str!("../../tests/data/attest/pchi-test-v0.1.0.jsonl");
/// The SLSA provenance of the fork `kroxiksut/pchi-test-fork` (same owner).
const FORK: &str = include_str!("../../tests/data/attest/pchi-test-fork-v0.3.0.jsonl");
const COMMIT: &str = "6ee0f9f53e5a296bd19904188d055608f32ffd82";
const ASSET_SHA256: &str = "8fcda58d824b4fea8f98e036083f398f497941af4b8c15de5dac02dd900576fd";
const SIGNER: &str = ".github/workflows/immutable-release.yml@refs/heads/main";

/// GitHub as far as `source add` needs it: the repository behind a name,
/// its latest release, the release tag and the attestations of the asset.
#[derive(Clone, Default)]
struct FakeGitHub(Arc<Mutex<FakeState>>);

#[derive(Default)]
struct FakeState {
    repository_id: u64,
    requests: usize,
    /// Serve release v0.1.0 as the latest release.
    release: bool,
    /// The listing for the asset's digest, as GitHub sends it.
    attestations: Vec<Value>,
}

fn bundles(fixture: &str) -> Vec<Value> {
    fixture
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

impl FakeGitHub {
    fn serving(repository_id: u64) -> Self {
        let fake = Self::default();
        fake.with(|state| state.repository_id = repository_id);
        fake
    }

    fn with(&self, change: impl FnOnce(&mut FakeState)) {
        change(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner));
    }

    fn set(&self, repository_id: u64) {
        self.with(|state| state.repository_id = repository_id);
    }

    /// Release v0.1.0 with these bundles listed under this repository's ID.
    fn release_with(&self, listed: Vec<Value>) {
        self.with(|state| {
            state.release = true;
            state.attestations = listed;
        });
    }

    fn requests(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .requests
    }
}

fn answer(status: u16, body: &Value) -> ApiResponse {
    ApiResponse {
        status,
        headers: ResponseHeaders::default(),
        body: body.to_string().into_bytes(),
    }
}

impl Transport for FakeGitHub {
    async fn send(
        &self,
        request: ApiRequest,
        _max_body_bytes: usize,
    ) -> Result<ApiResponse, TransportError> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.requests += 1;
        let not_found = || answer(404, &json!({"message": "Not Found"}));
        let path = request.path();
        let repository = format!("/repositories/{REPO_ID}");
        if path == "/repos/kroxiksut/pchi-test" {
            return Ok(answer(
                200,
                &json!({
                    "id": state.repository_id,
                    "node_id": "R_synthetic",
                    "name": "pchi-test",
                    "full_name": "kroxiksut/pchi-test",
                    "private": false,
                    "owner": {"login": "kroxiksut", "id": 2_264_172, "type": "User"},
                    "html_url": URL,
                    "fork": false,
                    "archived": false,
                    "default_branch": "main"
                }),
            ));
        }
        if path == format!("{repository}/releases/latest") {
            if !state.release {
                return Ok(not_found());
            }
            return Ok(answer(
                200,
                &json!({
                    "id": 420_324_447,
                    "tag_name": "v0.1.0",
                    "target_commitish": "main",
                    "draft": false,
                    "prerelease": false,
                    "immutable": true,
                    "published_at": "2026-10-22T05:00:23Z",
                    "assets": [{
                        "id": 664_728_438,
                        "name": "pakomichi-r003-fixture_0.1.0_all.deb",
                        "size": 800,
                        "digest": format!("sha256:{ASSET_SHA256}"),
                        "state": "uploaded",
                        "browser_download_url": "https://github.com/kroxiksut/pchi-test/releases/download/v0.1.0/pakomichi-r003-fixture_0.1.0_all.deb"
                    }]
                }),
            ));
        }
        if path == format!("{repository}/git/ref/tags/v0.1.0") {
            return Ok(answer(
                200,
                &json!({"ref": "refs/tags/v0.1.0", "object": {"sha": COMMIT, "type": "commit"}}),
            ));
        }
        if path == format!("{repository}/attestations/sha256:{ASSET_SHA256}?per_page=100") {
            let listed: Vec<Value> = state
                .attestations
                .iter()
                .map(|bundle| json!({"repository_id": REPO_ID, "bundle": bundle}))
                .collect();
            return Ok(answer(200, &json!({ "attestations": listed })));
        }
        Err(TransportError::Connect)
    }
}

fn now() -> String {
    "2026-10-24T12:00:00Z".to_owned()
}

struct Bed {
    _dir: TempDir,
    _runtime: tokio::runtime::Runtime,
    github: FakeGitHub,
    service: StateService<FakeGitHub>,
}

fn bed_with(roots: bool) -> Result<Bed, Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let github = FakeGitHub::serving(REPO_ID);
    let owner = StateOwner::open(&dir.join("state.db"))?;
    let verifier = if roots {
        ensure_crypto_provider()?;
        Some(Arc::new(AttestationVerifier::new(
            &TrustedRoots::embedded()?,
        )?))
    } else {
        None
    };
    let service = StateService::new(
        Arc::new(Mutex::new(owner)),
        GitHubClient::new(github.clone(), None),
        verifier,
        runtime.handle().clone(),
        now,
    )?;
    Ok(Bed {
        _dir: dir,
        _runtime: runtime,
        github,
        service,
    })
}

fn bed() -> Result<Bed, Box<dyn std::error::Error>> {
    bed_with(true)
}

fn add(observe: bool) -> AdminAction {
    add_naming(observe, None)
}

fn add_naming(observe: bool, signer: Option<&str>) -> AdminAction {
    AdminAction::SourceAdd(SourceAdd {
        url: URL.to_owned(),
        observe,
        signer: signer.map(str::to_owned),
    })
}

#[test]
fn a_confirmed_plan_adds_the_source_and_the_signer_it_showed() -> TestResult {
    let bed = bed()?;
    bed.github.release_with(bundles(V1));
    let plan = bed.service.plan(&add(false)).map_err(|r| r.message)?;
    let kinds: Vec<ChangeKind> = plan.changes.iter().map(|change| change.kind).collect();
    assert_eq!(kinds, [ChangeKind::AddSource, ChangeKind::SetSigner]);
    assert_eq!(plan.changes[1].after.as_deref(), Some(SIGNER));
    assert!(
        plan.summary.contains("nothing is activated"),
        "{}",
        plan.summary
    );
    assert!(bed.service.sources().is_empty(), "a plan writes nothing");
    let outcome = bed
        .service
        .run(&add(false), &plan)
        .map_err(|outcome| outcome.message)?;
    assert_eq!(
        outcome.message,
        format!("added source github-1429109739 with Attested signer {SIGNER}")
    );
    let sources = bed.service.sources();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].state, "registered");
    assert_eq!(sources[0].signer.as_deref(), Some(SIGNER));
    assert!(sources[0].activated.is_empty());
    Ok(())
}

#[test]
fn a_provenance_of_another_repository_never_becomes_the_signer() -> TestResult {
    // The listing says "this repository", but the certificate names the
    // fork: the listing is not evidence, the verified certificate is.
    let bed = bed()?;
    bed.github.release_with(bundles(FORK));
    let plan = bed.service.plan(&add(false)).map_err(|r| r.message)?;
    assert_eq!(plan.changes.len(), 1, "{:?}", plan.changes);
    assert!(
        plan.summary.contains("no Attested signer") && plan.summary.contains("Strict or Pinned"),
        "{}",
        plan.summary
    );
    bed.service
        .run(&add(false), &plan)
        .map_err(|outcome| outcome.message)?;
    assert_eq!(bed.service.sources()[0].signer, None);
    Ok(())
}

#[test]
fn a_source_without_a_release_or_roots_is_added_without_a_signer() -> TestResult {
    for (roots, release, why) in [
        (true, false, "no published release"),
        (false, true, "trusted roots are not available"),
    ] {
        let bed = bed_with(roots)?;
        if release {
            bed.github.release_with(bundles(V1));
        }
        let plan = bed.service.plan(&add(false)).map_err(|r| r.message)?;
        assert_eq!(plan.changes.len(), 1);
        assert!(plan.summary.contains(why), "{}", plan.summary);
    }
    Ok(())
}

#[test]
fn a_named_signer_must_agree_with_the_verified_one() -> TestResult {
    let bed = bed()?;
    bed.github.release_with(bundles(V1));
    // Another workflow of the same repository is not what signed it.
    let other = ".github/workflows/other.yml@refs/heads/main";
    let refused = bed.service.plan(&add_naming(false, Some(other)));
    assert!(
        matches!(&refused, Err(r) if r.message.contains(SIGNER) && r.message.contains(other)),
        "{refused:?}"
    );
    let plan = bed
        .service
        .plan(&add_naming(false, Some(SIGNER)))
        .map_err(|r| r.message)?;
    assert_eq!(plan.changes[1].after.as_deref(), Some(SIGNER));
    // Before the first attested release, a named signer is taken as named.
    let early = bed_with(true)?;
    let plan = early
        .service
        .plan(&add_naming(false, Some(other)))
        .map_err(|r| r.message)?;
    assert_eq!(plan.changes[1].after.as_deref(), Some(other));
    assert!(
        plan.summary.contains("not seen in a release yet"),
        "{}",
        plan.summary
    );
    // Not a signer at all.
    assert!(
        bed.service
            .plan(&add_naming(false, Some("release.yml@tag")))
            .is_err()
    );
    Ok(())
}

#[test]
fn discovery_never_chooses_between_two_signers() -> TestResult {
    let signer = |workflow: &str| {
        AttestedSigner::new(workflow, SignerRef::ReleaseTag).map_err(|_| "bad workflow")
    };
    let a = signer(".github/workflows/a.yml")?;
    let b = signer(".github/workflows/b.yml")?;
    let c = signer(".github/workflows/c.yml")?;
    let both = || Discovery::Ambiguous(vec![a.clone(), b.clone()]);
    assert!(choose_signer(None, both()).is_err());
    assert!(choose_signer(Some(c), both()).is_err());
    let (chosen, _) = choose_signer(Some(b.clone()), both()).map_err(|r| r.message)?;
    assert_eq!(chosen, Some(b));
    Ok(())
}

#[test]
fn another_repository_behind_the_address_at_run_time_is_not_added() -> TestResult {
    // Between the plan and the confirmation the name was taken over: the
    // administrator confirmed repository 1429109739, not this one.
    let bed = bed()?;
    let plan = bed.service.plan(&add(false)).map_err(|r| r.message)?;
    bed.github.set(7);
    let refused = bed.service.run(&add(false), &plan);
    assert!(
        matches!(&refused, Err(outcome) if outcome.message.contains("changed since the plan")),
        "{refused:?}"
    );
    assert!(bed.service.sources().is_empty());
    Ok(())
}

#[test]
fn a_repository_that_is_already_a_source_is_refused_at_plan() -> TestResult {
    let bed = bed()?;
    let plan = bed.service.plan(&add(true)).map_err(|r| r.message)?;
    bed.service.run(&add(true), &plan).map_err(|o| o.message)?;
    let again = bed.service.plan(&add(false));
    assert!(
        matches!(&again, Err(refusal) if refusal.message.contains("already source github-1429109739")),
        "{again:?}"
    );
    assert_eq!(bed.service.sources()[0].state, "observing");
    Ok(())
}

#[test]
fn an_address_that_is_not_a_plain_github_repository_asks_nobody() -> TestResult {
    let bed = bed()?;
    for url in [
        "https://token@github.com/kroxiksut/pchi-test",
        "http://github.com/kroxiksut/pchi-test",
        "https://github.com.evil.example/kroxiksut/pchi-test",
    ] {
        let action = AdminAction::SourceAdd(SourceAdd {
            url: url.to_owned(),
            observe: false,
            signer: None,
        });
        assert!(bed.service.plan(&action).is_err(), "{url}");
    }
    assert_eq!(bed.github.requests(), 0, "no request for a refused address");
    Ok(())
}

#[test]
fn a_plan_asked_during_an_operation_is_refused_at_once() -> TestResult {
    let bed = bed()?;
    let _running = bed
        .service
        .owner
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let refused = bed.service.plan(&add(false));
    assert!(
        matches!(&refused, Err(refusal) if refusal.message.contains("another operation")),
        "{refused:?}"
    );
    // Status is still answered from the snapshot.
    assert!(bed.service.sources().is_empty());
    Ok(())
}

#[test]
fn actions_of_later_steps_are_refused_and_change_nothing() -> TestResult {
    let bed = bed()?;
    let activate = AdminAction::SourceActivate(SourceActivate {
        source_id: "github-1429109739".to_owned(),
        packages: vec!["sampleapp".to_owned()],
        policy: ActivationPolicy::Supplemental,
    });
    assert!(bed.service.plan(&activate).is_err());
    assert!(bed.service.run(&activate, &Plan::default()).is_err());
    assert!(bed.service.sources().is_empty());
    Ok(())
}

// ------------------------------------------------- activation and sync

/// The pipeline as far as the service sees it: which sources ran, and
/// whether the APT configuration was applied.
#[derive(Clone)]
struct FakePipeline {
    calls: Arc<Mutex<Vec<String>>>,
    failing: Option<String>,
    /// What APT's choice looks like; `Err`: APT could not be asked.
    apt: Arc<Mutex<Result<BTreeMap<String, SourceAptView>, String>>>,
    /// The families whose pins the configuration held back.
    held: Arc<Mutex<Vec<crate::sync::publish::HeldFamily>>>,
}

impl Default for FakePipeline {
    fn default() -> Self {
        Self {
            calls: Arc::default(),
            failing: None,
            apt: Arc::new(Mutex::new(Ok(BTreeMap::new()))),
            held: Arc::default(),
        }
    }
}

impl FakePipeline {
    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Pipeline for FakePipeline {
    fn synchronize(
        &self,
        _owner: &mut StateOwner,
        source_id: &str,
        _at: &str,
        force: bool,
    ) -> Result<crate::sync::SyncReport, crate::sync::SyncError> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(if force {
                format!("sync {source_id} --force")
            } else {
                format!("sync {source_id}")
            });
        if self.failing.as_deref() == Some(source_id) {
            return Err(crate::sync::SyncError::GitHub("connect: refused".into()));
        }
        Ok(crate::sync::SyncReport {
            source_id: source_id.to_owned(),
            ..crate::sync::SyncReport::default()
        })
    }

    fn configure(
        &self,
        _owner: &mut StateOwner,
        _at: &str,
    ) -> Result<crate::sync::publish::Configured, String> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push("configure".to_owned());
        Ok(crate::sync::publish::Configured {
            ended: crate::apt::operation::Ended::Verified {
                changed: Vec::new(),
            },
            held: self
                .held
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        })
    }

    fn loopback_port(&self) -> u16 {
        879
    }

    fn apt_view(&self, _owner: &mut StateOwner) -> Result<BTreeMap<String, SourceAptView>, String> {
        self.apt
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

const SOURCE: &str = "github-1429109739";

fn added(observe: bool, pipeline: &FakePipeline) -> Result<Bed, Box<dyn std::error::Error>> {
    let bed = bed()?;
    let plan = bed.service.plan(&add(observe)).map_err(|r| r.message)?;
    bed.service
        .run(&add(observe), &plan)
        .map_err(|outcome| outcome.message)?;
    let Bed {
        _dir,
        _runtime,
        github,
        service,
    } = bed;
    Ok(Bed {
        _dir,
        _runtime,
        github,
        service: service.with_pipeline(Box::new(pipeline.clone()))?,
    })
}

/// What a first synchronization records: a proposed family and the
/// artifacts of `names`.
fn synchronized(bed: &Bed, names: &[&str]) -> TestResult {
    use crate::cas::Sha256Digest;
    use crate::family::{Family, MemberKey};
    use crate::inventory::Ecosystem;
    use crate::state::{ArtifactRow, ArtifactState, ReleaseRow};
    let mut owner = bed
        .service
        .owner
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let members = names.iter().map(|name| {
        (
            MemberKey::new(Ecosystem::Deb, name),
            ["all".to_owned()].into_iter().collect(),
        )
    });
    let family_id = owner.save_family(SOURCE, &Family::proposed(members)?)?;
    let release = owner.record_release(
        SOURCE,
        &ReleaseRow {
            forge_release_id: 1,
            tag: "v1.0",
            commit: None,
            published_at: "2026-10-24T10:00:00Z",
            channel: "stable",
            immutable: true,
        },
    )?;
    for (index, name) in names.iter().enumerate() {
        let filename = format!("{name}_1.0-1_all.deb");
        owner.record_artifact(
            SOURCE,
            &ArtifactRow {
                release_row: &release,
                asset_id: 100 + index as u64,
                family_id: &family_id,
                ecosystem: Ecosystem::Deb,
                name,
                version: "1.0-1",
                architecture: "all",
                filename: &filename,
                sha256: Sha256Digest::of(name.as_bytes()),
                size: 10,
            },
            None,
            ArtifactState::Held,
        )?;
    }
    Ok(())
}

fn activate(names: &[&str]) -> AdminAction {
    AdminAction::SourceActivate(SourceActivate {
        source_id: SOURCE.to_owned(),
        packages: names.iter().map(|name| (*name).to_owned()).collect(),
        policy: ActivationPolicy::Supplemental,
    })
}

#[test]
fn an_activation_needs_a_synchronized_source_and_a_name_it_offered() -> TestResult {
    let pipeline = FakePipeline::default();
    let bed = added(false, &pipeline)?;
    let never = bed.service.plan(&activate(&["sampleapp"]));
    assert!(
        matches!(&never, Err(r) if r.message.contains("run pchi sync github-1429109739 first")),
        "{never:?}"
    );
    synchronized(&bed, &["sampleapp", "sampleapp-data"])?;
    // A name the source never offered is not a typo to be guessed at.
    let unknown = bed.service.plan(&activate(&["sampleapp-tools"]));
    assert!(
        matches!(&unknown, Err(r) if r.message.contains("never offered sampleapp-tools")),
        "{unknown:?}"
    );
    assert!(pipeline.calls().is_empty(), "a plan runs nothing");
    Ok(())
}

#[test]
fn an_activation_approves_exactly_the_listed_names_at_the_shown_revision() -> TestResult {
    let pipeline = FakePipeline::default();
    let bed = added(false, &pipeline)?;
    synchronized(&bed, &["sampleapp", "sampleapp-data"])?;
    let plan = bed
        .service
        .plan(&activate(&["sampleapp"]))
        .map_err(|r| r.message)?;
    let approve = plan
        .changes
        .iter()
        .find(|change| change.kind == ChangeKind::ApproveFamily)
        .ok_or("no family change")?;
    assert_eq!(
        approve.before.as_deref(),
        Some("revision 1 proposed: sampleapp(all), sampleapp-data(all)")
    );
    assert_eq!(
        approve.after.as_deref(),
        Some("revision 2 approved: sampleapp(all)")
    );
    assert!(
        plan.summary.contains("sampleapp-data(all)"),
        "{}",
        plan.summary
    );
    bed.service
        .run(&activate(&["sampleapp"]), &plan)
        .map_err(|outcome| outcome.message)?;
    assert_eq!(
        pipeline.calls(),
        [format!("sync {SOURCE}"), "configure".to_owned()]
    );
    {
        let mut owner = bed
            .service
            .owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (_, family) = owner.family(SOURCE)?.ok_or("no family")?;
        let names: Vec<&str> = family
            .members()
            .keys()
            .map(|key| key.name.as_str())
            .collect();
        assert_eq!(names, ["sampleapp"], "the unlisted name stays outside");
    }
    // The same plan confirmed again is for an older revision now.
    let stale = bed.service.run(&activate(&["sampleapp"]), &plan);
    assert!(
        matches!(&stale, Err(outcome) if outcome.message.contains("changed since the plan")),
        "{stale:?}"
    );
    assert_eq!(pipeline.calls().len(), 2, "nothing ran for the stale plan");
    Ok(())
}

#[test]
fn an_observed_source_is_never_activated() -> TestResult {
    let pipeline = FakePipeline::default();
    let bed = added(true, &pipeline)?;
    synchronized(&bed, &["sampleapp"])?;
    let refused = bed.service.plan(&activate(&["sampleapp"]));
    assert!(
        matches!(&refused, Err(r) if r.message.contains("--observe")),
        "{refused:?}"
    );
    Ok(())
}

#[test]
fn one_failing_source_fails_the_operation_and_the_configuration_still_runs() -> TestResult {
    let pipeline = FakePipeline {
        failing: Some(SOURCE.to_owned()),
        ..FakePipeline::default()
    };
    let bed = added(false, &pipeline)?;
    let sync = AdminAction::Sync(crate::ipc::protocol::SyncTarget {
        source_id: None,
        force: false,
    });
    let plan = bed.service.plan(&sync).map_err(|r| r.message)?;
    assert_eq!(plan.changes.len(), 1);
    assert!(
        plan.summary.contains("nothing new is activated"),
        "{}",
        plan.summary
    );
    let Err(outcome) = bed.service.run(&sync, &plan) else {
        return Err("a failed source must fail the operation".into());
    };
    assert!(
        outcome.message.contains("not synchronized"),
        "{}",
        outcome.message
    );
    assert_eq!(
        outcome.reason_codes,
        [crate::error::ReasonCode::EForgeUnavailable]
    );
    assert_eq!(
        pipeline.calls(),
        [format!("sync {SOURCE}"), "configure".to_owned()]
    );
    Ok(())
}

// ------------------------------------------- what APT chooses (N-027)

fn sync_all() -> AdminAction {
    AdminAction::Sync(crate::ipc::protocol::SyncTarget {
        source_id: None,
        force: false,
    })
}

fn status_of(bed: &Bed) -> Result<SourceStatus, String> {
    bed.service
        .sources()
        .into_iter()
        .find(|source| source.source_id == SOURCE)
        .ok_or_else(|| "no source in the status".to_owned())
}

#[test]
fn n027_the_status_names_the_other_source_and_what_apt_does_not_keep() -> TestResult {
    use crate::apt::policy::{Finding, Notice};
    use crate::ipc::protocol::{AptProblem, UpdateElsewhere};
    let pipeline = FakePipeline::default();
    let bed = added(false, &pipeline)?;
    *pipeline.apt.lock().unwrap_or_else(PoisonError::into_inner) = Ok(BTreeMap::from([(
        SOURCE.to_owned(),
        SourceAptView {
            updates_elsewhere: vec![Notice {
                name: "sampleapp".to_owned(),
                version: "1.1-1".to_owned(),
                source: "http://deb.debian.org/debian-security bookworm-security/main".to_owned(),
            }],
            problems: vec![Finding::NotProtected {
                name: "sampleapp-data".to_owned(),
                candidate: Some("2.0-1".to_owned()),
                priority: Some(500),
            }],
        },
    )]));
    let plan = bed.service.plan(&sync_all()).map_err(|r| r.message)?;
    bed.service
        .run(&sync_all(), &plan)
        .map_err(|outcome| outcome.message)?;
    let status = status_of(&bed)?;
    assert_eq!(
        status.updates_elsewhere,
        [UpdateElsewhere {
            name: "sampleapp".to_owned(),
            version: "1.1-1".to_owned(),
            offered_by: "http://deb.debian.org/debian-security bookworm-security/main".to_owned(),
        }]
    );
    let [
        AptProblem {
            name: Some(name),
            reason_code: Some(code),
            message,
        },
    ] = status.apt_problems.as_slice()
    else {
        return Err(format!("{:?}", status.apt_problems).into());
    };
    assert_eq!(
        (name.as_str(), *code),
        (
            "sampleapp-data",
            crate::error::ReasonCode::EAdminApplyFailed
        )
    );
    assert!(message.contains("2.0-1"), "{message}");
    Ok(())
}

#[test]
fn apt_that_cannot_be_asked_is_shown_and_not_taken_for_kept_promises() -> TestResult {
    use crate::ipc::protocol::AptProblem;
    let pipeline = FakePipeline::default();
    let bed = added(false, &pipeline)?;
    *pipeline.apt.lock().unwrap_or_else(PoisonError::into_inner) =
        Err("apt-cache: E: The package lists are broken".to_owned());
    let plan = bed.service.plan(&sync_all()).map_err(|r| r.message)?;
    bed.service
        .run(&sync_all(), &plan)
        .map_err(|outcome| outcome.message)?;
    let status = status_of(&bed)?;
    assert!(
        matches!(
            status.apt_problems.as_slice(),
            [AptProblem { name: None, reason_code: None, message }]
                if message.contains("package lists are broken")
        ),
        "{:?}",
        status.apt_problems
    );
    Ok(())
}

// ------------------------------- pins only where APT can keep them (ADR-022 p.1)

#[test]
fn a_held_pin_tells_the_administrator_what_to_do_next() -> TestResult {
    use crate::apt::policy::{Finding, Held};
    use crate::sync::publish::HeldFamily;
    let pipeline = FakePipeline::default();
    let bed = added(false, &pipeline)?;
    *pipeline.held.lock().unwrap_or_else(PoisonError::into_inner) = vec![HeldFamily {
        source_id: SOURCE.to_owned(),
        members: ["sampleapp".to_owned()].into_iter().collect(),
        held: Held::NotListed {
            name: "sampleapp".to_owned(),
        },
    }];
    let plan = bed.service.plan(&sync_all()).map_err(|r| r.message)?;
    // Waiting for `apt update` is the expected next step, not a failure.
    let outcome = bed
        .service
        .run(&sync_all(), &plan)
        .map_err(|outcome| outcome.message)?;
    assert!(
        outcome.message.contains("run apt update, then pchi sync"),
        "{}",
        outcome.message
    );
    assert!(
        outcome.reason_codes.is_empty(),
        "{:?}",
        outcome.reason_codes
    );
    // An equal version elsewhere is a hold with its reason.
    *pipeline.held.lock().unwrap_or_else(PoisonError::into_inner) = vec![HeldFamily {
        source_id: SOURCE.to_owned(),
        members: ["sampleapp".to_owned(), "sampleapp-data".to_owned()]
            .into_iter()
            .collect(),
        held: Held::Ambiguous(Finding::EqualVersionElsewhere {
            name: "sampleapp-data".to_owned(),
            version: "1.0-1".to_owned(),
            other: "http://deb.debian.org/debian-security bookworm-security/main".to_owned(),
        }),
    }];
    let plan = bed.service.plan(&sync_all()).map_err(|r| r.message)?;
    let outcome = bed
        .service
        .run(&sync_all(), &plan)
        .map_err(|outcome| outcome.message)?;
    assert!(
        outcome
            .message
            .contains("sampleapp-data 1.0-1 is also offered by http://deb.debian.org"),
        "{}",
        outcome.message
    );
    assert_eq!(
        outcome.reason_codes,
        [crate::error::ReasonCode::ESourceAmbiguous]
    );
    Ok(())
}

#[test]
fn sync_force_checks_every_release_again_and_the_plan_says_so() -> TestResult {
    // ADR-037 point 1: between full checks the evidence of the same bytes
    // is reused; `--force` is the administrator's way to ask again now.
    let pipeline = FakePipeline::default();
    let bed = added(false, &pipeline)?;
    let force = AdminAction::Sync(crate::ipc::protocol::SyncTarget {
        source_id: None,
        force: true,
    });
    let plan = bed.service.plan(&force).map_err(|r| r.message)?;
    assert!(
        plan.summary
            .contains("evidence of every release is checked again"),
        "{}",
        plan.summary
    );
    bed.service
        .run(&force, &plan)
        .map_err(|outcome| outcome.message)?;
    assert_eq!(
        pipeline.calls(),
        [format!("sync {SOURCE} --force"), "configure".to_owned()]
    );
    let plan = bed.service.plan(&sync_all()).map_err(|r| r.message)?;
    assert!(!plan.summary.contains("checked again"), "{}", plan.summary);
    Ok(())
}

// ------------------------------------------- Pinned (ADR-027, P2-011b)

fn allow_pinned() -> AdminAction {
    AdminAction::SourceAllowPinned(crate::ipc::protocol::SourceAllowPinned {
        source_id: SOURCE.to_owned(),
    })
}

fn approve(release_id: u64) -> AdminAction {
    AdminAction::ReleaseApprove(crate::ipc::protocol::ReleaseApprove {
        source_id: SOURCE.to_owned(),
        release_id,
    })
}

#[test]
fn n040_pinned_consent_names_the_risk_and_is_given_once() -> TestResult {
    let pipeline = FakePipeline::default();
    let bed = added(false, &pipeline)?;
    let plan = bed.service.plan(&allow_pinned()).map_err(|r| r.message)?;
    assert!(
        plan.summary.contains(
            "a compromised publisher account, token, or CI can publish a malicious release"
        ),
        "{}",
        plan.summary
    );
    assert!(!status_of(&bed)?.pinned_consent, "a plan changes nothing");
    bed.service
        .run(&allow_pinned(), &plan)
        .map_err(|outcome| outcome.message)?;
    assert!(status_of(&bed)?.pinned_consent);
    assert!(bed.service.plan(&allow_pinned()).is_err(), "once");
    Ok(())
}

#[test]
fn n040_a_release_is_approved_by_its_exact_digests_and_only_after_consent() -> TestResult {
    let pipeline = FakePipeline::default();
    let bed = added(false, &pipeline)?;
    let refused = bed.service.plan(&approve(1));
    assert!(
        matches!(&refused, Err(r) if r.message.contains("pchi source allow-pinned")),
        "{refused:?}"
    );
    let plan = bed.service.plan(&allow_pinned()).map_err(|r| r.message)?;
    bed.service
        .run(&allow_pinned(), &plan)
        .map_err(|outcome| outcome.message)?;
    let unknown = bed.service.plan(&approve(1));
    assert!(
        matches!(&unknown, Err(r) if r.message.contains("pchi sync")),
        "{unknown:?}"
    );
    synchronized(&bed, &["sampleapp"])?;
    let plan = bed.service.plan(&approve(1)).map_err(|r| r.message)?;
    let digest = crate::cas::Sha256Digest::of(b"sampleapp").to_hex();
    assert_eq!(
        plan.changes,
        [PlanChange {
            kind: ChangeKind::ApproveRelease,
            target: "sampleapp_1.0-1_all.deb".to_owned(),
            before: None,
            after: Some(digest.clone()),
            risks: Vec::new(),
        }]
    );
    assert!(plan.summary.contains("v1.0"), "{}", plan.summary);
    bed.service
        .run(&approve(1), &plan)
        .map_err(|outcome| outcome.message)?;
    {
        let mut owner = bed
            .service
            .owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let approved = owner.approved_digests(SOURCE, &format!("{SOURCE}-release-1"))?;
        assert_eq!(approved.into_iter().collect::<Vec<_>>(), [digest]);
    }
    // The approval publishes through a synchronization of the source.
    assert_eq!(
        pipeline.calls(),
        [format!("sync {SOURCE}"), "configure".to_owned()]
    );
    assert!(bed.service.plan(&approve(1)).is_err(), "nothing left");
    Ok(())
}

#[test]
fn an_approval_confirmed_for_other_bytes_approves_nothing() -> TestResult {
    let pipeline = FakePipeline::default();
    let bed = added(false, &pipeline)?;
    let plan = bed.service.plan(&allow_pinned()).map_err(|r| r.message)?;
    bed.service
        .run(&allow_pinned(), &plan)
        .map_err(|outcome| outcome.message)?;
    synchronized(&bed, &["sampleapp"])?;
    let mut plan = bed.service.plan(&approve(1)).map_err(|r| r.message)?;
    // What the administrator confirmed is not what the server holds now.
    plan.changes[0].after = Some(crate::cas::Sha256Digest::of(b"other").to_hex());
    let stale = bed.service.run(&approve(1), &plan);
    assert!(
        matches!(&stale, Err(outcome) if outcome.message.contains("changed since the plan")),
        "{stale:?}"
    );
    let mut owner = bed
        .service
        .owner
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    assert!(
        owner
            .approved_digests(SOURCE, &format!("{SOURCE}-release-1"))?
            .is_empty()
    );
    Ok(())
}

#[test]
fn a_source_with_pinned_consent_is_never_activated_as_preferred() -> TestResult {
    let pipeline = FakePipeline::default();
    let bed = added(false, &pipeline)?;
    synchronized(&bed, &["sampleapp"])?;
    let plan = bed.service.plan(&allow_pinned()).map_err(|r| r.message)?;
    bed.service
        .run(&allow_pinned(), &plan)
        .map_err(|outcome| outcome.message)?;
    let preferred = AdminAction::SourceActivate(SourceActivate {
        source_id: SOURCE.to_owned(),
        packages: vec!["sampleapp".to_owned()],
        policy: ActivationPolicy::Preferred,
    });
    let refused = bed.service.plan(&preferred);
    assert!(
        matches!(&refused, Err(r) if r.message.contains("--policy supplemental")),
        "{refused:?}"
    );
    assert!(bed.service.plan(&activate(&["sampleapp"])).is_ok());
    Ok(())
}

#[test]
fn a_release_waiting_for_approval_names_the_command_that_approves_it() {
    use crate::sync::{ArtifactOutcome, ArtifactReport, SyncReport};
    let waiting = |filename: &str| ArtifactReport {
        tag: "v1.0".to_owned(),
        release_id: 268_800_123,
        filename: filename.to_owned(),
        package: None,
        outcome: ArtifactOutcome::Held(
            crate::error::ReasonCode::EReleaseApprovalRequired,
            "approval".to_owned(),
        ),
    };
    let report = SyncReport {
        source_id: SOURCE.to_owned(),
        releases: 1,
        artifacts: vec![waiting("a_1.0_all.deb"), waiting("b_1.0_all.deb")],
        ..SyncReport::default()
    };
    let text = super::pipeline::report_lines(&report);
    assert_eq!(
        text.matches(&format!("pchi release approve {SOURCE} 268800123"))
            .count(),
        1,
        "one line per release: {text}"
    );
}
