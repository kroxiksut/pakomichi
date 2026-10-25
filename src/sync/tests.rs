// SPDX-License-Identifier: MIT OR Apache-2.0

//! The whole pass against a real state database and CAS; GitHub, the
//! inspector, the evidence check, and the publisher are substitutes.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{Value, json};

use super::*;
use crate::attest::{RELEASE_PREDICATE, SLSA_PROVENANCE_V1};
use crate::cas::{Store, StoreConfig};
use crate::compat::{Distribution, ExecutionPolicy, Origin, OtherReleaseBuilds};
use crate::family::Family;
use crate::github::{
    ApiRequest, ApiResponse, OwnerId, OwnerLogin, RepositoryId, RepositoryIdentity, RepositoryName,
    ResponseHeaders, TransportError,
};
use crate::inspect::fixtures::deb_inspection;
use crate::inventory::{Ecosystem, TargetPlatform};
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const REPO: u64 = 1_429_307_950;
const OWNER_ID: u64 = 2_264_172;
const SOURCE: &str = "github-1429307950";
const AT: &str = "2026-10-24T12:00:00Z";

#[derive(Clone)]
struct Asset {
    id: u64,
    name: String,
    bytes: Vec<u8>,
    /// GitHub states the digest (R-005: not always).
    api_digest: bool,
    /// The control paragraph the inspector finds; `None`: refused.
    control: Option<String>,
}

fn deb(id: u64, name: &str, version: &str) -> Asset {
    Asset {
        id,
        name: format!("{name}_{version}_all.deb"),
        bytes: format!("{name} {version} bytes").into_bytes(),
        api_digest: true,
        control: Some(format!(
            "Package: {name}\nVersion: {version}\nArchitecture: all\n\
             Maintainer: Fixture <fixture@example.invalid>\nDescription: fixture\n"
        )),
    }
}

#[derive(Clone)]
struct ReleaseSpec {
    id: u64,
    tag: String,
    assets: Vec<Asset>,
}

/// GitHub: the repository by ID and its releases, newest first.
#[derive(Clone, Default)]
struct FakeGitHub(Arc<Mutex<Vec<ReleaseSpec>>>);

impl FakeGitHub {
    fn set(&self, releases: Vec<ReleaseSpec>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = releases;
    }

    fn releases(&self) -> Vec<ReleaseSpec> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn asset(&self, id: u64) -> Option<Asset> {
        self.releases()
            .into_iter()
            .flat_map(|release| release.assets)
            .find(|asset| asset.id == id)
    }
}

fn answer(body: &Value) -> ApiResponse {
    ApiResponse {
        status: 200,
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
        let path = request.path();
        if path == format!("/repositories/{REPO}") {
            return Ok(answer(&json!({
                "id": REPO,
                "node_id": "R_synthetic",
                "name": "pchi-test",
                "full_name": "kroxiksut/pchi-test",
                "private": false,
                "owner": {"login": "kroxiksut", "id": OWNER_ID, "type": "User"},
                "html_url": "https://github.com/kroxiksut/pchi-test",
                "fork": false,
                "archived": false,
                "default_branch": "main"
            })));
        }
        if path.starts_with(&format!("/repositories/{REPO}/releases?")) {
            let releases: Vec<Value> = self
                .releases()
                .iter()
                .map(|release| {
                    let assets: Vec<Value> = release
                        .assets
                        .iter()
                        .map(|asset| {
                            let mut wire = json!({
                                "id": asset.id,
                                "name": asset.name,
                                "size": asset.bytes.len(),
                                "state": "uploaded",
                                "browser_download_url": format!(
                                    "https://github.com/kroxiksut/pchi-test/releases/download/{}/{}",
                                    release.tag, asset.name
                                ),
                            });
                            if asset.api_digest {
                                wire["digest"] = Value::String(format!(
                                    "sha256:{}",
                                    Sha256Digest::of(&asset.bytes).to_hex()
                                ));
                            }
                            wire
                        })
                        .collect();
                    json!({
                        "id": release.id,
                        "tag_name": release.tag,
                        "target_commitish": "main",
                        "draft": false,
                        "prerelease": false,
                        "immutable": true,
                        "published_at": "2026-10-24T10:00:00Z",
                        "assets": assets,
                    })
                })
                .collect();
            return Ok(answer(&Value::Array(releases)));
        }
        Err(TransportError::Connect)
    }
}

/// Downloads put the asset's current bytes into the real CAS.
struct FakeFetch {
    github: FakeGitHub,
    cas: Store,
}

impl AssetFetch for FakeFetch {
    fn fetch(
        &self,
        locator: AssetLocator,
        _size: u64,
        _api_digest: Option<Sha256Digest>,
    ) -> Result<ExpectedObject, String> {
        let asset = self
            .github
            .asset(locator.asset.get())
            .ok_or("no such asset")?;
        let stored = self
            .cas
            .insert(asset.bytes.as_slice())
            .map_err(|error| error.to_string())?;
        Ok(ExpectedObject::new(stored.digest(), stored.size()))
    }
}

/// The inspector reads the control paragraph of the bytes it is given.
struct FakeInspect {
    github: FakeGitHub,
    down: Cell<bool>,
}

impl PackageInspect for FakeInspect {
    fn inspect_deb(&self, object: ExpectedObject) -> Result<DebInspection, InspectFailure> {
        if self.down.get() {
            return Err(InspectFailure::Unavailable("connect: refused".into()));
        }
        let asset = self
            .github
            .releases()
            .into_iter()
            .flat_map(|release| release.assets)
            .find(|asset| Sha256Digest::of(&asset.bytes) == object.sha256)
            .ok_or_else(|| InspectFailure::Refused("unknown bytes".into()))?;
        let control = asset
            .control
            .ok_or_else(|| InspectFailure::Refused("not a Debian package".into()))?;
        deb_inspection(&control).map_err(|error| InspectFailure::Refused(error.to_string()))
    }
}

/// The evidence verdict per asset bytes; Strict unless told otherwise.
#[derive(Default)]
struct FakeEvidence {
    verdicts: RefCell<BTreeMap<Vec<u8>, Verified>>,
    down: Cell<bool>,
}

impl FakeEvidence {
    fn set(&self, bytes: &[u8], verified: Verified) {
        self.verdicts.borrow_mut().insert(bytes.to_vec(), verified);
    }
}

impl EvidenceCheck for FakeEvidence {
    fn check(
        &self,
        _pinned: &PinnedRepository,
        _release: &Release,
        _asset_name: &str,
        sha256: Sha256Digest,
        _signer: Option<&AttestedSigner>,
    ) -> Result<Checked, String> {
        if self.down.get() {
            return Err("GitHub: connect: refused".into());
        }
        let verified = self
            .verdicts
            .borrow()
            .iter()
            .find(|(bytes, _)| Sha256Digest::of(bytes) == sha256)
            .map_or(Verified::Strict, |(_, verified)| *verified);
        let record = |level, predicate_type| {
            Some(EvidenceRecord {
                level,
                signer_identity: "test".to_owned(),
                predicate_type,
                bundle_sha256: Sha256Digest::of(sha256.to_hex().as_bytes()),
                record_json: "{}".to_owned(),
            })
        };
        Ok(Checked {
            verified,
            record: match verified {
                Verified::Strict => record(Level::Strict, RELEASE_PREDICATE),
                Verified::Attested => record(Level::Attested, SLSA_PROVENANCE_V1),
                Verified::Nothing | Verified::Invalid => None,
            },
            note: "test".to_owned(),
        })
    }
}

/// Records what each level would publish.
#[derive(Default)]
struct FakePublisher {
    published: Vec<(Level, Vec<String>)>,
}

impl LevelPublisher for FakePublisher {
    fn publish(
        &mut self,
        source_key: &str,
        level: Level,
        packages: &[AptPackage],
    ) -> Result<u64, (ReasonCode, String)> {
        assert_eq!(source_key, SOURCE);
        let mut names: Vec<String> = packages
            .iter()
            .map(|package| {
                format!(
                    "{} {}",
                    package.control.package(),
                    package.control.version()
                )
            })
            .collect();
        names.sort();
        self.published.push((level, names));
        Ok(self.published.len() as u64)
    }
}

struct Bed {
    _dir: TempDir,
    runtime: tokio::runtime::Runtime,
    owner: StateOwner,
    github: FakeGitHub,
    client: GitHubClient<FakeGitHub>,
    fetch: FakeFetch,
    inspect: FakeInspect,
    evidence: FakeEvidence,
    target: Target,
    system: SystemView,
    publisher: FakePublisher,
}

fn bed() -> Result<Bed, Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    let pinned = PinnedRepository::pin(RepositoryIdentity::new(
        RepositoryId::new(REPO)?,
        OwnerId::new(OWNER_ID)?,
        OwnerLogin::new("kroxiksut")?,
        RepositoryName::new("pchi-test")?,
    ));
    owner.add_source(&pinned, false, None, AT)?;
    let cas_root = dir.join("cas");
    std::fs::create_dir(&cas_root)?;
    let github = FakeGitHub::default();
    let mut packages = SystemPackages::new(Ecosystem::Deb);
    packages.add_package(Origin::Distribution, "libc6", "2.36-9");
    Ok(Bed {
        runtime: tokio::runtime::Builder::new_current_thread().build()?,
        owner,
        client: GitHubClient::new(github.clone(), None),
        fetch: FakeFetch {
            github: github.clone(),
            cas: Store::open(&cas_root, StoreConfig::default())?,
        },
        inspect: FakeInspect {
            github: github.clone(),
            down: Cell::new(false),
        },
        evidence: FakeEvidence::default(),
        target: Target {
            platform: TargetPlatform::new(Ecosystem::Deb, "amd64")?,
            distribution: Distribution::from_os_release("debian", "12"),
            execution_policy: ExecutionPolicy::Off,
            other_release_builds: OtherReleaseBuilds::default(),
        },
        system: SystemView::Known {
            namespace: SystemNamespace::new(),
            packages,
        },
        github,
        publisher: FakePublisher::default(),
        _dir: dir,
    })
}

impl Bed {
    fn sync(&mut self) -> Result<SyncReport, SyncError> {
        let sync = Sync {
            github: &self.client,
            runtime: self.runtime.handle().clone(),
            fetch: &self.fetch,
            inspect: &self.inspect,
            evidence: &self.evidence,
            target: &self.target,
            system: &self.system,
            policy: InventoryPolicy::default(),
        };
        synchronize(&sync, &mut self.owner, &mut self.publisher, SOURCE, AT)
    }

    /// The administrator's activation: the family at the next revision and
    /// the names' mode (what `source activate` confirms).
    fn activate(&mut self, names: &[&str]) -> TestResult {
        let revision = self
            .owner
            .family(SOURCE)?
            .map_or(1, |(_, family)| family.revision() + 1);
        let members = names.iter().map(|name| {
            (
                MemberKey::new(Ecosystem::Deb, name),
                ["all".to_owned()].into_iter().collect(),
            )
        });
        let family = Family::restore(revision, FamilyState::Approved, members)?;
        self.owner.save_family(SOURCE, &family)?;
        for name in names {
            self.owner.set_name_mode(
                SOURCE,
                &MemberKey::new(Ecosystem::Deb, name),
                SourceMode::Supplemental,
                AT,
            )?;
        }
        Ok(())
    }
}

fn release(id: u64, tag: &str, assets: Vec<Asset>) -> ReleaseSpec {
    ReleaseSpec {
        id,
        tag: tag.to_owned(),
        assets,
    }
}

fn outcome<'a>(report: &'a SyncReport, filename: &str) -> Option<&'a ArtifactOutcome> {
    report
        .artifacts
        .iter()
        .find(|artifact| artifact.filename == filename)
        .map(|artifact| &artifact.outcome)
}

fn held(report: &SyncReport, filename: &str) -> Option<ReasonCode> {
    match outcome(report, filename) {
        Some(ArtifactOutcome::Held(code, _) | ArtifactOutcome::Rejected(code, _)) => Some(*code),
        _ => None,
    }
}

#[test]
fn the_first_synchronization_proposes_the_family_and_publishes_nothing() -> TestResult {
    // `add` is not `activate`: whatever the first release holds is only
    // proposed to the administrator.
    let mut bed = bed()?;
    bed.github.set(vec![release(
        1,
        "v1.0",
        vec![
            deb(11, "sampleapp", "1.0-1"),
            deb(12, "sampleapp-data", "1.0-1"),
        ],
    )]);
    let report = bed.sync()?;
    assert!(bed.publisher.published.is_empty(), "{report:?}");
    assert!(!report.family_approved);
    let (_, family) = bed.owner.family(SOURCE)?.ok_or("no family")?;
    assert_eq!(family.state(), FamilyState::Proposed);
    assert_eq!(family.members().len(), 2);
    for filename in ["sampleapp_1.0-1_all.deb", "sampleapp-data_1.0-1_all.deb"] {
        assert_eq!(
            held(&report, filename),
            Some(ReasonCode::EFamilyUnapproved),
            "{report:?}"
        );
    }
    // Every decision is in the log with the facts it was made from.
    let logged: i64 = bed.owner.connection().query_row(
        "SELECT count(*) FROM decision_log WHERE object_type = 'artifact'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(logged, 2);
    Ok(())
}

#[test]
fn only_activated_names_are_published_and_a_new_name_waits() -> TestResult {
    let mut bed = bed()?;
    bed.github.set(vec![release(
        1,
        "v1.0",
        vec![deb(11, "sampleapp", "1.0-1")],
    )]);
    bed.sync()?;
    bed.activate(&["sampleapp"])?;
    // The next release brings a name the administrator never confirmed.
    bed.github.set(vec![
        release(
            2,
            "v1.1",
            vec![
                deb(21, "sampleapp", "1.1-1"),
                deb(22, "sampleapp-plugin", "1.1-1"),
            ],
        ),
        release(1, "v1.0", vec![deb(11, "sampleapp", "1.0-1")]),
    ]);
    let report = bed.sync()?;
    assert_eq!(
        bed.publisher.published,
        [(Level::Strict, vec!["sampleapp 1.1-1".to_owned()])],
        "{report:?}"
    );
    assert_eq!(
        held(&report, "sampleapp-plugin_1.1-1_all.deb"),
        Some(ReasonCode::EFamilyUnapproved)
    );
    let review = report.review.ok_or("no composition review")?;
    assert!(
        review
            .additions
            .contains_key(&MemberKey::new(Ecosystem::Deb, "sampleapp-plugin"))
    );
    // Seen, recorded, and still outside the family.
    let (_, family) = bed.owner.family(SOURCE)?.ok_or("no family")?;
    assert_eq!(family.members().len(), 1);
    assert!(
        bed.owner
            .seen_names(SOURCE)?
            .contains_key(&MemberKey::new(Ecosystem::Deb, "sampleapp-plugin"))
    );
    Ok(())
}

#[test]
fn a_replaced_asset_is_rejected_and_the_publication_does_not_take_it() -> TestResult {
    let mut bed = bed()?;
    let original = deb(11, "sampleapp", "1.0-1");
    bed.github
        .set(vec![release(1, "v1.0", vec![original.clone()])]);
    bed.sync()?;
    bed.activate(&["sampleapp"])?;
    bed.sync()?;
    assert_eq!(bed.publisher.published.len(), 1);
    // The same asset ID now serves other bytes, and the API no longer
    // states a digest (so the inventory alone cannot tell).
    let mut replaced = original;
    replaced.bytes = b"sampleapp 1.0-1 other bytes".to_vec();
    replaced.api_digest = false;
    bed.github.set(vec![release(1, "v1.0", vec![replaced])]);
    let report = bed.sync()?;
    assert_eq!(
        held(&report, "sampleapp_1.0-1_all.deb"),
        Some(ReasonCode::EAssetMutated),
        "{report:?}"
    );
    assert_eq!(
        bed.publisher.published.len(),
        1,
        "the replaced bytes are never published"
    );
    Ok(())
}

#[test]
fn weaker_evidence_than_the_floor_is_held_and_invalid_evidence_rejected() -> TestResult {
    let mut bed = bed()?;
    let attested_only = deb(21, "sampleapp", "1.1-1");
    let forged = deb(31, "sampleapp", "1.2-1");
    bed.evidence.set(&attested_only.bytes, Verified::Attested);
    bed.evidence.set(&forged.bytes, Verified::Invalid);
    bed.github.set(vec![release(
        1,
        "v1.0",
        vec![deb(11, "sampleapp", "1.0-1")],
    )]);
    bed.sync()?;
    bed.activate(&["sampleapp"])?;
    bed.github.set(vec![
        release(3, "v1.2", vec![forged]),
        release(2, "v1.1", vec![attested_only]),
        release(1, "v1.0", vec![deb(11, "sampleapp", "1.0-1")]),
    ]);
    let report = bed.sync()?;
    assert_eq!(
        held(&report, "sampleapp_1.1-1_all.deb"),
        Some(ReasonCode::EEvidenceDowngrade),
        "{report:?}"
    );
    assert!(matches!(
        outcome(&report, "sampleapp_1.2-1_all.deb"),
        Some(ArtifactOutcome::Rejected(
            ReasonCode::EAttestationInvalid,
            _
        ))
    ));
    // The newest admissible version stays the Strict 1.0.
    assert_eq!(
        bed.publisher.published.last(),
        Some(&(Level::Strict, vec!["sampleapp 1.0-1".to_owned()]))
    );
    Ok(())
}

#[test]
fn a_failure_to_ask_stops_the_pass_and_publishes_nothing() -> TestResult {
    let mut bed = bed()?;
    bed.github.set(vec![release(
        1,
        "v1.0",
        vec![deb(11, "sampleapp", "1.0-1")],
    )]);
    bed.sync()?;
    bed.activate(&["sampleapp"])?;
    // GitHub unreachable for the evidence: not "no evidence".
    bed.evidence.down.set(true);
    assert!(matches!(bed.sync(), Err(SyncError::Evidence(_))));
    bed.evidence.down.set(false);
    // The inspector down: not "malformed".
    bed.inspect.down.set(true);
    assert!(matches!(bed.sync(), Err(SyncError::Inspector(_))));
    assert!(bed.publisher.published.is_empty());
    Ok(())
}

#[test]
fn bytes_the_inspector_refuses_are_malformed_and_never_published() -> TestResult {
    let mut bed = bed()?;
    let mut broken = deb(12, "sampleapp-data", "1.0-1");
    broken.control = None;
    bed.github.set(vec![release(
        1,
        "v1.0",
        vec![deb(11, "sampleapp", "1.0-1"), broken],
    )]);
    let report = bed.sync()?;
    assert_eq!(
        held(&report, "sampleapp-data_1.0-1_all.deb"),
        Some(ReasonCode::EArtifactMalformed)
    );
    let (_, family) = bed.owner.family(SOURCE)?.ok_or("no family")?;
    assert_eq!(family.members().len(), 1, "no name from refused bytes");
    Ok(())
}

/// The root applier on a temporary root; `apt-cache policy` answers as
/// told.
struct RootApplier {
    root: std::path::PathBuf,
    refuse: Cell<bool>,
}

impl crate::apt::applier::AptCheck for RootApplier {
    fn check(&self) -> Result<(), String> {
        if self.refuse.get() {
            Err("E: Malformed entry 1".to_owned())
        } else {
            Ok(())
        }
    }
}

impl crate::apt::operation::Applier for RootApplier {
    fn call(
        &self,
        request: &crate::ipc::channels::ApplyRequest,
    ) -> Result<crate::ipc::channels::ApplyResponse, String> {
        Ok(crate::apt::applier::answer(
            &self.root,
            request.clone(),
            self,
        ))
    }
}

fn state(bed: &mut Bed) -> Result<String, StateError> {
    Ok(bed
        .owner
        .sources()?
        .into_iter()
        .find(|row| row.id == SOURCE)
        .map(|row| row.state)
        .unwrap_or_default())
}

fn journal(bed: &mut Bed) -> Result<Vec<String>, StateError> {
    Ok(bed
        .owner
        .open_activations(SOURCE)?
        .into_iter()
        .map(|(_, name)| name)
        .collect())
}

#[test]
fn the_activation_journal_follows_only_a_verified_apply() -> TestResult {
    use crate::apt::operation::Ended;
    let mut bed = bed()?;
    let root = bed._dir.join("root");
    std::fs::create_dir_all(root.join("etc/apt/sources.list.d"))?;
    let applier = RootApplier {
        root,
        refuse: Cell::new(false),
    };
    bed.github.set(vec![release(
        1,
        "v1.0",
        vec![deb(11, "sampleapp", "1.0-1")],
    )]);
    bed.sync()?;
    bed.activate(&["sampleapp"])?;
    bed.sync()?;
    let desired = desired_apt(&mut bed.owner, 18080, b"keyring".to_vec())?;
    let labels: Vec<(String, Vec<String>)> = desired
        .sources
        .iter()
        .flat_map(|source| &source.repositories)
        .map(|repository| {
            (
                repository.label.clone(),
                repository.activated.iter().cloned().collect(),
            )
        })
        .collect();
    assert_eq!(
        labels,
        [(
            "pakomichi-github-1429307950-strict".to_owned(),
            vec!["sampleapp".to_owned()]
        )]
    );
    // APT refuses the configuration: rolled back, nothing activated.
    applier.refuse.set(true);
    let ended = apply_and_record(&mut bed.owner, &applier, &desired, AT)?;
    assert!(matches!(ended, Ended::RolledBack { .. }), "{ended:?}");
    assert!(journal(&mut bed)?.is_empty());
    assert_eq!(state(&mut bed)?, "registered", "nothing is active yet");
    applier.refuse.set(false);
    let ended = apply_and_record(&mut bed.owner, &applier, &desired, AT)?;
    assert!(matches!(ended, Ended::Verified { .. }), "{ended:?}");
    assert_eq!(journal(&mut bed)?, ["sampleapp"]);
    // The status says what APT now does: the source serves an activated name.
    assert_eq!(state(&mut bed)?, "active");
    // The administrator withdraws the name: its pin goes, and so does the
    // open activation, once the apply is verified.
    bed.owner.set_name_mode(
        SOURCE,
        &MemberKey::new(Ecosystem::Deb, "sampleapp"),
        SourceMode::Observing,
        AT,
    )?;
    let desired = desired_apt(&mut bed.owner, 18080, b"keyring".to_vec())?;
    assert!(desired.activated().is_empty());
    apply_and_record(&mut bed.owner, &applier, &desired, AT)?;
    assert!(journal(&mut bed)?.is_empty());
    assert_eq!(state(&mut bed)?, "registered", "no name is served any more");
    Ok(())
}

#[test]
fn an_observed_source_stays_observed_whatever_is_applied() -> TestResult {
    // The state follows the activations of a source that may have them; an
    // observed or suspended source is never turned into an active one.
    let mut bed = bed()?;
    bed.owner
        .connection()
        .execute("UPDATE forge_repository SET state = 'observing'", [])?;
    bed.owner.set_source_activity(SOURCE, true)?;
    assert_eq!(state(&mut bed)?, "observing");
    bed.owner
        .connection()
        .execute("UPDATE forge_repository SET state = 'suspended'", [])?;
    bed.owner.set_source_activity(SOURCE, false)?;
    assert_eq!(state(&mut bed)?, "suspended");
    Ok(())
}
