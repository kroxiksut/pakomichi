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

/// GitHub: the repository by ID (under its current name) and its
/// releases, newest first.
#[derive(Clone, Default)]
struct FakeGitHub(
    Arc<Mutex<Vec<ReleaseSpec>>>,
    Arc<Mutex<Option<String>>>,
    Arc<Mutex<Option<u64>>>,
);

impl FakeGitHub {
    /// The repository is transferred on GitHub to the owner `owner_id`.
    fn transfer_to(&self, owner_id: u64) {
        *self.2.lock().unwrap_or_else(PoisonError::into_inner) = Some(owner_id);
    }

    fn owner_id(&self) -> u64 {
        self.2
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .unwrap_or(OWNER_ID)
    }

    /// The repository is renamed on GitHub; its IDs stay.
    fn rename(&self, name: &str) {
        *self.1.lock().unwrap_or_else(PoisonError::into_inner) = Some(name.to_owned());
    }

    fn name(&self) -> String {
        self.1
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| "pchi-test".to_owned())
    }

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
            let name = self.name();
            let owner_id = self.owner_id();
            return Ok(answer(&json!({
                "id": REPO,
                "node_id": "R_synthetic",
                "name": name,
                "full_name": format!("kroxiksut/{name}"),
                "private": false,
                "owner": {"login": "kroxiksut", "id": owner_id, "type": "User"},
                "html_url": format!("https://github.com/kroxiksut/{name}"),
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
    /// How many times GitHub was asked.
    calls: Cell<usize>,
    /// The signer an Attested verdict names; `test` when empty.
    signer_identity: RefCell<String>,
    /// The earlier owners each check was told to look at.
    earlier_owners: RefCell<Vec<Vec<u64>>>,
    /// How many times stored bundles were verified again offline.
    reverified: Cell<usize>,
}

impl FakeEvidence {
    fn set(&self, bytes: &[u8], verified: Verified) {
        self.verdicts.borrow_mut().insert(bytes.to_vec(), verified);
    }
}

impl EvidenceCheck for FakeEvidence {
    fn reverify(
        &self,
        _pinned: &PinnedRepository,
        _release: &Release,
        _asset_name: &str,
        sha256: Sha256Digest,
        _signer: Option<&AttestedSigner>,
        bundles: &[Vec<u8>],
    ) -> Result<Checked, String> {
        self.reverified.set(self.reverified.get() + 1);
        // The fake verifier accepts exactly the bundle it once issued.
        if bundles.iter().any(|bundle| *bundle == fake_bundle(sha256)) {
            Ok(Checked {
                verified: Verified::Strict,
                record: None,
                note: "test: verified again offline".to_owned(),
            })
        } else {
            Ok(Checked::nothing("test: the stored bundle does not verify"))
        }
    }

    fn check(
        &self,
        _pinned: &PinnedRepository,
        _release: &Release,
        _asset_name: &str,
        sha256: Sha256Digest,
        _signer: Option<&AttestedSigner>,
        earlier_owners: &[OwnerId],
    ) -> Result<Checked, String> {
        self.earlier_owners
            .borrow_mut()
            .push(earlier_owners.iter().map(|id| id.get()).collect());
        if self.down.get() {
            return Err("GitHub: connect: refused".into());
        }
        self.calls.set(self.calls.get() + 1);
        let signer_identity = match self.signer_identity.borrow().as_str() {
            "" => "test".to_owned(),
            named => named.to_owned(),
        };
        let verified = self
            .verdicts
            .borrow()
            .iter()
            .find(|(bytes, _)| Sha256Digest::of(bytes) == sha256)
            .map_or(Verified::Strict, |(_, verified)| *verified);
        let record = |level, predicate_type| {
            Some(EvidenceRecord {
                level,
                signer_identity: signer_identity.clone(),
                predicate_type,
                bundle_sha256: Sha256Digest::of(&fake_bundle(sha256)),
                bundle: fake_bundle(sha256),
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

/// The bundle the fake verifier accepted for these bytes.
fn fake_bundle(sha256: Sha256Digest) -> Vec<u8> {
    format!("bundle for {}", sha256.to_hex()).into_bytes()
}

impl BundleStore for FakeFetch {
    fn load(&self, sha256: Sha256Digest) -> Result<Vec<u8>, String> {
        load_verified(&self.cas, sha256)
    }

    fn store(&self, bundle: &[u8]) -> Result<Sha256Digest, String> {
        self.cas
            .insert(bundle)
            .map(|stored| stored.digest())
            .map_err(|error| error.to_string())
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
        self.sync_at(AT, false)
    }

    /// A pass at `at`; `force`: `pchi sync --force`.
    fn sync_at(&mut self, at: &str, force: bool) -> Result<SyncReport, SyncError> {
        let sync = Sync {
            github: &self.client,
            runtime: self.runtime.handle().clone(),
            fetch: &self.fetch,
            bundles: &self.fetch,
            inspect: &self.inspect,
            evidence: &self.evidence,
            target: &self.target,
            system: &self.system,
            policy: InventoryPolicy::default(),
            force_full_evidence_check: force,
        };
        synchronize(&sync, &mut self.owner, &mut self.publisher, SOURCE, at)
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
    // GitHub unreachable for the evidence: not "no evidence". Bytes seen
    // before keep their evidence until a full check (ADR-037 point 1), so
    // the full check asks.
    bed.evidence.down.set(true);
    assert!(matches!(bed.sync_at(AT, true), Err(SyncError::Evidence(_))));
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

// ------------------------------------------- what APT chooses (N-027)

const STRICT_URI: &str = "http://127.0.0.1:879/pakomichi-github-1429307950-strict \
                          pakomichi-github-1429307950-strict/main amd64 Packages";
const SECURITY: &str =
    "http://deb.debian.org/debian-security bookworm-security/main amd64 Packages";

fn policy_text(text: &str) -> Result<Vec<crate::apt::policy::PackagePolicy>, String> {
    crate::apt::policy::parse_policy(text).map_err(|error| error.to_string())
}

/// `sampleapp` 1.0-1 published at Strict and activated.
fn activated_bed() -> Result<Bed, Box<dyn std::error::Error>> {
    let mut bed = bed()?;
    bed.github.set(vec![release(
        1,
        "v1.0",
        vec![deb(11, "sampleapp", "1.0-1")],
    )]);
    bed.sync()?;
    bed.activate(&["sampleapp"])?;
    bed.sync()?;
    Ok(bed)
}

#[test]
fn n027_a_newer_version_elsewhere_is_a_notice_of_the_source_and_the_publisher_stays() -> TestResult
{
    use crate::apt::policy::Notice;
    use selection::{AptPromises, SourceAptView};
    let mut bed = activated_bed()?;
    let promises = AptPromises::read(&mut bed.owner, 879)?;
    assert_eq!(promises.names(), ["sampleapp"]);
    // A distribution security update offers 1.1-1; the pin keeps 1.0-1.
    let policies = policy_text(&format!(
        "sampleapp:\n  Installed: 1.0-1\n  Candidate: 1.0-1\n  Version table:\n\
         \x20    1.1-1 500\n        500 {SECURITY}\n\
         \x20*** 1.0-1 990\n        100 {STRICT_URI}\n        100 /var/lib/dpkg/status\n"
    ))?;
    let view = promises.judge(&policies);
    assert_eq!(
        view,
        BTreeMap::from([(
            SOURCE.to_owned(),
            SourceAptView {
                updates_elsewhere: vec![Notice {
                    name: "sampleapp".to_owned(),
                    version: "1.1-1".to_owned(),
                    source: "http://deb.debian.org/debian-security bookworm-security/main"
                        .to_owned(),
                }],
                problems: Vec::new(),
            }
        )])
    );
    Ok(())
}

#[test]
fn an_activated_name_apt_would_take_from_elsewhere_is_a_problem_of_its_source() -> TestResult {
    use crate::apt::policy::Finding;
    use selection::AptPromises;
    let mut bed = activated_bed()?;
    let promises = AptPromises::read(&mut bed.owner, 879)?;
    // The pin is not in effect: the next upgrade changes the publisher.
    let lost_pin = policy_text(&format!(
        "sampleapp:\n  Installed: 1.0-1\n  Candidate: 1.1-1\n  Version table:\n\
         \x20    1.1-1 500\n        500 {SECURITY}\n\
         \x20*** 1.0-1 100\n        100 {STRICT_URI}\n        100 /var/lib/dpkg/status\n"
    ))?;
    let problems = &promises.judge(&lost_pin)[SOURCE].problems;
    assert_eq!(
        problems,
        &[Finding::NotProtected {
            name: "sampleapp".to_owned(),
            candidate: Some("1.1-1".to_owned()),
            priority: Some(500),
        }]
    );
    // APT does not list the name at all yet (no `apt update` since it was
    // published): it is not protected either, and the status says so.
    let unlisted = promises.judge(&[]);
    assert!(matches!(
        unlisted[SOURCE].problems.as_slice(),
        [Finding::NotProtected {
            candidate: None,
            ..
        }]
    ));
    Ok(())
}

#[test]
fn a_withdrawn_name_is_not_protected_and_must_not_take_over_another_copy() -> TestResult {
    use crate::apt::policy::Finding;
    use selection::AptPromises;
    let mut bed = activated_bed()?;
    bed.owner.set_name_mode(
        SOURCE,
        &MemberKey::new(Ecosystem::Deb, "sampleapp"),
        SourceMode::Observing,
        AT,
    )?;
    let promises = AptPromises::read(&mut bed.owner, 879)?;
    // Still published, so still asked about; no longer promised.
    assert_eq!(promises.names(), ["sampleapp"]);
    let kept = policy_text(&format!(
        "sampleapp:\n  Installed: 0.9-1\n  Candidate: 0.9-1\n  Version table:\n\
         \x20    1.0-1 100\n        100 {STRICT_URI}\n\
         \x20*** 0.9-1 500\n        500 {SECURITY}\n        100 /var/lib/dpkg/status\n"
    ))?;
    assert_eq!(
        promises
            .judge(&kept)
            .get(SOURCE)
            .cloned()
            .unwrap_or_default(),
        selection::SourceAptView::default(),
        "a newer version of a name that is not activated is no notice"
    );
    // A preference outside Pakomichi makes our copy the candidate: the
    // installed copy of the other source would be replaced.
    let taken = policy_text(&format!(
        "sampleapp:\n  Installed: 0.9-1\n  Candidate: 1.0-1\n  Version table:\n\
         \x20    1.0-1 600\n        100 {STRICT_URI}\n\
         \x20*** 0.9-1 500\n        500 {SECURITY}\n        100 /var/lib/dpkg/status\n"
    ))?;
    assert_eq!(
        promises.judge(&taken)[SOURCE].problems,
        [Finding::TakesOver {
            name: "sampleapp".to_owned(),
            version: "1.0-1".to_owned(),
        }]
    );
    Ok(())
}

// ------------------------------- pins only where APT can keep them (ADR-022 p.1)

fn pin_gate(
    bed: &mut Bed,
    policies: &[crate::apt::policy::PackagePolicy],
    pinned_before: &[&str],
) -> Result<(Vec<String>, Vec<publish::HeldFamily>), Box<dyn std::error::Error>> {
    let mut desired = desired_apt(&mut bed.owner, 879, b"keyring".to_vec())?;
    let before = BTreeMap::from([(
        SOURCE.to_owned(),
        pinned_before
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
    )]);
    let held = publish::gate_pins(&mut desired, policies, &before);
    Ok((desired.activated(), held))
}

#[test]
fn a_new_activation_is_pinned_only_once_apt_lists_it() -> TestResult {
    use crate::apt::policy::Held;
    let mut bed = activated_bed()?;
    // Published, but `apt update` has not run: APT cannot show yet that no
    // other source offers an equal version.
    let (pinned, held) = pin_gate(&mut bed, &[], &[])?;
    assert!(pinned.is_empty(), "{pinned:?}");
    assert_eq!(
        held,
        [publish::HeldFamily {
            source_id: SOURCE.to_owned(),
            members: ["sampleapp".to_owned()].into_iter().collect(),
            held: Held::NotListed {
                name: "sampleapp".to_owned()
            },
        }]
    );
    let listed = policy_text(&format!(
        "sampleapp:\n  Installed: (none)\n  Candidate: 1.0-1\n  Version table:\n\
         \x20    1.0-1 100\n        100 {STRICT_URI}\n"
    ))?;
    let (pinned, held) = pin_gate(&mut bed, &listed, &[])?;
    assert_eq!(pinned, ["sampleapp"]);
    assert!(held.is_empty(), "{held:?}");
    Ok(())
}

#[test]
fn an_equal_version_elsewhere_holds_the_whole_family_even_when_pinned_before() -> TestResult {
    use crate::apt::policy::Held;
    let mut bed = bed()?;
    bed.github.set(vec![release(
        1,
        "v1.0",
        vec![
            deb(11, "sampleapp", "1.0-1"),
            deb(12, "sampleapp-data", "1.0-1"),
        ],
    )]);
    bed.sync()?;
    bed.activate(&["sampleapp", "sampleapp-data"])?;
    bed.sync()?;
    let policies = policy_text(&format!(
        "sampleapp:\n  Installed: (none)\n  Candidate: 1.0-1\n  Version table:\n\
         \x20    1.0-1 100\n        100 {STRICT_URI}\n\
         sampleapp-data:\n  Installed: (none)\n  Candidate: 1.0-1\n  Version table:\n\
         \x20    1.0-1 500\n        500 {SECURITY}\n        100 {STRICT_URI}\n"
    ))?;
    for before in [&[][..], &["sampleapp", "sampleapp-data"][..]] {
        let (pinned, held) = pin_gate(&mut bed, &policies, before)?;
        // A member left without the pin changes publisher on the next
        // upgrade, so the family is pinned whole or not at all.
        assert!(pinned.is_empty(), "{pinned:?}");
        let [publish::HeldFamily { members, held, .. }] = held.as_slice() else {
            return Err(format!("{held:?}").into());
        };
        assert_eq!(members.len(), 2);
        assert!(matches!(held, Held::Ambiguous(_)), "{held:?}");
    }
    Ok(())
}

#[test]
fn a_pinned_name_keeps_its_pin_while_apt_does_not_list_it() -> TestResult {
    // Dropping the pin of an installed name until the next `apt update`
    // would let another source's higher version take it over meanwhile.
    let mut bed = activated_bed()?;
    let (pinned, held) = pin_gate(&mut bed, &[], &["sampleapp"])?;
    assert_eq!(pinned, ["sampleapp"]);
    assert!(held.is_empty(), "{held:?}");
    Ok(())
}

#[test]
fn a_new_member_that_cannot_be_pinned_waits_alone_and_the_pinned_keep_their_pins() -> TestResult {
    // ADR-037 point 2: unpinning installed members because of one that is
    // not installed yet would expose them to another source's higher version.
    use crate::apt::policy::Held;
    let mut bed = bed()?;
    bed.github.set(vec![release(
        1,
        "v1.0",
        vec![
            deb(11, "sampleapp", "1.0-1"),
            deb(12, "sampleapp-data", "1.0-1"),
        ],
    )]);
    bed.sync()?;
    bed.activate(&["sampleapp", "sampleapp-data"])?;
    bed.sync()?;
    let app = format!(
        "sampleapp:\n  Installed: 1.0-1\n  Candidate: 1.0-1\n  Version table:\n\
         \x20    1.0-1 100\n        100 {STRICT_URI}\n"
    );
    let ambiguous = policy_text(&format!(
        "{app}sampleapp-data:\n  Installed: (none)\n  Candidate: 1.0-1\n  Version table:\n\
         \x20    1.0-1 500\n        500 {SECURITY}\n        100 {STRICT_URI}\n"
    ))?;
    let unlisted = policy_text(&app)?;
    for (policies, expected) in [(&ambiguous, "ambiguous"), (&unlisted, "not listed")] {
        let (pinned, held) = pin_gate(&mut bed, policies, &["sampleapp"])?;
        assert_eq!(pinned, ["sampleapp"], "{expected}");
        let [publish::HeldFamily { members, held, .. }] = held.as_slice() else {
            return Err(format!("{expected}: {held:?}").into());
        };
        assert_eq!(
            members.iter().map(String::as_str).collect::<Vec<_>>(),
            ["sampleapp-data"],
            "{expected}"
        );
        assert_eq!(
            matches!(held, Held::Ambiguous(_)),
            expected == "ambiguous",
            "{held:?}"
        );
    }
    Ok(())
}

// ------------------- evidence reused between synchronizations (ADR-037 p.1)

const HOUR_LATER: &str = "2026-10-24T13:00:00Z";
const DAY_LATER: &str = "2026-10-25T12:00:00Z";

#[test]
fn the_same_bytes_are_not_asked_about_again_until_the_daily_full_check() -> TestResult {
    // Every pass asked GitHub about every listed release, so a receiver
    // without a token ran out of its 60 requests an hour.
    let mut bed = activated_bed()?;
    assert_eq!(bed.evidence.calls.get(), 1, "the first pass checks in full");
    let report = bed.sync_at(HOUR_LATER, false)?;
    assert_eq!(
        bed.evidence.calls.get(),
        1,
        "the same bytes reuse their evidence"
    );
    assert_eq!(held(&report, "sampleapp_1.0-1_all.deb"), None, "{report:?}");
    bed.sync_at(DAY_LATER, false)?;
    assert_eq!(
        bed.evidence.calls.get(),
        2,
        "24 hours after the last full check"
    );
    bed.sync_at(DAY_LATER, false)?;
    assert_eq!(bed.evidence.calls.get(), 2);
    bed.sync_at(DAY_LATER, true)?;
    assert_eq!(
        bed.evidence.calls.get(),
        3,
        "`pchi sync --force` checks in full"
    );
    Ok(())
}

#[test]
fn bytes_without_evidence_are_asked_about_on_every_pass() -> TestResult {
    let mut bed = bed()?;
    let asset = deb(11, "sampleapp", "1.0-1");
    bed.evidence.set(&asset.bytes, Verified::Nothing);
    bed.github.set(vec![release(1, "v1.0", vec![asset])]);
    bed.sync()?;
    bed.sync_at(HOUR_LATER, false)?;
    assert_eq!(bed.evidence.calls.get(), 2);
    Ok(())
}

#[test]
fn attested_evidence_is_reused_only_for_the_current_signer() -> TestResult {
    use crate::attest::{AttestedSigner, SignerRef};
    let mut bed = bed()?;
    let workflow = |file: &str| -> Result<AttestedSigner, String> {
        AttestedSigner::new(
            format!(".github/workflows/{file}"),
            SignerRef::Branch("main".to_owned()),
        )
        .map_err(|_| "workflow".to_owned())
    };
    bed.owner
        .confirm_signer(SOURCE, &workflow("release.yml")?, AT)?;
    let asset = deb(11, "sampleapp", "1.0-1");
    bed.evidence.set(&asset.bytes, Verified::Attested);
    *bed.evidence.signer_identity.borrow_mut() =
        "https://github.com/kroxiksut/pchi-test/.github/workflows/release.yml@refs/heads/main"
            .to_owned();
    bed.github.set(vec![release(1, "v1.0", vec![asset])]);
    bed.sync()?;
    bed.sync_at(HOUR_LATER, false)?;
    assert_eq!(bed.evidence.calls.get(), 1, "the confirmed signer: reused");
    // Another workflow is confirmed: what the old one signed is checked
    // against the new one, not taken over.
    bed.owner
        .confirm_signer(SOURCE, &workflow("other.yml")?, HOUR_LATER)?;
    bed.sync_at(HOUR_LATER, false)?;
    assert_eq!(bed.evidence.calls.get(), 2);
    Ok(())
}

#[test]
fn a_clock_set_back_does_not_postpone_the_full_check() -> TestResult {
    // A last full check in the future would otherwise keep reusing until
    // the clock reaches it.
    let mut bed = activated_bed()?;
    bed.sync_at("2026-10-24T11:00:00Z", false)?;
    assert_eq!(bed.evidence.calls.get(), 2);
    Ok(())
}

// ----------------------------------------------- renames (ADR-005, R-003)

#[test]
fn a_rename_moves_the_address_and_keeps_the_old_one() -> TestResult {
    // The IDs bind, not the name: a renamed repository stays the source,
    // its status shows where it is now, and the old address is kept for
    // the user who still has it in a note or a script.
    let mut bed = activated_bed()?;
    bed.github.rename("pchi-test-renamed");
    let report = bed.sync()?;
    assert!(report.identity_note.is_some(), "{report:?}");
    assert_eq!(held(&report, "sampleapp_1.0-1_all.deb"), None, "{report:?}");
    let row = bed
        .owner
        .sources()?
        .into_iter()
        .find(|row| row.id == SOURCE)
        .ok_or("no source")?;
    assert_eq!(
        row.canonical_url,
        "https://github.com/kroxiksut/pchi-test-renamed"
    );
    assert_eq!(
        bed.owner.previous_addresses(SOURCE)?,
        ["https://github.com/kroxiksut/pchi-test"]
    );
    // The next pass sees the new address as the pinned one.
    let again = bed.sync()?;
    assert_eq!(again.identity_note, None);
    assert_eq!(bed.owner.previous_addresses(SOURCE)?.len(), 1);
    Ok(())
}

// ------------------------------------------- Pinned (ADR-027, P2-011b)

#[test]
fn a_pinned_release_is_published_only_with_consent_and_its_exact_approval() -> TestResult {
    // N-039/N-040: no evidence at all; only the administrator's consent
    // and the approval of exactly these bytes let it through.
    let mut bed = bed()?;
    let asset = deb(11, "sampleapp", "1.0-1");
    let bytes = asset.bytes.clone();
    bed.evidence.set(&bytes, Verified::Nothing);
    bed.github.set(vec![release(1, "v1.0", vec![asset])]);
    bed.sync()?;
    bed.activate(&["sampleapp"])?;
    let report = bed.sync()?;
    assert_ne!(
        outcome(&report, "sampleapp_1.0-1_all.deb"),
        Some(&ArtifactOutcome::Published(Level::Pinned)),
        "no consent: never Pinned"
    );
    assert!(bed.owner.grant_pinned_consent(SOURCE, AT)?);
    assert!(!bed.owner.grant_pinned_consent(SOURCE, AT)?, "once");
    let report = bed.sync()?;
    assert_eq!(
        held(&report, "sampleapp_1.0-1_all.deb"),
        Some(ReasonCode::EReleaseApprovalRequired),
        "consent alone publishes nothing"
    );
    let (release_row, tag) = bed
        .owner
        .release_by_forge_id(SOURCE, 1)?
        .ok_or("no release row")?;
    assert_eq!(tag, "v1.0");
    let artifacts = bed.owner.release_artifacts(SOURCE, &release_row)?;
    assert_eq!(artifacts.len(), 1);
    bed.owner
        .approve_release(SOURCE, &release_row, &[artifacts[0].sha256], AT)?;
    let report = bed.sync()?;
    assert_eq!(
        outcome(&report, "sampleapp_1.0-1_all.deb"),
        Some(&ArtifactOutcome::Published(Level::Pinned)),
        "{report:?}"
    );
    assert_eq!(
        bed.publisher.published.last(),
        Some(&(Level::Pinned, vec!["sampleapp 1.0-1".to_owned()]))
    );
    // The state carries the approval, so APT pins the name to the Pinned
    // repository; a published artifact without it would be held there.
    let desired = desired_apt(&mut bed.owner, 879, b"keyring".to_vec())?;
    let pinned: Vec<(String, Vec<String>)> = desired
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
        pinned,
        [(
            "pakomichi-github-1429307950-pinned".to_owned(),
            vec!["sampleapp".to_owned()]
        )]
    );
    // Other bytes behind the approved asset: the approval does not follow.
    let replaced = Asset {
        bytes: b"other bytes".to_vec(),
        ..deb(11, "sampleapp", "1.0-1")
    };
    bed.github.set(vec![release(1, "v1.0", vec![replaced])]);
    let report = bed.sync_at(AT, true)?;
    assert_eq!(
        held(&report, "sampleapp_1.0-1_all.deb"),
        Some(ReasonCode::EAssetMutated)
    );
    Ok(())
}

// ------------------------------- attestations after a transfer (ADR-034 p.2)

#[test]
fn after_confirmed_transfers_the_earlier_owners_are_asked_newest_first() -> TestResult {
    // GitHub keeps attestations under the owner of the repository when
    // they were made (R-003 observation 4): after a transfer only the
    // earlier owners' endpoints still have them.
    let mut bed = bed()?;
    bed.github.set(vec![release(
        1,
        "v1.0",
        vec![deb(11, "sampleapp", "1.0-1")],
    )]);
    bed.sync()?;
    assert_eq!(
        bed.evidence.earlier_owners.borrow().last(),
        Some(&Vec::new()),
        "no transfer: nobody else is asked"
    );
    bed.owner.confirm_owner_transfer(SOURCE, "3000", AT)?;
    bed.owner
        .confirm_owner_transfer(SOURCE, "4000", HOUR_LATER)?;
    bed.github.transfer_to(4000);
    bed.sync_at(DAY_LATER, true)?;
    assert_eq!(
        bed.evidence.earlier_owners.borrow().last(),
        Some(&vec![3000, OWNER_ID]),
        "the confirmed earlier owners, newest first, never the current one"
    );
    Ok(())
}

// ---------------------------------------------- stored bundles (ADR-034 p.1)

#[test]
fn the_bundle_behind_admitted_evidence_is_kept_for_a_later_offline_check() -> TestResult {
    // After a transfer, or when GitHub stops serving an attestation, the
    // forge cannot be asked again; the verified bundle must be kept.
    let mut bed = activated_bed()?;
    let bytes = deb(11, "sampleapp", "1.0-1").bytes;
    let sha256 = Sha256Digest::of(&bytes);
    let evidence = bed
        .owner
        .recorded_evidence(SOURCE, 11, sha256)?
        .ok_or("no evidence")?;
    let bundle = fake_bundle(sha256);
    assert_eq!(
        bed.owner.evidence_bundles(&evidence.id)?,
        [Sha256Digest::of(&bundle)]
    );
    bed.fetch.cas.verify(crate::cas::ExpectedObject::new(
        Sha256Digest::of(&bundle),
        bundle.len() as u64,
    ))?;
    Ok(())
}

#[test]
fn an_admitted_artifact_whose_attestation_the_forge_no_longer_serves_is_verified_offline()
-> TestResult {
    // ADR-034 point 1: after a transfer or a deleted attestation the forge
    // answers 404; the bundle kept at admission still proves the bytes.
    let mut bed = activated_bed()?;
    let bytes = deb(11, "sampleapp", "1.0-1").bytes;
    bed.evidence.set(&bytes, Verified::Nothing);
    let report = bed.sync_at(DAY_LATER, false)?;
    assert_eq!(bed.evidence.reverified.get(), 1, "{report:?}");
    assert_eq!(held(&report, "sampleapp_1.0-1_all.deb"), None, "{report:?}");
    Ok(())
}

#[test]
fn a_stored_bundle_that_changed_never_passes() -> TestResult {
    let mut bed = activated_bed()?;
    let bytes = deb(11, "sampleapp", "1.0-1").bytes;
    let bundle = Sha256Digest::of(&fake_bundle(Sha256Digest::of(&bytes)));
    let path = bed.fetch.cas.object_path(&bundle);
    let mut permissions = std::fs::metadata(&path)?.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    std::fs::set_permissions(&path, permissions)?;
    std::fs::write(&path, b"bundle for something else")?;
    bed.evidence.set(&bytes, Verified::Nothing);
    let report = bed.sync_at(DAY_LATER, false)?;
    assert_eq!(
        bed.evidence.reverified.get(),
        0,
        "a changed bundle is not verified"
    );
    assert_eq!(
        held(&report, "sampleapp_1.0-1_all.deb"),
        Some(ReasonCode::EEvidenceDowngrade),
        "{report:?}"
    );
    Ok(())
}

#[test]
fn an_asset_replaced_under_a_new_id_in_the_same_release_is_mutated() -> TestResult {
    // GitHub replaces a release asset by deleting it and uploading another
    // file of the same name: the asset ID changes too (R-003 step 3,
    // 664783235 -> 664806807). Other bytes under the name of an admitted
    // file are a replaced asset, never a new artifact to admit.
    let mut bed = bed()?;
    let original = deb(11, "sampleapp", "1.0-1");
    bed.github
        .set(vec![release(1, "v1.0", vec![original.clone()])]);
    bed.sync()?;
    bed.activate(&["sampleapp"])?;
    bed.sync()?;
    assert_eq!(bed.publisher.published.len(), 1);
    let replaced = Asset {
        id: 12,
        bytes: b"sampleapp 1.0-1 replaced under a new id".to_vec(),
        ..original
    };
    bed.github.set(vec![release(1, "v1.0", vec![replaced])]);
    let report = bed.sync_at(AT, true)?;
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
