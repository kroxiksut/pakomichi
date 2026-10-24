#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""R-008 Forgejo package-registry experiment (runs inside the disposable WSL
distribution against a Forgejo on 127.0.0.1:3300).

Usage: forgejo-registry.py OUTDIR
Reads tokens from the lab-only secrets directory, never prints them, and
writes sanitized rows to OUTDIR/forgejo-registry.tsv plus raw responses.
"""
import glob
import gzip
import hashlib
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

OUT = sys.argv[1]
RAW = os.path.join(OUT, "raw")
os.makedirs(RAW, exist_ok=True)
BASE = "http://127.0.0.1:3300"
SECRETS = "/mnt/d/Projects/pakomichi/.research-local/r-008/secrets"
LR = "/mnt/d/Projects/pakomichi/.research-local"
OWNER, OTHER = "lab", "other"
DIST, COMP = "bookworm", "main"


def token(name):
    with open(os.path.join(SECRETS, name)) as f:
        return f.read().strip()


TOK = {OWNER: token("forgejo-token"), OTHER: token("forgejo-token-other")}
ROWS = []


def row(exp, step, req, status, observed, note=""):
    clean = lambda s: str(s).replace("\t", " ").replace("\n", " | ")
    ROWS.append([clean(x) for x in (exp, step, req, status, observed, note)])
    print("\t".join(ROWS[-1]), flush=True)


def http(method, path, body=None, owner=OWNER, ctype=None):
    req = urllib.request.Request(BASE + path, data=body, method=method)
    req.add_header("Authorization", "token " + TOK[owner])
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def save(name, data):
    p = os.path.join(RAW, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def fixture(pattern, prefix):
    for p in glob.glob(LR + pattern, recursive=True):
        b = open(p, "rb").read()
        if sha256(b).startswith(prefix):
            return p, b
    raise SystemExit("fixture %s not found" % prefix)


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, errors="replace", **kw)


def gpg_home(name):
    h = "/tmp/r008/gnupg-" + name
    sh(["rm", "-rf", h])
    os.makedirs(h, mode=0o700)
    return h


def gpg(home, *args):
    return sh(["gpg", "--batch", "--homedir", home, "--status-fd", "1"] + list(args))


def key_info(armored_path):
    r = sh(["gpg", "--batch", "--show-keys", "--with-colons", armored_path])
    fprs = [l.split(":")[9] for l in r.stdout.splitlines() if l.startswith("fpr")]
    pub = [l.split(":") for l in r.stdout.splitlines() if l.startswith("pub")]
    algo = {"1": "RSA", "17": "DSA", "22": "EdDSA", "19": "ECDSA"}.get(pub[0][3], pub[0][3])
    return {"fpr": fprs, "algo": "%s-%s" % (algo, pub[0][2]), "created": pub[0][5],
            "expires": pub[0][6] or "none", "caps": pub[0][11], "uid": [l.split(":")[9] for l in r.stdout.splitlines() if l.startswith("uid")]}


def deb_url(owner, tail):
    return "/api/packages/%s/debian/%s" % (owner, tail)


def deb_snapshot(tag, owner=OWNER, exp="deb", check_sigs=True, home=None):
    """Fetch Release/InRelease/Release.gpg/Packages and return summary."""
    d = {}
    for f in ("Release", "InRelease", "Release.gpg"):
        s, h, b = http("GET", deb_url(owner, "dists/%s/%s" % (DIST, f)), owner=owner)
        d[f] = (s, b)
        save("%s-%s-%s-%s" % (exp, owner, tag, f), b)
    rel = d["Release"][1].decode("utf8", "replace")
    fields = {}
    for l in rel.splitlines():
        m = re.match(r"^([A-Za-z0-9-]+):(.*)$", l)
        if m:
            fields[m.group(1)] = m.group(2).strip()
    pk = {}
    for arch in ("amd64", "all"):
        s, h, b = http("GET", deb_url(owner, "dists/%s/%s/binary-%s/Packages" % (DIST, COMP, arch)), owner=owner)
        pk[arch] = (s, b)
        save("%s-%s-%s-Packages-%s" % (exp, owner, tag, arch), b)
    sigs = ""
    if check_sigs and home:
        r1 = gpg(home, "--verify", os.path.join(RAW, "%s-%s-%s-Release.gpg" % (exp, owner, tag)),
                 os.path.join(RAW, "%s-%s-%s-Release" % (exp, owner, tag)))
        r2 = gpg(home, "--verify", os.path.join(RAW, "%s-%s-%s-InRelease" % (exp, owner, tag)))
        g = lambda r: ",".join(re.findall(r"\[GNUPG:\] (GOODSIG|BADSIG|ERRSIG|NO_PUBKEY|VALIDSIG)", r.stdout)) or "none"
        v = lambda r: (re.findall(r"VALIDSIG \S+ \S+ \S+ \S+ \S+ \S+ \S+ \S+ \S+ (\S+)", r.stdout) or ["-"])[0]
        sigs = "Release.gpg=%s(primary %s) InRelease=%s(primary %s)" % (g(r1), v(r1), g(r2), v(r2))
    return fields, rel, pk, d, sigs


def packages_entry(pk_bytes, name, version):
    txt = pk_bytes.decode("utf8", "replace")
    for st in txt.split("\n\n"):
        if re.search(r"^Package: %s$" % re.escape(name), st, re.M) and re.search(r"^Version: %s$" % re.escape(version), st, re.M):
            return {m.group(1): m.group(2) for m in re.finditer(r"^([A-Za-z0-9-]+): (.*)$", st, re.M)}
    return None


def main():
    # ---- fixtures
    p1, b1 = fixture("/r-003/owner-step1-*/downloads/s1/*_0.1.0_all.deb", "8fcda58d")
    pA, bA = fixture("/r-003/owner-step2-*/downloads/s2/*_0.2.0_all.deb", "93b4dc42")
    pB, bB = fixture("/r-003/owner-step3-*/downloads/s3/*_0.2.0_all.deb", "a59a5cfd")
    row("fixtures", "deb", "sha256", "-", "0.1.0=%s 0.2.0A=%s 0.2.0B=%s" % (sha256(b1), sha256(bA), sha256(bB)),
        "sizes %d/%d/%d" % (len(b1), len(bA), len(bB)))
    for n, p in (("0.1.0", p1), ("0.2.0A", pA), ("0.2.0B", pB)):
        r = sh(["dpkg-deb", "-f", p, "Package", "Version", "Architecture"])
        row("fixtures", "deb-control", n, "-", r.stdout.replace("\n", "; "))
    DEBPKG = "pakomichi-r003-fixture"

    # ---- Q1: signing key, per owner
    keys = {}
    for o in (OWNER, OTHER):
        # key is created lazily with the first Debian publication of the owner
        s, h, b = http("PUT", deb_url(o, "pool/%s/%s/upload" % (DIST, COMP)), b1, owner=o, ctype="application/octet-stream")
        row("deb-key", "upload-0.1.0-" + o, "PUT debian/pool/%s/%s/upload" % (DIST, COMP), s, b.decode("utf8", "replace")[:200])
        s, h, b = http("GET", deb_url(o, "repository.key"), owner=o)
        p = save("deb-%s-repository.key" % o, b)
        info = key_info(p)
        keys[o] = info
        row("deb-key", "repository.key-" + o, "GET debian/repository.key", s,
            "fpr=%s algo=%s created=%s expires=%s caps=%s uid=%s" % (",".join(info["fpr"]), info["algo"], info["created"], info["expires"], info["caps"], info["uid"]),
            "content-type=%s" % h.get("Content-Type"))
    row("deb-key", "same-key-across-owners", "compare", "-", str(keys[OWNER]["fpr"] == keys[OTHER]["fpr"]),
        "lab=%s other=%s" % (keys[OWNER]["fpr"][0], keys[OTHER]["fpr"][0]))

    home = gpg_home("deb")
    gpg(home, "--import", os.path.join(RAW, "deb-lab-repository.key"))

    # ---- Q2: Release file
    t0 = time.time()
    fields, rel, pk, d, sigs = deb_snapshot("s1-after-0.1.0", home=home)
    row("deb-release", "Release", "GET dists/%s/Release" % DIST, d["Release"][0],
        "; ".join("%s=%s" % (k, v[:80]) for k, v in fields.items() if k not in ("MD5Sum", "SHA1", "SHA256", "SHA512")),
        "hash sections: " + ",".join(k for k in fields if k in ("MD5Sum", "SHA1", "SHA256", "SHA512")) + "; " + ("sections present: " + ",".join(re.findall(r"^(MD5Sum|SHA1|SHA256|SHA512):", rel, re.M))))
    row("deb-release", "Valid-Until", "grep Release", "-", "present" if "Valid-Until" in fields else "absent")
    row("deb-release", "Acquire-By-Hash", "grep Release", "-", fields.get("Acquire-By-Hash", "absent"))
    row("deb-release", "signatures", "gpg --verify Release.gpg / InRelease", "-", sigs,
        "statuses Release=%s InRelease=%s Release.gpg=%s" % (d["Release"][0], d["InRelease"][0], d["Release.gpg"][0]))
    row("deb-release", "release-listing", "Release hash lines (SHA256)", "-",
        " | ".join(re.findall(r"^ [0-9a-f]{64} +\d+ (\S+)$", rel, re.M)))
    for a in ("amd64", "all"):
        row("deb-release", "Packages-binary-" + a, "GET Packages", pk[a][0], "bytes=%d entry=%s" % (len(pk[a][1]), packages_entry(pk[a][1], DEBPKG, "0.1.0") is not None))
    # does Date change without a package change?
    time.sleep(3)
    f2, _, _, _, _ = deb_snapshot("s1b-recheck", home=home, check_sigs=False)
    row("deb-release", "Date-stable-without-change", "re-GET Release after 3 s", "-", "Date1=%s Date2=%s" % (fields.get("Date"), f2.get("Date")))

    # ---- Q3: same version, new bytes
    time.sleep(2)
    s, h, b = http("PUT", deb_url(OWNER, "pool/%s/%s/upload" % (DIST, COMP)), bA, ctype="application/octet-stream")
    row("deb-replace", "upload-0.2.0-A", "PUT upload", s, b.decode("utf8", "replace")[:200])
    fA, _, pkA, dA, sA = deb_snapshot("s2-after-0.2.0A", home=home)
    eA = packages_entry(pkA["all"][1], DEBPKG, "0.2.0") or packages_entry(pkA["amd64"][1], DEBPKG, "0.2.0")
    row("deb-replace", "index-after-A", "Packages", pkA["all"][0], "SHA256=%s Size=%s Filename=%s" % (eA and eA.get("SHA256"), eA and eA.get("Size"), eA and eA.get("Filename")),
        "Date=%s; %s" % (fA.get("Date"), sA))
    time.sleep(2)
    s, h, b = http("GET", deb_url(OWNER, "pool/%s/%s/%s_0.2.0_all.deb" % (DIST, COMP, DEBPKG)))
    row("deb-replace", "pool-download-A", "GET pool/..._0.2.0_all.deb", s, "sha256=%s" % sha256(b), "A=%s" % sha256(bA))

    apt = AptTest(keyfile=os.path.join(RAW, "deb-lab-repository.key"))
    apt.setup()
    apt.update("A")
    apt.download("A-after-update", DEBPKG, "0.2.0", sha256(bA), sha256(bB))

    time.sleep(2)
    s, h, b = http("PUT", deb_url(OWNER, "pool/%s/%s/upload" % (DIST, COMP)), bB, ctype="application/octet-stream")
    row("deb-replace", "upload-0.2.0-B-duplicate", "PUT upload (same name/version/arch)", s, b.decode("utf8", "replace")[:300])
    fD, _, pkD, dD, sD = deb_snapshot("s3-after-dup-B", home=home)
    eD = packages_entry(pkD["all"][1], DEBPKG, "0.2.0") or packages_entry(pkD["amd64"][1], DEBPKG, "0.2.0")
    row("deb-replace", "index-after-duplicate", "Packages", pkD["all"][0], "SHA256=%s" % (eD and eD.get("SHA256")), "Date=%s (before %s); %s" % (fD.get("Date"), fA.get("Date"), sD))

    s, h, b = http("GET", "/api/v1/packages/%s/debian/%s/0.2.0" % (OWNER, DEBPKG))
    save("deb-version-before-delete.json", b)
    row("deb-replace", "version-meta-before-delete", "GET /api/v1/packages/lab/debian/NAME/0.2.0", s, b.decode("utf8", "replace")[:400])
    s, h, b = http("GET", "/api/v1/packages/%s/debian/%s/0.2.0/files" % (OWNER, DEBPKG))
    save("deb-files-before-delete.json", b)
    row("deb-replace", "files-before-delete", "GET .../0.2.0/files", s, b.decode("utf8", "replace")[:600])

    time.sleep(2)
    s, h, b = http("DELETE", "/api/v1/packages/%s/debian/%s/0.2.0" % (OWNER, DEBPKG))
    row("deb-replace", "delete-0.2.0", "DELETE /api/v1/packages/lab/debian/NAME/0.2.0", s, b.decode("utf8", "replace")[:200])
    fX, _, pkX, dX, sX = deb_snapshot("s4-after-delete", home=home)
    eX = packages_entry(pkX["all"][1], DEBPKG, "0.2.0") or packages_entry(pkX["amd64"][1], DEBPKG, "0.2.0")
    row("deb-replace", "index-after-delete", "Packages", pkX["all"][0], "0.2.0 entry=%s" % (eX is not None), "Date=%s; %s" % (fX.get("Date"), sX))

    time.sleep(2)
    s, h, b = http("PUT", deb_url(OWNER, "pool/%s/%s/upload" % (DIST, COMP)), bB, ctype="application/octet-stream")
    row("deb-replace", "upload-0.2.0-B-after-delete", "PUT upload", s, b.decode("utf8", "replace")[:200])
    fB, _, pkB, dB, sB = deb_snapshot("s5-after-B", home=home)
    eB = packages_entry(pkB["all"][1], DEBPKG, "0.2.0") or packages_entry(pkB["amd64"][1], DEBPKG, "0.2.0")
    row("deb-replace", "index-after-B", "Packages", pkB["all"][0],
        "SHA256=%s Size=%s equals_B=%s equals_A=%s" % (eB and eB.get("SHA256"), eB and eB.get("Size"), eB and eB.get("SHA256") == sha256(bB), eB and eB.get("SHA256") == sha256(bA)),
        "Date=%s (A-time %s); %s" % (fB.get("Date"), fA.get("Date"), sB))
    s, h, b = http("GET", deb_url(OWNER, "pool/%s/%s/%s_0.2.0_all.deb" % (DIST, COMP, DEBPKG)))
    row("deb-replace", "pool-download-after-B", "GET pool/..._0.2.0_all.deb", s, "sha256=%s" % sha256(b), "equals_B=%s equals_A=%s" % (sha256(b) == sha256(bB), sha256(b) == sha256(bA)))
    s, h, b = http("GET", deb_url(OWNER, "repository.key"))
    save("deb-lab-repository-after.key", b)
    ki = key_info(os.path.join(RAW, "deb-lab-repository-after.key"))
    row("deb-replace", "key-after", "GET repository.key", s, "fpr=%s same_as_before=%s" % (",".join(ki["fpr"]), ki["fpr"] == keys[OWNER]["fpr"]))
    s, h, b = http("GET", "/api/v1/packages/%s/debian/%s/0.2.0" % (OWNER, DEBPKG))
    save("deb-version-after.json", b)
    row("deb-replace", "version-meta-after", "GET /api/v1/packages/lab/debian/NAME/0.2.0", s, b.decode("utf8", "replace")[:400],
        "compare id/created_at with before-delete row")
    s, h, b = http("GET", "/api/v1/packages/%s?type=debian" % OWNER)
    save("deb-package-list-after.json", b)
    row("deb-replace", "package-list", "GET /api/v1/packages/lab?type=debian", s, b.decode("utf8", "replace")[:900],
        "history trace check: look for the deleted version id")

    # apt after replacement
    apt.download("B-stale-index", DEBPKG, "0.2.0", sha256(bA), sha256(bB))
    apt.update("B")
    apt.download("B-after-update", DEBPKG, "0.2.0", sha256(bA), sha256(bB))

    rpm_part()

    with open(os.path.join(OUT, "forgejo-registry.tsv"), "w") as f:
        f.write("experiment\tstep\trequest\thttp_status\tobserved\tnote\n")
        for r in ROWS:
            f.write("\t".join(r) + "\n")


class AptTest:
    def __init__(self, keyfile):
        self.d = "/tmp/r008/apt"
        self.keyfile = keyfile

    def opts(self):
        d = self.d
        return ["-o", "Dir::Etc::sourcelist=%s/sources.list" % d, "-o", "Dir::Etc::sourceparts=/nonexistent",
                "-o", "Dir::State=%s/state" % d, "-o", "Dir::State::status=/var/lib/dpkg/status",
                "-o", "Dir::Cache=%s/cache" % d, "-o", "APT::Sandbox::User=root"]

    def setup(self):
        d = self.d
        sh(["rm", "-rf", d])
        for p in ("state/lists/partial", "cache/archives/partial", "dl"):
            os.makedirs(os.path.join(d, p))
        sh(["cp", self.keyfile, d + "/key.asc"])
        with open(d + "/sources.list", "w") as f:
            f.write("deb [signed-by=%s/key.asc arch=amd64] %s/api/packages/%s/debian %s %s\n" % (d, BASE, OWNER, DIST, COMP))

    def update(self, tag):
        r = sh(["apt-get"] + self.opts() + ["update"])
        save("apt-update-%s.txt" % tag, (r.stdout + "\n--stderr--\n" + r.stderr).encode())
        row("apt", "update-" + tag, "apt-get update", r.returncode, " | ".join((r.stdout + r.stderr).strip().splitlines())[-500:])

    def download(self, tag, name, ver, shaA, shaB):
        dl = self.d + "/dl"
        for f in glob.glob(dl + "/*"):
            os.remove(f)
        r = sh(["apt-get"] + self.opts() + ["download", "%s=%s" % (name, ver)], cwd=dl)
        files = glob.glob(dl + "/*.deb")
        got = sha256(open(files[0], "rb").read()) if files else None
        save("apt-download-%s.txt" % tag, (r.stdout + "\n--stderr--\n" + r.stderr).encode())
        row("apt", "download-" + tag, "apt-get download %s=%s" % (name, ver), r.returncode,
            "file=%s sha256=%s is_A=%s is_B=%s" % (bool(files), got, got == shaA, got == shaB),
            " | ".join((r.stdout + r.stderr).strip().splitlines())[-400:])


def rpm_part():
    R1A = glob.glob(LR + "/r-001/layouts/rpm/equal/alpha/sampleapp-1.0-1.noarch.rpm")
    R1B = glob.glob(LR + "/r-001/layouts/rpm/equal/beta/sampleapp-1.0-1.noarch.rpm")
    bA = open(R1A[0], "rb").read()
    bB = open(R1B[0], "rb").read()
    row("rpm-fixtures", "sampleapp-1.0-1.noarch", "sha256", "-", "A=%s (%d) B=%s (%d)" % (sha256(bA), len(bA), sha256(bB), len(bB)))
    up = lambda body: http("PUT", "/api/packages/%s/rpm/upload" % OWNER, body, ctype="application/octet-stream")
    s, h, b = up(bA)
    row("rpm-replace", "upload-A", "PUT rpm/upload", s, b.decode("utf8", "replace")[:200])
    s, h, b = http("GET", "/api/packages/%s/rpm/repository.key" % OWNER)
    save("rpm-repository.key", b)
    ki = key_info(os.path.join(RAW, "rpm-repository.key"))
    row("rpm-key", "repository.key", "GET rpm/repository.key", s,
        "fpr=%s algo=%s created=%s expires=%s uid=%s" % (",".join(ki["fpr"]), ki["algo"], ki["created"], ki["expires"], ki["uid"]))
    deb_key = key_info(os.path.join(RAW, "deb-lab-repository.key"))
    row("rpm-key", "same-as-deb-key", "compare", "-", str(ki["fpr"] == deb_key["fpr"]), "rpm=%s deb=%s" % (ki["fpr"][0], deb_key["fpr"][0]))
    home = gpg_home("rpm")
    gpg(home, "--import", os.path.join(RAW, "rpm-repository.key"))

    def snap(tag):
        out = {}
        for f in ("repomd.xml", "repomd.xml.asc"):
            s, h, b = http("GET", "/api/packages/%s/rpm/repodata/%s" % (OWNER, f))
            out[f] = (s, b)
            save("rpm-%s-%s" % (tag, f), b)
        x = out["repomd.xml"][1].decode("utf8", "replace")
        rv = re.search(r"<revision>(\d+)</revision>", x)
        ts = re.findall(r"<timestamp>(\d+)</timestamp>", x)
        v = gpg(home, "--verify", os.path.join(RAW, "rpm-%s-repomd.xml.asc" % tag), os.path.join(RAW, "rpm-%s-repomd.xml" % tag))
        sig = ",".join(re.findall(r"\[GNUPG:\] (GOODSIG|BADSIG|ERRSIG|NO_PUBKEY)", v.stdout)) or "none"
        pm = re.search(r'<data type="primary">.*?<location href="([^"]+)"', x, re.S)
        ent = None
        if pm:
            s, h, b = http("GET", "/api/packages/%s/rpm/%s" % (OWNER, pm.group(1)))
            save("rpm-%s-primary.xml.gz" % tag, b)
            try:
                px = gzip.decompress(b).decode("utf8", "replace")
            except Exception:
                px = b.decode("utf8", "replace")
            m = re.search(r'<checksum type="sha256" pkgid="YES">([0-9a-f]+)</checksum>', px)
            sz = re.search(r'<size package="(\d+)"', px)
            ent = (m and m.group(1), sz and sz.group(1))
        return x, rv and rv.group(1), ts, sig, ent, out

    x1, rev1, ts1, sig1, ent1, o1 = snap("s1-after-A")
    row("rpm-release", "repomd", "GET rpm/repodata/repomd.xml (+.asc)", "%s/%s" % (o1["repomd.xml"][0], o1["repomd.xml.asc"][0]),
        "revision=%s timestamps=%s asc=%s primary_pkg_sha256=%s size=%s" % (rev1, ts1, sig1, ent1 and ent1[0], ent1 and ent1[1]),
        "hash types: %s; has Valid-Until-like field: n/a (repomd has no expiry)" % ",".join(sorted(set(re.findall(r'<(?:open-)?checksum type="(\w+)"', x1)))))
    time.sleep(2)
    s, h, b = up(bB)
    row("rpm-replace", "upload-B-duplicate", "PUT rpm/upload same NEVRA different bytes", s, b.decode("utf8", "replace")[:300])
    s, h, b = http("GET", "/api/v1/packages/%s?type=rpm" % OWNER)
    save("rpm-package-list.json", b)
    row("rpm-replace", "package-list", "GET /api/v1/packages/lab?type=rpm", s, b.decode("utf8", "replace")[:600])
    m = re.search(r'"name":"([^"]+)".*?"version":"([^"]+)"', b.decode("utf8", "replace"))
    name, ver = (m.group(1), m.group(2)) if m else ("sampleapp", "1.0-1")
    x2, rev2, ts2, sig2, ent2, _ = snap("s2-after-dup")
    row("rpm-replace", "index-after-duplicate", "repomd/primary", "-", "revision=%s pkg_sha256=%s equals_A=%s" % (rev2, ent2 and ent2[0], ent2 and ent2[0] == sha256(bA)))
    time.sleep(2)
    s, h, b = http("DELETE", "/api/v1/packages/%s/rpm/%s/%s" % (OWNER, name, ver))
    row("rpm-replace", "delete", "DELETE /api/v1/packages/lab/rpm/%s/%s" % (name, ver), s, b.decode("utf8", "replace")[:200])
    time.sleep(2)
    s, h, b = up(bB)
    row("rpm-replace", "upload-B-after-delete", "PUT rpm/upload", s, b.decode("utf8", "replace")[:200])
    x3, rev3, ts3, sig3, ent3, _ = snap("s3-after-B")
    row("rpm-replace", "index-after-B", "repomd/primary", "-",
        "revision=%s timestamps=%s asc=%s pkg_sha256=%s equals_B=%s equals_A=%s" % (rev3, ts3, sig3, ent3 and ent3[0], ent3 and ent3[0] == sha256(bB), ent3 and ent3[0] == sha256(bA)),
        "revision before=%s" % rev1)
    s, h, b = http("GET", "/api/packages/%s/rpm/repository.key" % OWNER)
    save("rpm-repository-after.key", b)
    ka = key_info(os.path.join(RAW, "rpm-repository-after.key"))
    row("rpm-replace", "key-after", "GET rpm/repository.key", s, "same_as_before=%s" % (ka["fpr"] == ki["fpr"]))


if __name__ == "__main__":
    main()
