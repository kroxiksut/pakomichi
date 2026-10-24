# SPDX-License-Identifier: MIT OR Apache-2.0
"""R-008 phase B: identity, rename, transfer, asset replacement and Debian
registry experiments on gitea.com (disposable fixtures, label below).

Run inside WSL:  python3 -I research/r-008/gitea.py [--stamp STAMP] [--only E1,E2,...]
The token is read from .research-local/r-008/secrets/gitea-token and is never
printed or written. Raw data: .research-local/r-008/gitea-<stamp>/.
"""
import base64
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = "/mnt/d/Projects/pakomichi"
TOKEN_FILE = ROOT + "/.research-local/r-008/secrets/gitea-token"
R3 = ROOT + "/.research-local/r-003/"
BASE = "https://gitea.com"
API = BASE + "/api/v1"
LOGIN = "kroxiksut"
IDENT = {"name": "kroxiksut", "email": "kroxiksut@noreply.gitea.com"}
LABEL = ("Created by an AI agent (Claude) on the owner's instructions for "
         "Pakomichi research R-008. Disposable test fixture.")
ORG_A = "pchi-test-gitea-a"
ORG_B = "pchi-test-gitea-b"
UA = "pakomichi-research-r008"
NAME = "pakomichi-r003-fixture"

FIXTURES = {
    "0.1.0": (R3 + "owner-step1-20261022T050816Z/downloads/s1/664728438-pakomichi-r003-fixture_0.1.0_all.deb", "8fcda58d"),
    "0.2.0-a": (R3 + "owner-step2-20261022T053242Z/downloads/s2/664783235-pakomichi-r003-fixture_0.2.0_all.deb", "93b4dc42"),
    "0.2.0-b": (R3 + "owner-step3-20261022T054617Z/downloads/s3/664806807-pakomichi-r003-fixture_0.2.0_all.deb", "a59a5cfd"),
}

TOKEN = open(TOKEN_FILE).read().strip()
EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

stamp = None
only = None
args = sys.argv[1:]
while args:
    a = args.pop(0)
    if a == "--stamp":
        stamp = args.pop(0)
    elif a == "--only":
        only = args.pop(0).split(",")
if not stamp:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
RAW = ROOT + "/.research-local/r-008/gitea-" + stamp
os.makedirs(RAW, exist_ok=True)
STATE_F = RAW + "/state.json"
STATE = json.load(open(STATE_F)) if os.path.exists(STATE_F) else {}
ROWS = []
SEQ = [0]
OTHER_EMAILS = [0]
STOP = [False]


def save_state():
    json.dump(STATE, open(STATE_F, "w"), indent=1)


def redact(b):
    def f(m):
        s = m.group(0)
        if s.lower().endswith(b"@noreply.gitea.com"):
            return s
        OTHER_EMAILS[0] += 1
        return b"<redacted-email>"
    return EMAIL_RE.sub(f, b)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


class Resp:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def h(self, k):
        return self.headers.get(k.lower())

    def json(self):
        try:
            return json.loads(self.body)
        except Exception:
            return None


def http(method, url, headers=None, data=None, label="x", save_body=True):
    hd = {"User-Agent": UA}
    hd.update(headers or {})
    for attempt in range(3):
        rq = urllib.request.Request(url, data=data, method=method, headers=hd)
        try:
            r = OPENER.open(rq, timeout=120)
            st, hs, body = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            st, hs, body = e.code, e.headers, e.read()
        except Exception as e:
            st, hs, body = 0, {}, ("ERR %s" % type(e).__name__).encode()
        hdrs = {k.lower(): v for k, v in hs.items()} if hs else {}
        if st == 429 and attempt < 2:
            time.sleep(min(int(hdrs.get("retry-after", "5") or 5), 30))
            continue
        break
    SEQ[0] += 1
    base = "%s/%03d-%s" % (RAW, SEQ[0], re.sub(r"[^A-Za-z0-9._-]", "_", label))
    with open(base + ".hdr", "w") as f:
        f.write("%s %s\nstatus %s\n" % (method, url, st))
        for k, v in hdrs.items():
            f.write("%s: %s\n" % (k, v))
    if save_body:
        with open(base + ".body", "wb") as f:
            f.write(redact(body[:2000000]))
    time.sleep(0.3)
    return Resp(st, hdrs, body)


def api(method, path, obj=None, auth=True, extra=None, label=None, url=None):
    hd = dict(extra or {})
    data = None
    if obj is not None:
        data = json.dumps(obj).encode()
        hd["Content-Type"] = "application/json"
    if auth:
        hd["Authorization"] = "token " + TOKEN
    u = url or (API + path)
    return http(method, u, hd, data, label or (method + path))


def pkg_auth():
    return "Basic " + base64.b64encode((LOGIN + ":" + TOKEN).encode()).decode()


PRESIGNED = re.compile(r"https://[A-Za-z0-9.-]+\.r2\.cloudflarestorage\.com/[^\s'\"\]\)]*")


def row(exp, step, request, status, observed, note=""):
    # Presigned storage URLs carry a signature: never in the published table.
    clean = lambda s: PRESIGNED.sub(
        "https://<account>.r2.cloudflarestorage.com/<presigned URL redacted>",
        str(s).replace("\t", " ").replace("\n", " ").replace("\r", " "))
    ROWS.append([exp, step, clean(request), clean(status), clean(observed), clean(note)])
    print("%s %s %s -> %s | %s" % (exp, step, request, status, str(observed)[:150]))


def hdrsum(r, keys=("etag", "last-modified", "cache-control", "location", "content-length", "content-type")):
    return "; ".join("%s=%s" % (k, r.h(k)) for k in keys if r.h(k))


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def commit_file(owner, repo, path, text, msg):
    body = {
        "content": base64.b64encode(text.encode()).decode(),
        "message": msg + "\n\n" + LABEL,
        "author": IDENT, "committer": IDENT,
    }
    r = api("POST", "/repos/%s/%s/contents/%s" % (owner, repo, path), body, label="commit-%s-%s" % (repo, path))
    sha = None
    if r.json() and r.json().get("commit"):
        sha = r.json()["commit"].get("sha")
    ok = None
    if sha:
        c = api("GET", "/repos/%s/%s/git/commits/%s" % (owner, repo, sha), label="gitcommit-" + repo)
        j = c.json() or {}
        emails = set()
        for k in ("author", "committer"):
            emails.add(((j.get("commit") or {}).get(k) or {}).get("email"))
        ok = emails == {IDENT["email"]}
        row("IDENT", "commit identity " + owner + "/" + repo, "GET git/commits/<sha>", c.status,
            "author/committer e-mails = %s" % sorted(map(str, emails)), "OK" if ok else "MISMATCH - stop")
        if not ok:
            STOP[0] = True
            raise SystemExit("commit identity mismatch")
    return r, sha


def get_deb(key):
    p, pre = FIXTURES[key]
    b = open(p, "rb").read()
    h = sha256(b)
    assert h.startswith(pre), (key, h)
    return b, h


def multipart(field, filename, content):
    bnd = "----r008" + hashlib.md5(filename.encode()).hexdigest()
    body = (("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
             "Content-Type: application/octet-stream\r\n\r\n" % (bnd, field, filename)).encode()
            + content + ("\r\n--%s--\r\n" % bnd).encode())
    return body, "multipart/form-data; boundary=" + bnd


def follow_download(url, label):
    """Manual redirect following, no credentials. Returns (final Resp, chain)."""
    chain = []
    for i in range(6):
        r = http("GET", url, {}, None, "%s-hop%d" % (label, i), save_body=False)
        chain.append((r.status, url.split("?")[0] if i else url, r.h("location")))
        if r.status in (301, 302, 303, 307, 308) and r.h("location"):
            url = urllib.parse.urljoin(url, r.h("location"))
            continue
        return r, chain
    return r, chain


def repo_fields(j):
    if not j:
        return "no json"
    return "id=%s owner.id=%s full_name=%s has_actions=%s has_packages=%s has_releases=%s default_branch=%s" % (
        j.get("id"), (j.get("owner") or {}).get("id"), j.get("full_name"),
        j.get("has_actions"), j.get("has_packages"), j.get("has_releases"), j.get("default_branch"))


# ---------------------------------------------------------------- E1
def e1():
    for org in (ORG_A, ORG_B):
        r = api("POST", "/orgs", {"username": org, "full_name": org, "description": LABEL, "visibility": "public"}, label="create-org-" + org)
        j = r.json() or {}
        if r.status not in (200, 201):
            row("E1", "create org " + org, "POST /orgs", r.status, (r.body[:200]).decode(errors="replace"), "name taken or error")
            STATE.setdefault("errors", []).append("org " + org)
            continue
        STATE["org_" + org] = {"id": j.get("id"), "username": j.get("username")}
        row("E1", "create org " + org, "POST /orgs", r.status, "id=%s username=%s visibility=%s" % (j.get("id"), j.get("username"), j.get("visibility")))
    save_state()
    r = api("POST", "/orgs/%s/repos" % ORG_A, {"name": "pchi-test", "description": LABEL, "private": False, "auto_init": False}, label="create-repo")
    j = r.json() or {}
    row("E1", "create repo", "POST /orgs/A/repos", r.status, repo_fields(j))
    STATE["repo1"] = {"id": j.get("id"), "owner_id": (j.get("owner") or {}).get("id")}
    save_state()
    rr, sha = commit_file(ORG_A, "pchi-test", "README.md", "# pchi-test\n\n" + LABEL + "\n", "Add README")
    row("E1", "first commit", "POST contents/README.md", rr.status, "commit sha=%s" % sha)
    rid = STATE["repo1"]["id"]
    nm = "/repos/%s/pchi-test" % ORG_A
    cases = [("by name anonymous", nm, False), ("by name token", nm, True),
             ("by id anonymous", "/repositories/%s" % rid, False), ("by id token", "/repositories/%s" % rid, True)]
    for step, p, auth in cases:
        r = api("GET", p, auth=auth, label="e1-" + step.replace(" ", "-"))
        j = r.json() or {}
        row("E1", step, "GET " + p, r.status, repo_fields(j) if r.status == 200 else r.body[:120].decode(errors="replace"),
            hdrsum(r) + "; ratelimit=" + str({k: v for k, v in r.headers.items() if "ratelimit" in k or "rate-limit" in k}))
        et, lm = r.h("etag"), r.h("last-modified")
        if et:
            r2 = api("GET", p, auth=auth, extra={"If-None-Match": et}, label="e1-inm-" + step.replace(" ", "-"))
            row("E1", step + " If-None-Match", "GET " + p, r2.status, "304 expected if validators work", "etag sent=" + et)
        if lm:
            r3 = api("GET", p, auth=auth, extra={"If-Modified-Since": lm}, label="e1-ims-" + step.replace(" ", "-"))
            row("E1", step + " If-Modified-Since", "GET " + p, r3.status, "", "lm sent=" + lm)
        if not et and not lm:
            row("E1", step + " validators", "GET " + p, r.status, "no ETag and no Last-Modified")


# ---------------------------------------------------------------- E2
def web_probe(exp, step, path):
    r = http("GET", BASE + path, {}, None, "web-" + re.sub(r"\W", "_", path), save_body=False)
    row(exp, step, "GET " + path + " (web, no follow)", r.status, "location=%s" % r.h("location"), hdrsum(r, ("cache-control",)))
    return r


def e2():
    rid = STATE["repo1"]["id"]
    r = api("PATCH", "/repos/%s/pchi-test" % ORG_A, {"name": "pchi-test-renamed"}, label="rename")
    j = r.json() or {}
    row("E2", "rename", "PATCH /repos/A/pchi-test", r.status, repo_fields(j))
    r = api("GET", "/repos/%s/pchi-test-renamed" % ORG_A, label="e2-new")
    row("E2", "new name", "GET /repos/A/pchi-test-renamed", r.status, repo_fields(r.json()) + " (id before=%s)" % rid)
    for auth in (False, True):
        r = api("GET", "/repos/%s/pchi-test" % ORG_A, auth=auth, label="e2-old-%s" % auth)
        row("E2", "old name API %s" % ("token" if auth else "anonymous"), "GET /repos/A/pchi-test", r.status,
            "location=%s; %s" % (r.h("location"), repo_fields(r.json()) if r.status == 200 else r.body[:150].decode(errors="replace")))
    r = api("GET", "/repositories/%s" % rid, label="e2-byid")
    row("E2", "by ID after rename", "GET /repositories/<id>", r.status, repo_fields(r.json()))
    web_probe("E2", "old web URL", "/%s/pchi-test" % ORG_A)
    web_probe("E2", "new web URL", "/%s/pchi-test-renamed" % ORG_A)
    # git smart-HTTP old URL
    r = http("GET", BASE + "/%s/pchi-test.git/info/refs?service=git-upload-pack" % ORG_A, {}, None, "e2-git-old", save_body=False)
    row("E2", "old git URL", "GET /A/pchi-test.git/info/refs", r.status, "location=%s" % r.h("location"))


# ---------------------------------------------------------------- E3
def e3():
    old_id = STATE["repo1"]["id"]
    r = api("POST", "/orgs/%s/repos" % ORG_A, {"name": "pchi-test", "description": LABEL, "private": False, "auto_init": False}, label="e3-create")
    j = r.json() or {}
    row("E3", "create new repo with old name", "POST /orgs/A/repos", r.status, repo_fields(j), "old id=%s" % old_id)
    STATE["repo2"] = {"id": j.get("id"), "owner_id": (j.get("owner") or {}).get("id")}
    save_state()
    rr, sha = commit_file(ORG_A, "pchi-test", "README.md", "# pchi-test (second)\n\n" + LABEL + "\n", "Add README")
    row("E3", "first commit", "POST contents/README.md", rr.status, "commit sha=%s" % sha)
    r = api("GET", "/repos/%s/pchi-test" % ORG_A, label="e3-old-name")
    row("E3", "old name now", "GET /repos/A/pchi-test", r.status, repo_fields(r.json()), "new id=%s" % STATE["repo2"]["id"])
    r = api("GET", "/repos/%s/pchi-test-renamed" % ORG_A, label="e3-renamed")
    row("E3", "renamed repo", "GET /repos/A/pchi-test-renamed", r.status, repo_fields(r.json()))
    r = api("GET", "/repositories/%s" % old_id, label="e3-oldid")
    row("E3", "old ID", "GET /repositories/<old id>", r.status, repo_fields(r.json()))
    web_probe("E3", "old name web URL", "/%s/pchi-test" % ORG_A)


# ---------------------------------------------------------------- E4
def e4():
    rid = STATE["repo1"]["id"]
    r = api("GET", "/repositories/%s" % rid, label="e4-before")
    row("E4", "before", "GET /repositories/<id>", r.status, repo_fields(r.json()))
    r = api("POST", "/repos/%s/pchi-test-renamed/transfer" % ORG_A, {"new_owner": ORG_B}, label="e4-transfer")
    j = r.json() or {}
    row("E4", "transfer A -> B", "POST /repos/A/pchi-test-renamed/transfer", r.status, repo_fields(j) if j.get("id") else r.body[:200].decode(errors="replace"))
    time.sleep(2)
    r = api("GET", "/repositories/%s" % rid, label="e4-after-id")
    row("E4", "after, by ID", "GET /repositories/<id>", r.status, repo_fields(r.json()))
    for p in ("/repos/%s/pchi-test-renamed" % ORG_A, "/repos/%s/pchi-test-renamed" % ORG_B):
        r = api("GET", p, label="e4-" + p.split("/")[2])
        row("E4", "path " + p, "GET " + p, r.status, "location=%s; %s" % (r.h("location"), repo_fields(r.json()) if r.status == 200 else r.body[:120].decode(errors="replace")))
    r = api("GET", "/repos/%s/pchi-test-renamed" % ORG_A, auth=False, label="e4-old-anon")
    row("E4", "old path anonymous", "GET /repos/A/pchi-test-renamed", r.status, "location=%s" % r.h("location"))
    web_probe("E4", "old web URL", "/%s/pchi-test-renamed" % ORG_A)
    web_probe("E4", "new web URL", "/%s/pchi-test-renamed" % ORG_B)
    r = api("GET", "/repos/%s/pchi-test-renamed/transfer" % ORG_B, label="e4-pending-probe")
    row("E4", "pending transfer probe", "GET /repos/B/.../transfer", r.status, r.body[:100].decode(errors="replace"), "informational")
    # does the A/pchi-test (new repo, E3) still work
    r = api("GET", "/repos/%s/pchi-test" % ORG_A, label="e4-a-new")
    row("E4", "org A pchi-test unaffected", "GET /repos/A/pchi-test", r.status, repo_fields(r.json()))


# ---------------------------------------------------------------- E5
def e5():
    o, rp = ORG_A, "pchi-test"
    rid = STATE["repo2"]["id"]
    row("E5", "repo used", "-", "-", "%s/%s id=%s (the E3 repo created after the rename)" % (o, rp, rid))
    ra = api("GET", "/repos/%s/%s" % (o, rp), label="e5-repo")
    br = (ra.json() or {}).get("default_branch", "main")
    r = api("POST", "/repos/%s/%s/releases" % (o, rp), {"tag_name": "v0.2.0", "target_commitish": br, "name": "v0.2.0 (R-008 fixture)",
                                                         "body": LABEL, "draft": False, "prerelease": False}, label="e5-release")
    rel = r.json() or {}
    row("E5", "create release", "POST /releases", r.status, "id=%s tag=%s keys=%s" % (rel.get("id"), rel.get("tag_name"), sorted(rel.keys())))
    if r.status not in (200, 201):
        return
    STATE["rel"] = rel["id"]
    save_state()
    # tag identity check
    t = api("GET", "/repos/%s/%s/git/refs/tags/v0.2.0" % (o, rp), label="e5-tagref")
    tj = t.json()
    obj = None
    if isinstance(tj, list) and tj:
        tj = tj[0]
    if tj:
        obj = (tj.get("object") or {})
    row("E5", "tag ref", "GET git/refs/tags/v0.2.0", t.status, "object=%s" % json.dumps(obj))
    if obj and obj.get("type") == "tag":
        tg = api("GET", "/repos/%s/%s/git/tags/%s" % (o, rp, obj["sha"]), label="e5-tagobj")
        tjj = tg.json() or {}
        em = (tjj.get("tagger") or {}).get("email")
        row("E5", "annotated tag tagger", "GET git/tags/<sha>", tg.status, "tagger email=%s" % em)
        if em != IDENT["email"] and em is not None:
            STOP[0] = True
            raise SystemExit("tagger e-mail not the noreply identity")
    relid = rel["id"]
    d1, h1 = get_deb("0.2.0-a")
    d2, h2 = get_deb("0.2.0-b")
    aname = NAME + "_0.2.0_all.deb"
    def upload(data, label):
        body, ct = multipart("attachment", aname, data)
        return api("POST", "/repos/%s/%s/releases/%s/assets?name=%s" % (o, rp, relid, aname), extra={"Content-Type": ct}, label=label, url=None) if False else \
            http("POST", API + "/repos/%s/%s/releases/%s/assets?name=%s" % (o, rp, relid, aname),
                 {"Authorization": "token " + TOKEN, "Content-Type": ct}, body, label)
    r = upload(d1, "e5-upload-a")
    a1 = r.json() or {}
    row("E5", "upload 93b4dc42", "POST releases/<id>/assets?name=", r.status, json.dumps(a1, sort_keys=True))
    if r.status not in (200, 201):
        return
    row("E5", "asset keys", "-", "-", sorted(a1.keys()), "digest/hash field present: %s" % any("hash" in k or "digest" in k or "sha" in k for k in a1))
    url1 = a1.get("browser_download_url")
    fr, chain = follow_download(url1, "e5-dl-a")
    row("E5", "download after upload", "GET browser_download_url", fr.status, "chain=%s" % chain,
        "sha256=%s expected=%s; %s; digest-like headers=%s" % (sha256(fr.body), h1, hdrsum(fr), {k: v for k, v in fr.headers.items() if "digest" in k or "sha" in k or "md5" in k or "checksum" in k}))
    ra1 = api("GET", "/repos/%s/%s/releases/%s" % (o, rp, relid), label="e5-rel-before")
    rj1 = ra1.json() or {}
    row("E5", "release before replace", "GET releases/<id>", ra1.status, "updated_at=%s created_at=%s published_at=%s" % (rj1.get("updated_at"), rj1.get("created_at"), rj1.get("published_at")),
        "keys=%s" % sorted(rj1.keys()))
    # duplicate name while the first exists
    r = upload(d2, "e5-upload-dup")
    dj = r.json() or {}
    row("E5", "second attachment same name while first exists", "POST assets?name=same", r.status,
        (json.dumps(dj, sort_keys=True) if r.status in (200, 201) else r.body[:200].decode(errors="replace")))
    ls = api("GET", "/repos/%s/%s/releases/%s/assets" % (o, rp, relid), label="e5-list-after-dup")
    row("E5", "asset list after duplicate attempt", "GET releases/<id>/assets", ls.status,
        json.dumps([(x.get("id"), x.get("uuid"), x.get("name"), x.get("size")) for x in (ls.json() or [])]))
    # delete every asset with that name, then upload the replaced bytes
    for x in ls.json() or []:
        dr = api("DELETE", "/repos/%s/%s/releases/%s/assets/%s" % (o, rp, relid, x["id"]), label="e5-delete-%s" % x["id"])
        row("E5", "delete asset %s" % x["id"], "DELETE releases/<id>/assets/<aid>", dr.status, "")
    r = upload(d2, "e5-upload-b")
    a2 = r.json() or {}
    row("E5", "upload a59a5cfd under same name", "POST assets?name=", r.status, json.dumps(a2, sort_keys=True))
    row("E5", "compare ids", "-", "-", "id %s -> %s; uuid %s -> %s; url same: %s" % (a1.get("id"), a2.get("id"), a1.get("uuid"), a2.get("uuid"),
                                                                                 a1.get("browser_download_url") == a2.get("browser_download_url")),
        "url1=%s url2=%s" % (a1.get("browser_download_url"), a2.get("browser_download_url")))
    # old URL, new URL
    for lab, u in (("old url", url1), ("new url", a2.get("browser_download_url"))):
        if not u:
            continue
        fr, chain = follow_download(u, "e5-dl-" + lab.replace(" ", "-"))
        row("E5", "download " + lab, "GET url", fr.status, "sha256=%s (a=%s.. b=%s..)" % (sha256(fr.body), h1[:8], h2[:8]), "chain=%s; %s" % (chain, hdrsum(fr)))
    ra2 = api("GET", "/repos/%s/%s/releases/%s" % (o, rp, relid), label="e5-rel-after")
    rj2 = ra2.json() or {}
    row("E5", "release after replace", "GET releases/<id>", ra2.status,
        "updated_at=%s created_at=%s published_at=%s; assets=%s" % (rj2.get("updated_at"), rj2.get("created_at"), rj2.get("published_at"),
                                                                    json.dumps([(x.get("id"), x.get("uuid"), x.get("download_count")) for x in rj2.get("assets", [])])),
        "before updated_at=%s" % rj1.get("updated_at"))
    imm = {k: v for k, v in rj2.items() if "immut" in k or "lock" in k}
    rf = {k: v for k, v in (ra.json() or {}).items() if "immut" in k or "lock" in k or "release" in k}
    row("E5", "immutability fields", "-", "-", "release: %s; repo: %s" % (imm or "none", rf), "release keys: %s" % sorted(rj2.keys()))
    # traces
    for lab, p, au in (("activity feeds", "/repos/%s/%s/activities/feeds" % (o, rp), True),
                       ("events", "/repos/%s/%s/events" % (o, rp), True),
                       ("org-activity", "/orgs/%s/activities/feeds" % o, True)):
        r = api("GET", p, auth=au, label="e5-" + lab.replace(" ", "-"))
        row("E5", "trace: " + lab, "GET " + p, r.status, r.body[:300].decode(errors="replace") if r.status != 200 else ("%d items; op_types=%s" % (len(r.json() or []), [x.get("op_type") for x in (r.json() or [])][:15])))
    for lab, p in (("releases atom", "/%s/%s/releases.atom" % (o, rp)),):
        r = http("GET", BASE + p, {}, None, "e5-atom")
        row("E5", "trace: " + lab, "GET " + p, r.status, "len=%d; mentions asset name=%s" % (len(r.body), aname.encode() in r.body))
    # latest release listing
    r = api("GET", "/repos/%s/%s/releases/tags/v0.2.0" % (o, rp), label="e5-bytag")
    row("E5", "release by tag", "GET releases/tags/v0.2.0", r.status, hdrsum(r))


# ---------------------------------------------------------------- E6
def pkg_url(path):
    return BASE + "/api/packages/%s/debian/%s" % (ORG_A, path)


def pkg_get(path, label, auth=False):
    hd = {"Authorization": pkg_auth()} if auth else {}
    return http("GET", pkg_url(path), hd, None, label)


def armor_parse(text):
    lines = [l for l in text.splitlines() if l and not l.startswith("-----") and not l.startswith("=") and ":" not in l]
    return base64.b64decode("".join(lines))


def parse_key(b):
    """Return (fingerprints of v4 keys, user ids) from binary OpenPGP key."""
    i, fps, uids = 0, [], []
    while i < len(b):
        tag = b[i]
        if not tag & 0x80:
            break
        if tag & 0x40:
            t = tag & 0x3f
            l = b[i + 1]
            if l < 192:
                hl, ln = 2, l
            elif l < 224:
                hl, ln = 3, ((l - 192) << 8) + b[i + 2] + 192
            else:
                hl, ln = 6, int.from_bytes(b[i + 2:i + 6], "big")
        else:
            t = (tag >> 2) & 0xf
            lt = tag & 3
            if lt == 0:
                hl, ln = 2, b[i + 1]
            elif lt == 1:
                hl, ln = 3, int.from_bytes(b[i + 1:i + 3], "big")
            elif lt == 2:
                hl, ln = 5, int.from_bytes(b[i + 1:i + 5], "big")
            else:
                break
        body = b[i + hl:i + hl + ln]
        if t in (6, 14) and body[0] == 4:
            fps.append(("primary" if t == 6 else "subkey", hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper(),
                        "algo=%d created=%d" % (body[5], int.from_bytes(body[1:5], "big"))))
        if t == 13:
            uids.append(body.decode(errors="replace"))
        i += hl + ln
    return fps, uids


def parse_release(txt):
    d = {}
    for l in txt.splitlines():
        if l and not l.startswith(" ") and ":" in l:
            k, v = l.split(":", 1)
            d[k] = v.strip()
    return d


def snapshot_index(tag):
    out = {}
    rels = {}
    for nm in ("Release", "InRelease", "Release.gpg"):
        rels[nm] = pkg_get("dists/pchi/" + nm, "e6-%s-%s" % (tag, nm))
    out["rel"] = rels
    rt = rels["Release"].body.decode(errors="replace")
    rd = parse_release(rt)
    arch = rd.get("Architectures", "").split()
    comp = rd.get("Components", "").split()
    pk = {}
    for c in comp or ["main"]:
        for a in arch or ["amd64"]:
            r = pkg_get("dists/pchi/%s/binary-%s/Packages" % (c, a), "e6-%s-Packages-%s-%s" % (tag, c, a))
            pk["%s/%s" % (c, a)] = r
    out["pk"] = pk
    return out, rd


def summarize_index(exp, tag, out, rd):
    rels = out["rel"]
    row(exp, tag + " Release", "GET dists/pchi/Release", rels["Release"].status,
        "Date=%s; Suite=%s; Codename=%s; Architectures=%s; Components=%s; Valid-Until=%s" % (rd.get("Date"), rd.get("Suite"), rd.get("Codename"), rd.get("Architectures"), rd.get("Components"), rd.get("Valid-Until", "ABSENT")),
        hdrsum(rels["Release"]))
    row(exp, tag + " InRelease", "GET dists/pchi/InRelease", rels["InRelease"].status, "len=%d starts=%r" % (len(rels["InRelease"].body), rels["InRelease"].body[:30]), hdrsum(rels["InRelease"]))
    row(exp, tag + " Release.gpg", "GET dists/pchi/Release.gpg", rels["Release.gpg"].status, "len=%d" % len(rels["Release.gpg"].body), hdrsum(rels["Release.gpg"]))
    for k, r in out["pk"].items():
        txt = r.body.decode(errors="replace")
        ents = [e for e in txt.split("\n\n") if e.strip()]
        summ = []
        for e in ents:
            f = dict(l.split(": ", 1) for l in e.splitlines() if ": " in l and not l.startswith(" "))
            summ.append("%s %s %s size=%s sha256=%s file=%s" % (f.get("Package"), f.get("Version"), f.get("Architecture"), f.get("Size"), f.get("SHA256"), f.get("Filename")))
        row(exp, tag + " Packages " + k, "GET dists/pchi/%s/binary-%s/Packages" % tuple(k.split("/")), r.status, " | ".join(summ) or "empty", hdrsum(r))


def verify_gpg(tmp, keyfile, tag, out):
    if not shutil.which("gpg"):
        row("E6", tag + " signature verification", "gpg", "-", "gpg not installed in the distribution", "fingerprint parsed manually")
        return
    gh = tempfile.mkdtemp(prefix="gh-", dir=tmp)
    os.chmod(gh, 0o700)
    env = dict(os.environ, GNUPGHOME=gh)
    subprocess.run(["gpg", "--batch", "--import", keyfile], env=env, capture_output=True)
    for nm, args2 in (("InRelease", ["--verify"]), ):
        p = os.path.join(tmp, "InRelease-" + tag)
        open(p, "wb").write(out["rel"]["InRelease"].body)
        rr = subprocess.run(["gpg", "--batch", "--status-fd", "1", "--verify", p], env=env, capture_output=True, text=True)
        st = [l for l in rr.stdout.splitlines() if "SIG" in l]
        row("E6", tag + " verify InRelease", "gpg --verify", rr.returncode, " ; ".join(redact(s.encode()).decode() for s in st))
    p1 = os.path.join(tmp, "Release-" + tag)
    p2 = p1 + ".gpg"
    open(p1, "wb").write(out["rel"]["Release"].body)
    open(p2, "wb").write(out["rel"]["Release.gpg"].body)
    rr = subprocess.run(["gpg", "--batch", "--status-fd", "1", "--verify", p2, p1], env=env, capture_output=True, text=True)
    st = [l for l in rr.stdout.splitlines() if "SIG" in l]
    row("E6", tag + " verify Release.gpg", "gpg --verify", rr.returncode, " ; ".join(redact(s.encode()).decode() for s in st))
    shutil.rmtree(gh, ignore_errors=True)


def put_deb(key, path_name, label):
    d, h = get_deb(key)
    r = http("PUT", pkg_url("pool/pchi/main/upload"), {"Authorization": pkg_auth(), "Content-Type": "application/vnd.debian.binary-package"}, d, label)
    return r, h


def e6():
    tmp = tempfile.mkdtemp(prefix="r008-")
    r, h1 = put_deb("0.1.0", "", "e6-put-010")
    row("E6", "upload 0.1.0", "PUT pool/pchi/main/upload", r.status, r.body[:200].decode(errors="replace"), "sha256=" + h1)
    if r.status == 404:
        # registry not served: probe other types and a non-existent owner to see whether the whole /api/packages prefix is blocked
        for lab, m, p in (("debian key, existing org", "GET", "/api/packages/%s/debian/repository.key" % ORG_A),
                          ("debian key, non-existent owner", "GET", "/api/packages/no-such-owner-zzz/debian/repository.key"),
                          ("api/packages root", "GET", "/api/packages/"),
                          ("container /v2/", "GET", "/v2/"),
                          ("org packages web page", "GET", "/%s/-/packages" % ORG_A)):
            x = http(m, BASE + p, {}, None, "e6-probe-" + re.sub(r"\W", "_", lab))
            row("E6", "probe: " + lab, m + " " + p, x.status, "server=%s content-type=%s body=%r" % (x.h("server"), x.h("content-type"), x.body[:40]))
        x = http("PUT", BASE + "/api/packages/%s/generic/r008probe/0.0.1/probe.txt" % ORG_A, {"Authorization": pkg_auth()}, b"probe\n", "e6-probe-generic-put")
        row("E6", "probe: generic upload (token)", "PUT /api/packages/A/generic/...", x.status, "body=%r" % x.body[:40])
        x = api("GET", "/version", auth=False, label="e6-version")
        row("E6", "server version", "GET /api/v1/version", x.status, x.body[:100].decode(errors="replace"))
        x = api("GET", "/packages/%s" % ORG_A, label="e6-pkglist-api")
        row("E6", "package list endpoint", "GET /api/v1/packages/A", x.status, x.body[:100].decode(errors="replace"))
        row("E6", "conclusion", "-", "-", "package registry endpoints (/api/packages/...) are not served for any owner or type on gitea.com; E6 could not be run there", "same-version/new-bytes question for the Debian registry stays open for gitea.com")
        shutil.rmtree(tmp, ignore_errors=True)
        return
    out, rd = snapshot_index("s1")
    summarize_index("E6", "after 0.1.0:", out, rd)
    kr = pkg_get("repository.key", "e6-key")
    row("E6", "repository.key", "GET repository.key", kr.status, "len=%d" % len(kr.body), hdrsum(kr))
    kf = os.path.join(tmp, "repository.key")
    open(kf, "wb").write(kr.body)
    keys = {}
    try:
        fps, uids = parse_key(armor_parse(kr.body.decode()))
        keys["s1"] = fps
        row("E6", "key fingerprints", "parse repository.key", "-", "; ".join("%s %s (%s)" % f for f in fps), "user IDs: %s" % [redact(u.encode()).decode() for u in uids])
    except Exception as e:
        row("E6", "key parse", "-", "-", "error " + type(e).__name__)
    verify_gpg(tmp, kf, "s1", out)
    snaps = {"s1": rd.get("Date")}
    time.sleep(3)
    r, h2a = put_deb("0.2.0-a", "", "e6-put-020a")
    row("E6", "upload 0.2.0 (93b4dc42)", "PUT pool/pchi/main/upload", r.status, r.body[:200].decode(errors="replace"), "sha256=" + h2a)
    out2, rd2 = snapshot_index("s2")
    summarize_index("E6", "after 0.2.0 (93b4):", out2, rd2)
    snaps["s2"] = rd2.get("Date")
    # same name+version, different bytes
    r, h2b = put_deb("0.2.0-b", "", "e6-put-020b-dup")
    row("E6", "upload replaced 0.2.0 (a59a5cfd), same name/version", "PUT pool/pchi/main/upload", r.status, r.body[:300].decode(errors="replace"), "sha256=" + h2b)
    # package list
    lp = api("GET", "/packages/%s?type=debian" % ORG_A, label="e6-pkglist-1")
    row("E6", "package list", "GET /packages/A?type=debian", lp.status,
        json.dumps([(x.get("id"), x.get("name"), x.get("version"), x.get("created_at")) for x in (lp.json() or [])]))
    # delete the 0.2.0 version via API
    time.sleep(3)
    dl = api("DELETE", "/packages/%s/debian/%s/0.2.0" % (ORG_A, NAME), label="e6-delete-020")
    row("E6", "delete version 0.2.0", "DELETE /packages/A/debian/<name>/0.2.0", dl.status, dl.body[:200].decode(errors="replace"))
    out3, rd3 = snapshot_index("s3")
    summarize_index("E6", "after delete 0.2.0:", out3, rd3)
    time.sleep(3)
    r, h2b = put_deb("0.2.0-b", "", "e6-put-020b")
    row("E6", "upload a59a5cfd as 0.2.0 after delete", "PUT pool/pchi/main/upload", r.status, r.body[:300].decode(errors="replace"), "sha256=" + h2b)
    out4, rd4 = snapshot_index("s4")
    summarize_index("E6", "after re-upload (a59a):", out4, rd4)
    kr2 = pkg_get("repository.key", "e6-key-after")
    same_key = kr2.body == kr.body
    row("E6", "signing key unchanged", "GET repository.key", kr2.status, "identical bytes to first fetch: %s" % same_key)
    verify_gpg(tmp, kf, "s4", out4)
    # pool download of the 0.2.0 file and hash
    fn = None
    for r_ in out4["pk"].values():
        for l in r_.body.decode(errors="replace").splitlines():
            if l.startswith("Filename: ") and "0.2.0" in l:
                fn = l.split(": ", 1)[1]
    if fn:
        d = http("GET", BASE + "/api/packages/%s/debian/%s" % (ORG_A, fn), {}, None, "e6-pool-020", save_body=False)
        if d.status in (301, 302, 307):
            d, _ = follow_download(urllib.parse.urljoin(BASE, d.h("location")), "e6-pool-020-f")
        row("E6", "pool download 0.2.0", "GET " + fn, d.status, "sha256=%s (a=93b4.. b=a59a..)" % sha256(d.body), hdrsum(d))
    row("E6", "Release Date sequence", "-", "-", "s1=%s s2=%s s3=%s s4=%s" % (snaps["s1"], snaps["s2"], rd3.get("Date"), rd4.get("Date")))
    lp = api("GET", "/packages/%s?type=debian" % ORG_A, label="e6-pkglist-2")
    row("E6", "package list at end", "GET /packages/A?type=debian", lp.status,
        json.dumps([(x.get("id"), x.get("name"), x.get("version"), x.get("created_at")) for x in (lp.json() or [])]))
    shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- E7
def e7():
    r = api("GET", "/repos/%s/pchi-test" % ORG_A, label="e7-repo")
    row("E7", "has_actions field", "GET /repos/A/pchi-test", r.status, "has_actions=%s" % (r.json() or {}).get("has_actions"))
    r = api("GET", "/repos/%s/pchi-test/actions/runs" % ORG_A, label="e7-runs")
    row("E7", "actions runs endpoint", "GET /repos/A/pchi-test/actions/runs", r.status, r.body[:150].decode(errors="replace"))


def scan_token():
    hits = 0
    t = TOKEN.encode()
    for root in (RAW, ROOT + "/research/r-008"):
        for dp, _, fs in os.walk(root):
            for f in fs:
                p = os.path.join(dp, f)
                try:
                    if t in open(p, "rb").read():
                        hits += 1
                        print("TOKEN HIT in", p)
                except Exception:
                    pass
    return hits


def main():
    exps = [("E1", e1), ("E2", e2), ("E3", e3), ("E4", e4), ("E5", e5), ("E6", e6), ("E7", e7)]
    for name, fn in exps:
        if only and name not in only:
            continue
        try:
            fn()
        except SystemExit:
            raise
        except Exception as e:
            import traceback
            row(name, "harness error", "-", "-", "%s: %s" % (type(e).__name__, str(e)[:200]))
            traceback.print_exc(file=open(RAW + "/error-%s.txt" % name, "w"))
        save_state()
    tsv = ROOT + "/research/r-008/gitea-results.tsv"
    mode = "a" if only else "w"
    fresh = mode == "w" or not os.path.exists(tsv)
    with open(tsv, mode, newline="\n") as f:
        if fresh:
            f.write("experiment\tstep\trequest\thttp_status\tobserved\tnote\n")
        for rw in ROWS:
            f.write("\t".join(rw) + "\n")
    with open(RAW + "/rows.tsv", "w", newline="\n") as f:
        for rw in ROWS:
            f.write("\t".join(rw) + "\n")
    print("non-noreply e-mails redacted from raw bodies:", OTHER_EMAILS[0])
    print("token hits:", scan_token())


main()
