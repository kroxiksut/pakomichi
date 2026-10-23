#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Build the P1-003c probe inputs from recorded R-003 evidence.

Usage: verifier-probe-inputs.py R003_RUN_DIR OWNER_STEP1_DIR OUT_DIR

Splits the recorded trusted roots, and writes tampered bundles and roots
into OUT_DIR (a scratch directory, never the evidence directories). Every
tampered input changes one thing only.
"""
import base64
import copy
import hashlib
import json
import pathlib
import sys


def lines(path):
    return [json.loads(x) for x in pathlib.Path(path).read_text().splitlines() if x.strip()]


def write(path, obj):
    path.write_text(json.dumps(obj, separators=(",", ":")) + "\n")


def flip_b64(value, position=-1):
    raw = bytearray(base64.b64decode(value))
    raw[position] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def main():
    run, step1, out = (pathlib.Path(p) for p in sys.argv[1:4])
    out.mkdir(parents=True, exist_ok=True)

    public_good, github = lines(run / "trusted-root.jsonl")
    write(out / "root-public-good.json", public_good)
    write(out / "root-github.json", github)
    write(out / "root-public-good-no-ca.json", lines(run / "negatives/trusted-root-no-ca.jsonl")[0])
    no_ct = copy.deepcopy(public_good)
    no_ct["ctlogs"] = []
    write(out / "root-public-good-no-ctlogs.json", no_ct)
    # CT log IDs kept, public keys swapped between the two logs: the SCT
    # names a known log but its signature does not verify.
    swapped_ct = copy.deepcopy(public_good)
    first, second = swapped_ct["ctlogs"][:2]
    first["publicKey"], second["publicKey"] = second["publicKey"], first["publicKey"]
    write(out / "root-public-good-ct-keys-swapped.json", swapped_ct)
    # Every GitHub CA window ends the moment it starts: a well-formed window
    # that no signing time falls into.
    early = copy.deepcopy(github)
    for ca in early["certificateAuthorities"]:
        ca["validFor"]["end"] = ca["validFor"]["start"]
    write(out / "root-github-ca-ended.json", early)

    attested = lines(run / "bundles/subject/649038819.jsonl")[0]
    # The netwatch asset bundles are one attestation (identical files), so
    # the "other" public-good bundle is the cli/cli SLSA provenance.
    other_attested = lines(run / "bundles/strict/450525940.jsonl")[1]
    strict = lines(run / "bundles/strict/450525940.jsonl")[0]

    def variant(name, base, change):
        bundle = copy.deepcopy(base)
        change(bundle)
        write(out / f"{name}.jsonl", bundle)

    tlog = lambda b: b["verificationMaterial"]["tlogEntries"][0]

    variant("n27-no-tlog", attested, lambda b: b["verificationMaterial"].pop("tlogEntries"))

    def proof_hash(b):
        proof = tlog(b)["inclusionProof"]
        proof["hashes"][0] = flip_b64(proof["hashes"][0])
    variant("n28-inclusion-proof", attested, proof_hash)

    def checkpoint(b):
        checkpoint = tlog(b)["inclusionProof"]["checkpoint"]
        text = checkpoint["envelope"].rstrip("\n").split("\n")
        prefix, signature = text[-1].rsplit(" ", 1)
        text[-1] = prefix + " " + flip_b64(signature)
        checkpoint["envelope"] = "\n".join(text) + "\n"
    variant("n29-checkpoint", attested, checkpoint)

    def integrated_time(b):
        tlog(b)["integratedTime"] = str(int(tlog(b)["integratedTime"]) - 3600)
    variant("n30-integrated-time", attested, integrated_time)

    variant("n31-foreign-tlog", attested,
            lambda b: b["verificationMaterial"].__setitem__(
                "tlogEntries", copy.deepcopy(other_attested["verificationMaterial"]["tlogEntries"])))
    variant("n32-swapped-leaf", attested,
            lambda b: b["verificationMaterial"].__setitem__(
                "certificate", copy.deepcopy(other_attested["verificationMaterial"]["certificate"])))

    def tsa_byte(b):
        stamp = b["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0]
        stamp["signedTimestamp"] = flip_b64(stamp["signedTimestamp"])
    variant("n33-tsa-byte", strict, tsa_byte)
    variant("n34-no-timestamp", strict, lambda b: b["verificationMaterial"].pop("timestampVerificationData"))

    def two_signatures(b):
        b["dsseEnvelope"]["signatures"].append(copy.deepcopy(b["dsseEnvelope"]["signatures"][0]))
    variant("n37-two-signatures", attested, two_signatures)
    variant("n38-payload-type", attested, lambda b: b["dsseEnvelope"].__setitem__("payloadType", "text/plain"))

    def statement_type(b):
        statement = json.loads(base64.b64decode(b["dsseEnvelope"]["payload"]))
        statement["_type"] = "https://in-toto.io/Statement/v0.1"
        b["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    variant("n39-statement-type", attested, statement_type)
    variant("n40-media-type", attested,
            lambda b: b.__setitem__("mediaType", "application/vnd.dev.sigstore.bundle+json;version=0.1"))

    asset = (run / "downloads/subject/649038819-netwatch-0.35.4-1.x86_64.rpm").read_bytes()

    def message_signature(b):
        signature = b["dsseEnvelope"]["signatures"][0]["sig"]
        b.pop("dsseEnvelope")
        b["messageSignature"] = {
            "messageDigest": {"algorithm": "SHA2_256",
                              "digest": base64.b64encode(hashlib.sha256(asset).digest()).decode()},
            "signature": signature,
        }
    variant("n41-message-signature", attested, message_signature)

    big = copy.deepcopy(attested)
    big["pakomichiPadding"] = "x" * (300 * 1024)
    write(out / "n05-too-large.jsonl", big)
    line = json.dumps(attested, separators=(",", ":"))
    (out / "n05b-too-many.jsonl").write_text((line + "\n") * 17)

    # Release attestation from the owner's test repository, alone.
    (out / "pchi-release.jsonl").write_text(
        (step1 / "bundles/s1/664728438.jsonl").read_text().splitlines()[0] + "\n")
    print(f"inputs written to {out}")


if __name__ == "__main__":
    main()
