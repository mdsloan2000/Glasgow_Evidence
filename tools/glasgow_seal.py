#!/usr/bin/env python3
"""glasgow_seal.py -- encrypt the Glasgow evidence repo for GitHub, and verify it.

Why: the repo holds forensic evidence and notes that may matter in a civil
dispute. GitHub stores only ciphertext. Plaintext stays on JENNY.

How: OpenPGP symmetric encryption (AES-256, RFC 9580/4880) through GnuPG.
Any OpenPGP tool can decrypt it, now or years from now, with the key file.

Layout:
  plaintext files (working tree, git-ignored)  ->  sealed/<same path>.gpg (committed)
  SHA256SUMS (committed, plaintext) = SHA-256 of every PLAINTEXT file.
  The hashes are the integrity anchor; the ciphertext is the confidentiality layer.

Commands:
  seal    encrypt new or changed plaintext files; leave unchanged ones alone
  verify  decrypt every sealed file to a temp dir and check it against SHA256SUMS
  unseal  restore plaintext from sealed/ (fresh clone); never overwrites a file

Key: a passphrase file outside every repo. Default D:\\REPOS\\_keys\\glasgow\\glasgow-evidence.key
(on the Linux bridge: $HOME/mnt/glasgow/glasgow-evidence.key). Override with --key.
The key is never printed.

Status lines are text, never colour: [OK] [SKIP] [FAIL] [INFO]
"""
import argparse, hashlib, os, shutil, subprocess, sys, tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SEALED = REPO / "sealed"
SUMS = REPO / "SHA256SUMS"
# Files that stay plaintext in git (no sensitive content). Everything else is sealed.
PLAINTEXT_OK = {".gitignore", ".gitattributes", "README.md", "SHA256SUMS"}
SKIP_DIRS = {".git", "sealed", "tools"}


def say(tag, msg):
    print(f"[{tag:<4}] {msg}", flush=True)


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def plaintext_files():
    out = []
    for root, dirs, files in os.walk(REPO):
        rel_root = Path(root).relative_to(REPO)
        dirs[:] = sorted(d for d in dirs if not (rel_root == Path(".") and d in SKIP_DIRS))
        for f in sorted(files):
            rel = (rel_root / f).as_posix()
            if rel in PLAINTEXT_OK or f.startswith(".~lock."):
                continue
            out.append(rel)
    return out


def read_sums():
    sums = {}
    if SUMS.exists():
        for line in SUMS.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#"):
                h, rel = line.split("  ", 1)
                sums[rel] = h
    return sums


def write_sums(sums):
    lines = ["# SHA-256 of each PLAINTEXT file. sealed/<path>.gpg is its encrypted copy.",
             "# Check: python3 tools/glasgow_seal.py verify"]
    lines += [f"{sums[k]}  {k}" for k in sorted(sums)]
    SUMS.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def gpg(args, key, home):
    cmd = ["gpg", "--homedir", home, "--batch", "--yes", "--quiet",
           "--pinentry-mode", "loopback", "--passphrase-file", str(key)] + args
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"gpg exit {r.returncode}: {r.stderr.strip()[:300]}")


def check_key(key):
    if not key.exists():
        say("FAIL", f"Key file not found: {key}")
        sys.exit(1)
    if REPO in key.resolve().parents:
        say("FAIL", "Key file is inside the repo. Refusing.")
        sys.exit(1)


def cmd_seal(key):
    check_key(key)
    old = read_sums()
    new, sealed_n, skipped = {}, 0, 0
    changed_evidence = []
    with tempfile.TemporaryDirectory() as home:
        for rel in plaintext_files():
            h = sha256(REPO / rel)
            if rel.startswith("evidence/") and rel in old and old[rel] != h:
                say("FAIL", f"EVIDENCE CHANGED, not resealed: {rel}")
                say("FAIL", f"  recorded {old[rel]}")
                say("FAIL", f"  now      {h}")
                changed_evidence.append(rel)
                new[rel] = old[rel]
                continue
            new[rel] = h
            target = SEALED / (rel + ".gpg")
            if old.get(rel) == h and target.exists():
                skipped += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            gpg(["--symmetric", "--cipher-algo", "AES256", "--s2k-mode", "3",
                 "--s2k-digest-algo", "SHA512", "--s2k-count", "65011712",
                 "--compress-algo", "zlib", "-o", str(target), str(REPO / rel)], key, home)
            sealed_n += 1
            say("OK", f"sealed {rel}")
    orphans = [p for p in SEALED.rglob("*.gpg")
               if p.relative_to(SEALED).as_posix()[:-4] not in new]
    if changed_evidence:
        say("FAIL", "Evidence files are write-once. SHA256SUMS left unchanged. Stop and tell Mike.")
        sys.exit(2)
    write_sums(new)
    say("INFO", f"{sealed_n} sealed, {skipped} unchanged, {len(new)} tracked")
    for o in orphans:
        say("INFO", f"orphan (plaintext gone or moved): {o.relative_to(REPO).as_posix()}")
    return orphans


def cmd_verify(key):
    check_key(key)
    sums = read_sums()
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        home = os.path.join(tmp, "gnupg"); os.mkdir(home, 0o700)
        for rel, h in sorted(sums.items()):
            src = SEALED / (rel + ".gpg")
            if not src.exists():
                say("FAIL", f"missing sealed copy: {rel}"); bad += 1; continue
            out = os.path.join(tmp, "x")
            gpg(["-d", "-o", out, str(src)], key, home)
            got = sha256(out); os.remove(out)
            if got == h:
                say("OK", f"{rel}")
            else:
                say("FAIL", f"hash mismatch: {rel}"); bad += 1
    say("INFO", f"{len(sums)} checked, {bad} failed")
    say("OK" if bad == 0 else "FAIL", "RESULT")
    return bad == 0


def cmd_unseal(key):
    check_key(key)
    sums = read_sums()
    with tempfile.TemporaryDirectory() as home:
        for rel, h in sorted(sums.items()):
            dst = REPO / rel
            if dst.exists():
                say("SKIP", f"exists, not overwritten: {rel}"); continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            gpg(["-d", "-o", str(dst), str(SEALED / (rel + ".gpg"))], key, home)
            say("OK" if sha256(dst) == h else "FAIL", f"unsealed {rel}")


def run(a):
    if a.command == "seal":
        cmd_seal(a.key)
    elif a.command == "verify":
        sys.exit(0 if cmd_verify(a.key) else 1)
    else:
        cmd_unseal(a.key)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["seal", "verify", "unseal"])
    default_key = Path(os.environ.get("GLASGOW_KEY",
                       Path.home() / "mnt" / "glasgow" / "glasgow-evidence.key"))
    ap.add_argument("--key", type=Path, default=default_key)
    a = ap.parse_args()
    if shutil.which("gpg") is None:
        say("FAIL", "gpg not found on PATH"); sys.exit(1)
    try:
        run(a)
    except RuntimeError as e:
        say("FAIL", str(e)); sys.exit(1)
