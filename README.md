# Glasgow Evidence

Forensic audit of the PC "Glasgow" after a MicroCenter repair (June 2026).
Owner: Mike Sloan. Investigator: Claude (claude.ai Project "Forensic Audit of Glasgow").

**This repo is the canonical record of the audit.** Copies elsewhere are pointers or snapshots.

## What is on GitHub, and what is not

- Evidence files and notes are **encrypted** before they reach GitHub (`sealed/*.gpg`).
  OpenPGP symmetric, AES-256, via GnuPG. Any OpenPGP tool can open them with the key.
- `SHA256SUMS` is plaintext on purpose: the SHA-256 of every plaintext file. It proves
  integrity and gives a dated public anchor for each file without revealing content.
- Plaintext lives only in the working tree on JENNY (`D:\REPOS\Glasgow_Evidence`).
  `.gitignore` is fail-closed: anything not on its allow list never gets committed.
- The key is **not** in any repo. It lives at `D:\REPOS\_keys\glasgow\glasgow-evidence.key`
  on JENNY, with an offline backup held by Mike.

## Layout (working tree on JENNY)

| Path | What | On GitHub as |
|---|---|---|
| `Forensics_Audit.md` | Running audit log, Step N format. Never edit a prior step. | sealed |
| `PLAN.md` | Current plan | sealed |
| `OPEN_ITEMS.csv` | This project's open items (Brain DEC-008: teams own their lists) | sealed |
| `evidence/<date>_<source>/` | Evidence, **write-once**. A changed file stops the seal run. | sealed |
| `Superseded/` | Retired versions, kept, never deleted | sealed |
| `tools/glasgow_seal.py` | seal / verify / unseal | plaintext |
| `SHA256SUMS` | Plaintext hashes | plaintext |

## Use

    python3 tools/glasgow_seal.py seal      # encrypt new/changed files, update SHA256SUMS
    python3 tools/glasgow_seal.py verify    # decrypt everything to temp, check every hash
    python3 tools/glasgow_seal.py unseal    # fresh clone: restore plaintext (never overwrites)

Pass `--key <path>` if the key is not at the default location.
