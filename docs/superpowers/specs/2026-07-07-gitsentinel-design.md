# GitSentinel — design spec

Date: 2026-07-07

## Problem

A downloaded client project contained a `.git` directory with malware files
mixed in among normal git metadata. There is currently no quick way to check
whether a `.git` directory's contents are structurally consistent with what
git itself would create, versus tampered with or padded with foreign files.

## Goal

A Rust CLI, `gitsentinel`, that recursively finds every `.git` directory
under a given path and runs a set of structural checks against each one,
flagging anything that doesn't look like it belongs, with enough detail for
a human to decide whether it's malicious or a known-benign tool (husky,
lefthook, pre-commit framework, etc.).

This is a structural/heuristic scanner, not a signature-based antivirus and
not a git object-graph analyzer. It does not decompress and inspect full
blob contents, and it does not walk the commit/tree graph to find orphaned
objects. It catches the more common and more mechanical class of tampering:
foreign files, broken naming conventions, bad permissions, and suspicious
config directives.

## Non-goals (v1)

- Deep content scanning of blob contents (e.g., shell/base64 pattern
  matching inside object contents).
- Orphan object detection via commit/tree graph traversal.
- JSON output / machine-readable report format.
- A curated allowlist of known third-party hook-manager signatures (husky,
  lefthook, pre-commit, etc.) — these are always reported as WARNING with
  full detail; the user decides.

Both are reasonable v2 follow-ups but out of scope here.

## Naming

Cargo package name: `git-sentinel` (kebab-case, matches crates.io convention).
Binary name: `gitsentinel` (no hyphen — set via an explicit `[[bin]]` section
in `Cargo.toml` since it differs from the package name).

## Architecture

```
CLI (clap) -> discovery (recursive .git finder) -> checks (per-repo) -> report (terminal) -> exit code
```

Crates: `clap` (derive-based CLI), `walkdir` (tree traversal), `flate2`
(lightweight zlib-stream validity check on loose objects), `colored`
(terminal color), `anyhow` (error handling), `tempfile` (dev-dependency,
test fixtures).

### Discovery

Starting at the given path (default `.`), recursively walk the directory
tree looking for:

- `.git` directories (normal repos) — scanned in full.
- `.git` files (gitlink — submodule/worktree pointer, contains
  `gitdir: <path>`) — reported as INFO ("submodule pointer"), not
  followed/scanned as a separate repo in v1.

Skip common large/irrelevant directories during the walk for performance:
`node_modules`, `target`, `.venv` (skip contents, but still detect a `.git`
if one exists exactly at that path — in practice these never contain one).

### Checks

Each check produces zero or more `Finding`:

```rust
struct Finding {
    severity: Severity,   // Critical | Warning | Info
    category: &'static str,
    path: PathBuf,         // path to the offending entry, relative to repo root
    message: String,
}
```

1. **`check_root_files`** — compares the immediate children of `.git/`
   against the known-entries list: `HEAD`, `config`, `description`,
   `index`, `packed-refs`, `info/`, `hooks/`, `objects/`, `refs/`, `logs/`,
   `COMMIT_EDITMSG`, `FETCH_HEAD`, `ORIG_HEAD`, `MERGE_HEAD`, `MERGE_MSG`,
   `MERGE_MODE`, `shallow`, `modules/`, `worktrees/`, `branches/` (legacy).
   Anything else: CRITICAL if executable or has a suspicious extension
   (`.exe`, `.sh`, `.py`, `.dll`, `.ps1`, `.bin`, `.bat`, `.jar`), otherwise
   WARNING ("unknown file, review manually").

2. **`check_hooks`** — for each entry directly under `hooks/`: if the name
   does not end in `.sample` and the file is executable, WARNING with name,
   size, and first line (shebang) as detail. A subdirectory under `hooks/`
   is unusual: WARNING. A `.sample` file that is itself executable:
   WARNING (git ships samples as non-executable).

3. **`check_config`** — parse `.git/config` as INI. Flag as WARNING (with
   the offending key/value) any of: `core.hooksPath`, `url.*.insteadOf`,
   `core.fsmonitor`, `include.path` / `includeIf.*.path` pointing outside
   the repository.

4. **`check_objects`** — for each file under `objects/xx/`: the parent
   directory name must be exactly 2 lowercase hex chars, the filename must
   be 38 hex chars (SHA-1 loose object) or 62 hex chars (SHA-256 repo);
   the file must not be executable; the first bytes must parse as a valid
   zlib stream (attempt a bounded `flate2` decode of the header — full
   content is not inspected). Any violation: CRITICAL. Under
   `objects/pack/`: only `*.pack`, `*.idx`, `*.rev` are expected; anything
   else is CRITICAL.

5. **`check_refs`** — for `refs/heads/**`, `refs/tags/**`,
   `refs/remotes/**`, and `packed-refs`: content must be a bare hex SHA
   (40 or 64 chars) or a symref line (`ref: refs/...`). Anything else, or
   an executable bit set on any of these files: CRITICAL.

6. **`check_permissions`** — global pass: any file anywhere under `.git`
   with the executable bit set, outside of `hooks/`, is CRITICAL (git never
   sets +x on its own tracked metadata outside hooks).

### Severity model

- **CRITICAL** — near-certain sign of tampering: broken object naming/zlib
  validity, executable files outside `hooks/`, unknown top-level files with
  suspicious extensions, malformed ref content.
- **WARNING** — needs a human look, often benign: custom (non-sample)
  executable hooks, suspicious config directives, unknown top-level files
  without a suspicious extension.
- **INFO** — informational only: submodule gitlink pointers found during
  discovery.

No check ever silently "passes" a suspicious hook because it resembles a
known hook-manager signature — v1 always surfaces it as WARNING with full
detail and leaves the judgment call to the user.

### Report format

Plain colored terminal text, one block per discovered repo:

```
GitSentinel — scanning /path/to/project

[repo] ./  (.git)
  CRITICAL  objects/4a/f3b2...   invalid zlib header — possible tampered object
  WARNING   hooks/pre-commit     custom executable hook (not .sample)
  WARNING   config               core.hooksPath points outside repo: /tmp/x

[repo] ./vendor/lib  (.git)
  clean — no issues found

Summary: 2 repos scanned, 1 CRITICAL, 2 WARNING, 0 INFO
```

### Exit codes

- `0` — no findings, or INFO only.
- `1` — at least one WARNING, no CRITICAL.
- `2` — at least one CRITICAL.

This makes the tool usable in CI/scripts even without a machine-readable
output format.

### Testing

- Unit tests per check function, using `tempfile` to build minimal `.git`
  fixtures: clean `git init` output, a forged executable hook, a corrupted
  loose object (bad filename / bad zlib header), a foreign top-level file,
  a bad-permission file, a malformed ref.
- One integration test: run the full scan against a real `git init` in a
  tempdir and assert zero CRITICAL/WARNING findings — a sanity check that
  the tool doesn't false-positive on a normal, freshly created repo.

## Open items for v2 (explicitly deferred, not blocking v1)

- JSON/machine-readable output.
- Known-hook-manager signature allowlist.
- Orphan object detection via commit/tree graph walk.
- Deep blob content scanning for embedded shellcode/base64 patterns.
