use std::path::Path;
use std::path::PathBuf;
use walkdir::WalkDir;

pub enum RepoEntry {
    GitDir(PathBuf),
    GitLink(PathBuf),
}

const SKIP_DIRS: &[&str] = &["node_modules", "target", ".venv"];

pub fn discover_git_dirs(_path: &Path) -> Vec<RepoEntry> {
    let mut repos = Vec::new();
    let mut it = WalkDir::new(_path).into_iter();

    while let Some(entry) = it.next() {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                println!("Error: {}", err);
                continue;
            }
        };

        let name = entry.file_name().to_string_lossy();

        if entry.file_type().is_dir() {
            if name == ".git" {
                repos.push(RepoEntry::GitDir(entry.path().to_path_buf()));
                it.skip_current_dir();
                continue;
            }
            if SKIP_DIRS.contains(&name.as_ref()) {
                it.skip_current_dir();
                continue;
            }
        } else if entry.file_type().is_file() && name == ".git" {
            repos.push(RepoEntry::GitLink(entry.path().to_path_buf()));
        }
    }

    repos
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn skips_ignored_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // repo1/.git directory
        fs::create_dir_all(root.join("repo1/.git")).unwrap();

        // repo2/.git file
        fs::create_dir_all(root.join("repo2")).unwrap();
        fs::write(root.join("repo2/.git"), "gitdir: /some/other/location").unwrap();

        // node_modules
        fs::create_dir_all(root.join("node_modules/pkg/.git")).unwrap();

        // target
        fs::create_dir_all(root.join("target/debug/.git")).unwrap();

        // .venv
        fs::create_dir_all(root.join(".venv/project/.git")).unwrap();

        let repos = discover_git_dirs(root);

        assert_eq!(repos.len(), 2);

        assert!(repos.iter().any(|r| matches!(r,
            RepoEntry::GitDir(p) if p.ends_with("repo1/.git")
        )));

        assert!(repos.iter().any(|r| matches!(r,
            RepoEntry::GitLink(p) if p.ends_with("repo2/.git")
        )));
    }

    #[test]
    fn diagnostic_real_git_dir_with_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("repo1/.git/objects")).unwrap();
        fs::write(root.join("repo1/.git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(root.join("repo1/.git/config"), "").unwrap();

        let repos = discover_git_dirs(root);
        for r in &repos {
            match r {
                RepoEntry::GitDir(p) => println!("GitDir: {}", p.display()),
                RepoEntry::GitLink(p) => println!("GitLink: {}", p.display()),
            }
        }
        assert_eq!(
            repos.len(),
            1,
            "expected exactly 1 entry (the .git dir itself), got {:?} entries",
            repos.len()
        );
    }
}
