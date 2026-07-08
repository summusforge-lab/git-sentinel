use std::path::Path;

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
