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
