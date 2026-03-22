use std::path::{Component, Path, PathBuf};

/// Resolve a file path: expand ~ and canonicalize.
/// Returns None if the path contains traversal (`..`).
pub fn resolve(path: &str) -> Option<PathBuf> {
    if Path::new(path)
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return None;
    }

    let expanded = expand_tilde(path);

    // Try to canonicalize (resolves symlinks), fall back to cleaned path
    match std::fs::canonicalize(&expanded) {
        Ok(canonical) => Some(canonical),
        Err(_) => Some(PathBuf::from(expanded)),
    }
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}/{rest}");
    }
    if path == "~"
        && let Ok(home) = std::env::var("HOME")
    {
        return home;
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-022: path traversal detected → None
    #[test]
    fn t022_path_traversal_denied() {
        assert!(resolve("../../../etc/passwd").is_none());
    }

    #[test]
    fn traversal_in_middle_denied() {
        assert!(resolve("/home/user/../root/.ssh/id_rsa").is_none());
    }

    #[test]
    fn url_encoded_dots_are_not_traversal() {
        // %2F is URL encoding — Path::components treats "..%2F..." as a normal dir name
        assert!(resolve("..%2F..%2Fetc/passwd").is_some());
    }

    // CQ-03: legitimate paths with ".." in names should pass
    #[test]
    fn double_dot_in_filename_allowed() {
        let result = resolve("/Users/test/my..project/file.rs");
        assert!(result.is_some());
    }

    // Normal paths resolve successfully
    #[test]
    fn absolute_path_resolves() {
        let result = resolve("/tmp/test.rs");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), PathBuf::from("/tmp/test.rs"));
    }

    #[test]
    fn tilde_expanded() {
        let result = resolve("~/.claude/tools.json");
        assert!(result.is_some());
        let path = result.unwrap();
        assert!(!path.to_string_lossy().contains('~'));
    }

    #[test]
    fn relative_path_resolves() {
        let result = resolve("src/main.rs");
        assert!(result.is_some());
    }
}
