use std::process::Command;

use regex::Regex;

/// Check if the command is a git commit, and if so, inspect staged files.
/// Returns Some((filename, pattern_desc)) if a secret file is staged.
pub fn check_secrets(
    command: &str,
    staged_files: &[String],
    extra_patterns: &[Regex],
) -> Option<(String, String)> {
    if !is_git_commit(command) {
        return None;
    }

    let builtin = builtin_secret_patterns();

    for file in staged_files {
        for pat in &builtin {
            if pat.regex.is_match(file) {
                return Some((file.clone(), pat.description.to_owned()));
            }
        }
        for pat in extra_patterns {
            if pat.is_match(file) {
                return Some((file.clone(), pat.to_string()));
            }
        }
    }

    None
}

fn is_git_commit(command: &str) -> bool {
    let trimmed = command.trim();
    trimmed.starts_with("git commit")
        || trimmed.starts_with("git -c ") && trimmed.contains("commit")
}

struct SecretPattern {
    regex: Regex,
    description: &'static str,
}

impl SecretPattern {
    fn new(pattern: &str, description: &'static str) -> Self {
        Self {
            regex: Regex::new(pattern)
                .unwrap_or_else(|e| panic!("shields: invalid secret pattern: {e}")),
            description,
        }
    }
}

fn builtin_secret_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern::new(r"\.env($|\.)", "Environment file (.env)"),
        SecretPattern::new(r"\.env\.local$", "Local env file (.env.local)"),
        SecretPattern::new(r"\.env\.production$", "Production env (.env.production)"),
        SecretPattern::new(r"\.key$", "Key file (.key)"),
        SecretPattern::new(r"\.pem$", "PEM certificate (.pem)"),
        SecretPattern::new(r"\.p12$", "PKCS12 certificate (.p12)"),
        SecretPattern::new(r"\.pfx$", "PFX certificate (.pfx)"),
        SecretPattern::new(r"id_rsa", "SSH private key (id_rsa)"),
        SecretPattern::new(r"id_ed25519", "SSH private key (id_ed25519)"),
        SecretPattern::new(r"id_ecdsa", "SSH private key (id_ecdsa)"),
        SecretPattern::new(r"\.secret$", "Secret file (.secret)"),
        SecretPattern::new(r"\.token$", "Token file (.token)"),
        SecretPattern::new(r"credentials\.json$", "Credentials file"),
        SecretPattern::new(r"service[_-]?account.*\.json$", "Service account key"),
        SecretPattern::new(r"\.keystore$", "Keystore file (.keystore)"),
        SecretPattern::new(r"\.jks$", "Java Keystore (.jks)"),
        SecretPattern::new(r"\.htpasswd$", "htpasswd file"),
        SecretPattern::new(r"\.netrc$", "netrc file"),
        SecretPattern::new(r"\.npmrc$", "npmrc file (may contain tokens)"),
        SecretPattern::new(r"\.pypirc$", "pypirc file (may contain tokens)"),
    ]
}

/// Get staged file list via git.
pub fn get_staged_files() -> Vec<String> {
    Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.lines().map(String::from).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- T-013: staged .env file → block ---

    #[test]
    fn t013_env_file_detected() {
        let staged = vec![".env".to_owned()];
        let result = check_secrets("git commit -m \"test\"", &staged, &[]);
        assert!(result.is_some());
        let (file, _) = result.unwrap();
        assert_eq!(file, ".env");
    }

    #[test]
    fn env_local_detected() {
        let staged = vec![".env.local".to_owned()];
        let result = check_secrets("git commit -m \"test\"", &staged, &[]);
        assert!(result.is_some());
    }

    #[test]
    fn env_production_detected() {
        let staged = vec![".env.production".to_owned()];
        let result = check_secrets("git commit -m \"test\"", &staged, &[]);
        assert!(result.is_some());
    }

    // --- T-014: no secrets staged → pass ---

    #[test]
    fn t014_no_secrets_passes() {
        let staged = vec!["src/main.rs".to_owned(), "README.md".to_owned()];
        let result = check_secrets("git commit -m \"test\"", &staged, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn empty_staged_passes() {
        let result = check_secrets("git commit -m \"test\"", &[], &[]);
        assert!(result.is_none());
    }

    // --- T-015: non-commit command → skip ---

    #[test]
    fn t015_git_status_skipped() {
        let staged = vec![".env".to_owned()];
        let result = check_secrets("git status", &staged, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn non_git_command_skipped() {
        let staged = vec![".env".to_owned()];
        let result = check_secrets("cargo test", &staged, &[]);
        assert!(result.is_none());
    }

    // --- T-016: custom secrets pattern ---

    #[test]
    fn t016_custom_pattern_tfstate() {
        let staged = vec!["infra/main.tfstate".to_owned()];
        let custom = vec![Regex::new(r"\.tfstate$").unwrap()];
        let result = check_secrets("git commit -m \"test\"", &staged, &custom);
        assert!(result.is_some());
        let (file, _) = result.unwrap();
        assert_eq!(file, "infra/main.tfstate");
    }

    // --- All 20 builtin patterns ---

    #[test]
    fn detects_key_file() {
        let staged = vec!["cert.key".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_pem_file() {
        let staged = vec!["cert.pem".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_p12_file() {
        let staged = vec!["cert.p12".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_pfx_file() {
        let staged = vec!["cert.pfx".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_id_rsa() {
        let staged = vec![".ssh/id_rsa".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_id_ed25519() {
        let staged = vec![".ssh/id_ed25519".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_id_ecdsa() {
        let staged = vec![".ssh/id_ecdsa".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_credentials_json() {
        let staged = vec!["credentials.json".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_service_account() {
        let staged = vec!["service_account.json".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_keystore() {
        let staged = vec!["release.keystore".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_jks() {
        let staged = vec!["truststore.jks".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_htpasswd() {
        let staged = vec![".htpasswd".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_netrc() {
        let staged = vec![".netrc".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_npmrc() {
        let staged = vec![".npmrc".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_pypirc() {
        let staged = vec![".pypirc".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_secret_file() {
        let staged = vec!["api.secret".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }

    #[test]
    fn detects_token_file() {
        let staged = vec!["auth.token".to_owned()];
        assert!(check_secrets("git commit", &staged, &[]).is_some());
    }
}
