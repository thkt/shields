use regex::Regex;
use serde::Deserialize;
use std::path::{Component, Path};

use crate::check::patterns::Pattern;

fn validate_relative_paths(paths: Vec<String>, label: &str) -> Vec<String> {
    paths
        .into_iter()
        .filter(|p| {
            let path = Path::new(p);
            if path.is_absolute() {
                eprintln!("shields: {label} entry '{p}' is absolute path, ignored");
                return false;
            }
            if path.components().any(|c| matches!(c, Component::ParentDir)) {
                eprintln!("shields: {label} entry '{p}' contains traversal, ignored");
                return false;
            }
            true
        })
        .collect()
}

const TOOLS_CONFIG_FILE: &str = ".claude/tools.json";

pub struct ShieldsConfig {
    pub check_enabled: bool,
    pub acl_enabled: bool,
    pub custom_patterns: Vec<Pattern>,
    pub secrets_patterns: Vec<Regex>,
    pub safe_dirs: Vec<String>,
    pub deny_subagent: Vec<String>,
    pub config_error: Option<String>,
}

impl Default for ShieldsConfig {
    fn default() -> Self {
        Self {
            check_enabled: true,
            acl_enabled: true,
            custom_patterns: Vec::new(),
            secrets_patterns: Vec::new(),
            safe_dirs: Vec::new(),
            deny_subagent: Vec::new(),
            config_error: None,
        }
    }
}

#[derive(Deserialize)]
struct ToolsJson {
    shields: Option<ShieldsJson>,
}

#[derive(Deserialize)]
struct ShieldsJson {
    check: Option<bool>,
    acl: Option<bool>,
    custom_patterns: Option<Vec<PatternDef>>,
    secrets_patterns: Option<Vec<String>>,
    safe_dirs: Option<Vec<String>>,
    deny_subagent: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct PatternDef {
    id: String,
    regex: String,
    context: String,
}

impl ShieldsConfig {
    pub fn load(project_dir: &Path) -> Self {
        let path = project_dir.join(TOOLS_CONFIG_FILE);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(e) => {
                eprintln!("shields: failed to read {}: {}", path.display(), e);
                return Self::default();
            }
        };

        let parsed = match serde_json::from_str::<ToolsJson>(&content) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("shields: config parse error, using defaults: {}", e);
                return Self::default();
            }
        };

        let Some(shields) = parsed.shields else {
            return Self::default();
        };

        let mut errors = Vec::new();

        let custom_patterns: Vec<Pattern> = shields
            .custom_patterns
            .unwrap_or_default()
            .into_iter()
            .filter_map(|def| match Regex::new(&def.regex) {
                Ok(re) => Some(Pattern {
                    id: def.id,
                    regex: re,
                    context: def.context,
                }),
                Err(e) => {
                    errors.push(format!("invalid custom pattern '{}': {}", def.id, e));
                    None
                }
            })
            .collect();

        let secrets_patterns: Vec<Regex> = shields
            .secrets_patterns
            .unwrap_or_default()
            .into_iter()
            .filter_map(|pat| match Regex::new(&pat) {
                Ok(re) => Some(re),
                Err(e) => {
                    errors.push(format!("invalid secret pattern '{}': {}", pat, e));
                    None
                }
            })
            .collect();

        let config_error = if errors.is_empty() {
            None
        } else {
            let msg = format!("config has invalid patterns: {}", errors.join("; "));
            eprintln!("shields: {msg}");
            Some(msg)
        };

        Self {
            check_enabled: shields.check.unwrap_or(true),
            acl_enabled: shields.acl.unwrap_or(true),
            custom_patterns,
            secrets_patterns,
            safe_dirs: validate_relative_paths(shields.safe_dirs.unwrap_or_default(), "safe_dirs"),
            deny_subagent: validate_relative_paths(
                shields.deny_subagent.unwrap_or_default(),
                "deny_subagent",
            ),
            config_error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_dir(json: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        if let Some(content) = json {
            let claude_dir = dir.path().join(".claude");
            fs::create_dir_all(&claude_dir).unwrap();
            fs::write(claude_dir.join("tools.json"), content).unwrap();
        }
        dir
    }

    // T-024: tools.json with shields key → custom config applied
    #[test]
    fn t024_shields_config_loaded() {
        let dir = setup_dir(Some(
            r#"{"shields":{"check":true,"acl":false,"safe_dirs":["custom"]}}"#,
        ));
        let config = ShieldsConfig::load(dir.path());
        assert!(config.check_enabled);
        assert!(!config.acl_enabled);
        assert_eq!(config.safe_dirs, vec!["custom"]);
    }

    // T-025: no tools.json → all defaults enabled
    #[test]
    fn t025_missing_file_defaults() {
        let dir = setup_dir(None);
        let config = ShieldsConfig::load(dir.path());
        assert!(config.check_enabled);
        assert!(config.acl_enabled);
        assert!(config.custom_patterns.is_empty());
        assert!(config.secrets_patterns.is_empty());
    }

    // T-026: tools.json without shields key → all defaults
    #[test]
    fn t026_missing_shields_key_defaults() {
        let dir = setup_dir(Some(r#"{"gates":{"knip":true}}"#));
        let config = ShieldsConfig::load(dir.path());
        assert!(config.check_enabled);
        assert!(config.acl_enabled);
    }

    // T-012: custom pattern loaded
    #[test]
    fn t012_custom_pattern_loaded() {
        let dir = setup_dir(Some(
            r#"{"shields":{"custom_patterns":[{"id":"kubectl-delete","regex":"\\bkubectl\\s+delete\\b","context":"kubectl delete is prohibited."}]}}"#,
        ));
        let config = ShieldsConfig::load(dir.path());
        assert_eq!(config.custom_patterns.len(), 1);
        assert_eq!(config.custom_patterns[0].id, "kubectl-delete");
    }

    // T-016: custom secrets pattern loaded
    #[test]
    fn t016_custom_secrets_pattern_loaded() {
        let dir = setup_dir(Some(r#"{"shields":{"secrets_patterns":["\\.tfstate$"]}}"#));
        let config = ShieldsConfig::load(dir.path());
        assert_eq!(config.secrets_patterns.len(), 1);
        assert!(config.secrets_patterns[0].is_match("main.tfstate"));
    }

    // Invalid JSON → defaults + stderr warning
    #[test]
    fn invalid_json_defaults() {
        let dir = setup_dir(Some("not json{{{"));
        let config = ShieldsConfig::load(dir.path());
        assert!(config.check_enabled);
        assert!(config.acl_enabled);
    }

    // SF-05: invalid custom pattern regex → config_error (fail-hard)
    #[test]
    fn invalid_custom_regex_sets_config_error() {
        let dir = setup_dir(Some(
            r#"{"shields":{"custom_patterns":[{"id":"bad","regex":"[invalid","context":"test"}]}}"#,
        ));
        let config = ShieldsConfig::load(dir.path());
        assert!(config.config_error.is_some());
        assert!(
            config
                .config_error
                .unwrap()
                .contains("invalid custom pattern")
        );
    }

    // SF-06: invalid secrets pattern regex → config_error (fail-hard)
    #[test]
    fn invalid_secrets_regex_sets_config_error() {
        let dir = setup_dir(Some(r#"{"shields":{"secrets_patterns":["[bad"]}}"#));
        let config = ShieldsConfig::load(dir.path());
        assert!(config.config_error.is_some());
        assert!(
            config
                .config_error
                .unwrap()
                .contains("invalid secret pattern")
        );
    }

    // Valid patterns → no config_error
    #[test]
    fn valid_patterns_no_config_error() {
        let dir = setup_dir(Some(
            r#"{"shields":{"custom_patterns":[{"id":"ok","regex":"\\btest\\b","context":"test"}]}}"#,
        ));
        let config = ShieldsConfig::load(dir.path());
        assert!(config.config_error.is_none());
        assert_eq!(config.custom_patterns.len(), 1);
    }

    // deny_subagent custom paths
    #[test]
    fn deny_subagent_loaded() {
        let dir = setup_dir(Some(
            r#"{"shields":{"deny_subagent":["rules/","agents/"]}}"#,
        ));
        let config = ShieldsConfig::load(dir.path());
        assert_eq!(config.deny_subagent, vec!["rules/", "agents/"]);
    }

    // Partial config: only check disabled
    #[test]
    fn partial_config_check_disabled() {
        let dir = setup_dir(Some(r#"{"shields":{"check":false}}"#));
        let config = ShieldsConfig::load(dir.path());
        assert!(!config.check_enabled);
        assert!(config.acl_enabled);
    }

    // SEC-04: absolute path in safe_dirs rejected
    #[test]
    fn absolute_safe_dirs_rejected() {
        let dir = setup_dir(Some(
            r#"{"shields":{"safe_dirs":["/tmp","custom","/../etc"]}}"#,
        ));
        let config = ShieldsConfig::load(dir.path());
        assert_eq!(config.safe_dirs, vec!["custom"]);
    }

    // SEC-04: absolute path in deny_subagent rejected
    #[test]
    fn absolute_deny_subagent_rejected() {
        let dir = setup_dir(Some(
            r#"{"shields":{"deny_subagent":["/etc/passwd","rules/"]}}"#,
        ));
        let config = ShieldsConfig::load(dir.path());
        assert_eq!(config.deny_subagent, vec!["rules/"]);
    }

    // SEC-04: traversal in safe_dirs rejected
    #[test]
    fn traversal_safe_dirs_rejected() {
        let dir = setup_dir(Some(r#"{"shields":{"safe_dirs":["../hooks","valid"]}}"#));
        let config = ShieldsConfig::load(dir.path());
        assert_eq!(config.safe_dirs, vec!["valid"]);
    }
}
