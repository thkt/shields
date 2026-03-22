use std::path::Path;

#[derive(Debug, PartialEq)]
pub enum AclDecision {
    Approve,
    Ask,
    Deny,
}

/// Priority order: deny > ask > approve.
pub fn evaluate(
    file_path: &Path,
    tool_name: &str,
    is_subagent: bool,
    home: &Path,
    safe_dirs: &[String],
    deny_subagent: &[String],
) -> (AclDecision, &'static str) {
    let claude_dir = home.join(".claude");

    // 1. Subagent → deny security-critical paths
    if is_subagent {
        let default_deny = ["hooks/", "settings.json", "CLAUDE.md"];
        for deny_path in default_deny
            .iter()
            .copied()
            .chain(deny_subagent.iter().map(|s| s.as_str()))
        {
            let full = claude_dir.join(deny_path);
            if path_matches(file_path, &full) {
                return (
                    AclDecision::Deny,
                    "Subagent cannot modify security-critical files",
                );
            }
        }
    }

    // 2. Sensitive file access → deny writes, ask reads
    if is_sensitive_file(file_path) {
        if is_write_tool(tool_name) {
            return (AclDecision::Deny, "Sensitive file write blocked");
        }
        if tool_name == "Read" {
            return (AclDecision::Ask, "Reading sensitive file");
        }
    }

    // 3. Security-critical .claude/ paths → ask
    let security_paths = [
        claude_dir.join("hooks/security"),
        claude_dir.join("CLAUDE.md"),
        claude_dir.join("settings.json"),
    ];
    for sec_path in &security_paths {
        if path_matches(file_path, sec_path) {
            return (AclDecision::Ask, "Security-critical configuration file");
        }
    }

    // 4. All hooks → ask
    if path_matches(file_path, &claude_dir.join("hooks")) {
        return (AclDecision::Ask, "Hook script modification");
    }

    // 5. System prompt directories → ask
    let prompt_dirs = [claude_dir.join("memory"), claude_dir.join("projects")];
    for dir in &prompt_dirs {
        if path_matches(file_path, dir) {
            return (AclDecision::Ask, "System prompt file");
        }
    }

    // 6. Custom safe dirs → approve
    for dir in safe_dirs {
        if path_matches(file_path, &claude_dir.join(dir)) {
            return (AclDecision::Approve, "Claude data directory");
        }
    }

    // 7. Default safe data dirs → approve
    let default_safe = ["workspace", "logs", "cache", "todos", "tasks", "teams"];
    for dir in &default_safe {
        if path_matches(file_path, &claude_dir.join(dir)) {
            return (AclDecision::Approve, "Claude data directory");
        }
    }

    // 8. Other .claude/ paths → ask
    if path_matches(file_path, &claude_dir) {
        return (AclDecision::Ask, "Claude content directory");
    }

    // 9. Everything else → ask (requires user confirmation)
    (AclDecision::Ask, "Requires user confirmation")
}

fn path_matches(file_path: &Path, target: &Path) -> bool {
    file_path.starts_with(target)
}

fn is_sensitive_file(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Extension-based checks
    let sensitive_extensions = [".env", ".key", ".secret", ".token", ".credentials"];
    for ext in &sensitive_extensions {
        if path_str.ends_with(ext) || path_str.contains(&format!("{ext}.")) {
            return true;
        }
    }

    // SSH key and config checks
    if let Some(pos) = path_str.find("/.ssh/") {
        let after = &path_str[pos + 6..];
        if after.starts_with("id_")
            || after.starts_with("authorized_keys")
            || after.starts_with("known_hosts")
            || after.starts_with("config")
        {
            return true;
        }
    }

    // Secrets directory
    if path_str.contains("/secrets/") {
        return true;
    }

    false
}

fn is_write_tool(tool_name: &str) -> bool {
    matches!(tool_name, "Write" | "Edit" | "MultiEdit")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn home() -> PathBuf {
        PathBuf::from("/Users/test")
    }

    // --- T-017: subagent × security path → deny ---

    #[test]
    fn t017_subagent_hooks_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/hooks/test.sh"),
            "Write",
            true,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn subagent_settings_json_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/settings.json"),
            "Write",
            true,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn subagent_claude_md_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/CLAUDE.md"),
            "Write",
            true,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    // --- T-018: main agent × security path → ask ---

    #[test]
    fn t018_main_agent_hooks_write_ask() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/hooks/test.sh"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Ask);
    }

    // --- T-019: subagent × safe dir → approve ---

    #[test]
    fn t019_subagent_workspace_approve() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/workspace/plan.md"),
            "Write",
            true,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Approve);
    }

    // --- T-020: main agent × .env write → deny ---

    #[test]
    fn t020_main_env_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/project/.env"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    // --- T-021: main agent × .env read → ask ---

    #[test]
    fn t021_main_env_read_ask() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/project/.env"),
            "Read",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Ask);
    }

    // --- T-023: custom safe_dirs → approve ---

    #[test]
    fn t023_custom_safe_dir_approve() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/custom/x.md"),
            "Write",
            false,
            &home(),
            &["custom".to_string()],
            &[],
        );
        assert_eq!(decision, AclDecision::Approve);
    }

    // --- T-011: safe dirs → approve ---

    #[test]
    fn logs_dir_approve() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/logs/test.log"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Approve);
    }

    #[test]
    fn cache_dir_approve() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/cache/index.json"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Approve);
    }

    #[test]
    fn tasks_dir_approve() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/tasks/task.md"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Approve);
    }

    #[test]
    fn teams_dir_approve() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/teams/team.json"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Approve);
    }

    // --- System prompt dirs → ask ---

    #[test]
    fn memory_dir_ask() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/memory/note.md"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Ask);
    }

    #[test]
    fn projects_dir_ask() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/projects/proj/CLAUDE.md"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Ask);
    }

    // --- Sensitive files ---

    #[test]
    fn ssh_key_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.ssh/id_rsa"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn ssh_ed25519_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.ssh/id_ed25519"),
            "Edit",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn secrets_dir_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/project/secrets/api.key"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn env_production_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/project/.env.production"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    // --- Custom deny_subagent paths ---

    #[test]
    fn custom_deny_subagent_path() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/rules/custom.md"),
            "Write",
            true,
            &home(),
            &[],
            &["rules/".to_string()],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    // --- Other .claude/ paths → ask ---

    #[test]
    fn claude_skills_ask() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/skills/custom.md"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Ask);
    }

    // --- Non-.claude paths → ask ---

    #[test]
    fn project_file_ask() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/project/src/main.rs"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Ask);
    }

    // --- SEC-08: expanded SSH key coverage ---

    #[test]
    fn ssh_id_ecdsa_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.ssh/id_ecdsa"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn ssh_id_dsa_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.ssh/id_dsa"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn ssh_authorized_keys_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.ssh/authorized_keys"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn ssh_config_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.ssh/config"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn ssh_known_hosts_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.ssh/known_hosts"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    // --- TC-03: sensitive file boundary tests ---

    #[test]
    fn env_local_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/project/.env.local"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn key_backup_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/project/api.key.backup"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn token_file_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/project/auth.token"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn ssh_id_rsa_read_ask() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.ssh/id_rsa"),
            "Read",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Ask);
    }

    // --- TC-04: non-write tool on sensitive file → falls through ---

    #[test]
    fn env_bash_tool_ask() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/project/.env"),
            "Bash",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Ask);
    }

    // --- TC-08: subagent × sensitive file combinations ---

    #[test]
    fn subagent_env_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/project/.env"),
            "Write",
            true,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn subagent_env_read_ask() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/project/.env"),
            "Read",
            true,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Ask);
    }

    #[test]
    fn subagent_skills_dir_ask() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.claude/skills/custom.md"),
            "Write",
            true,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Ask);
    }
}
