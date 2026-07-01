use std::path::Path;

#[derive(Debug, PartialEq)]
pub enum AclDecision {
    Approve,
    Ask,
    Deny,
    /// No shields output: defer to Claude Code's standard permission flow.
    Passthrough,
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
            .chain(deny_subagent.iter().map(String::as_str))
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

    // 2. Sensitive file access → deny writes, ask everything else.
    // No fallthrough: a sensitive path must never reach the rule-9 Passthrough,
    // so a tool that is neither write-class nor Read still prompts.
    if is_sensitive_file(file_path) {
        if is_write_tool(tool_name) {
            return (AclDecision::Deny, "Sensitive file write blocked");
        }
        return (AclDecision::Ask, "Sensitive file access");
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

    // 9. Everything else → passthrough (defer to standard permission flow)
    (AclDecision::Passthrough, "No special handling required")
}

fn path_matches(file_path: &Path, target: &Path) -> bool {
    file_path.starts_with(target)
}

fn is_sensitive_file(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Extension-based checks
    let sensitive_extensions = [".env", ".key", ".secret", ".token", ".credentials", ".pem"];
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

    // Cloud credential dirs and network auth file. Lowercase first: macOS HFS+
    // is case-insensitive, so /.AWS/credentials resolves to the same file, but a
    // case-sensitive match would miss it and fall through to rule-9 Passthrough.
    let lower = path_str.to_ascii_lowercase();
    if lower.contains("/.aws/") || lower.contains("/.kube/") {
        return true;
    }
    if lower.ends_with("/.netrc") {
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
            &["custom".to_owned()],
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
            &["rules/".to_owned()],
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

    // --- Non-.claude paths → passthrough (standard permission flow) ---

    #[test]
    fn project_file_passthrough() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/project/src/main.rs"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Passthrough);
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

    // --- RC-3: non-write tool on sensitive file → ask (no passthrough fallthrough) ---
    // A sensitive path reached by a tool that is neither write-class nor Read
    // (e.g. NotebookEdit) must prompt, not silently defer to the standard flow.
    // (At runtime Bash carries no file_path, so acl::run early-returns before
    // evaluate — covered by the acl_passes_bash_tool integration test.)

    #[test]
    fn sensitive_file_non_write_tool_asks() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/project/.env"),
            "NotebookEdit",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Ask);
    }

    // --- CLUSTER-A: cloud credential + network auth locations are sensitive ---

    #[test]
    fn aws_credentials_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.aws/credentials"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn kube_config_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.kube/config"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn pem_file_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/certs/server.pem"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    #[test]
    fn netrc_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.netrc"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
    }

    // security F-1: macOS HFS+ is case-insensitive, so `/.AWS/credentials`
    // resolves to the same file as `/.aws/credentials`; the check must match it.
    #[test]
    fn aws_credentials_uppercase_write_denied() {
        let (decision, _) = evaluate(
            Path::new("/Users/test/.AWS/credentials"),
            "Write",
            false,
            &home(),
            &[],
            &[],
        );
        assert_eq!(decision, AclDecision::Deny);
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
