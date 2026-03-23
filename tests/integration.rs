use std::process::Command;

fn shields(subcommand: &str, stdin_json: &str) -> (String, String, i32) {
    let bin = std::env::var("CARGO_BIN_EXE_shields").expect("CARGO_BIN_EXE_shields");
    let output = Command::new(bin)
        .arg(subcommand)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(stdin_json.as_bytes()).ok();
            }
            child.wait_with_output()
        })
        .expect("failed to run shields");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

fn parse_decision(stdout: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(stdout)
        .ok()
        .and_then(|v| v["decision"].as_str().map(String::from))
}

// =============================================================
// check subcommand integration tests (TC-01)
// =============================================================

// T-001: dangerous command → block
#[test]
fn check_blocks_rm_rf() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
    let (stdout, stderr, _) = shields("check", input);
    assert_eq!(parse_decision(&stdout), Some("block".into()));
    assert!(stderr.contains("BLOCKED"));
}

// T-002: safe command → pass (exit 0, no output)
#[test]
fn check_passes_safe_command() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"cargo test"}}"#;
    let (stdout, _, code) = shields("check", input);
    assert!(stdout.is_empty(), "safe command should produce no output");
    assert_eq!(code, 0);
}

// T-004+T-009: normalized bypass caught (N1 quotes + N6 backslash)
#[test]
fn check_blocks_normalized_bypass() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"'r\\m' -rf /"}}"#;
    let (stdout, _, _) = shields("check", input);
    assert_eq!(parse_decision(&stdout), Some("block".into()));
}

// T-027: empty stdin → block (fail-closed)
#[test]
fn check_blocks_empty_stdin() {
    let (stdout, stderr, _) = shields("check", "");
    assert_eq!(parse_decision(&stdout), Some("block".into()));
    assert!(stderr.contains("malformed"));
}

// T-028: malformed JSON → block (fail-closed)
#[test]
fn check_blocks_malformed_json() {
    let (stdout, stderr, _) = shields("check", "not json{{{");
    assert_eq!(parse_decision(&stdout), Some("block".into()));
    assert!(stderr.contains("malformed"));
}

// FR-001: empty command → pass through (exit 0)
#[test]
fn check_passes_empty_command() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":""}}"#;
    let (stdout, _, code) = shields("check", input);
    assert!(stdout.is_empty());
    assert_eq!(code, 0);
}

// Absolute path bypass: /bin/rm should be caught by \b word boundary
#[test]
fn check_blocks_absolute_path_rm() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"/bin/rm -rf /"}}"#;
    let (stdout, _, _) = shields("check", input);
    assert_eq!(parse_decision(&stdout), Some("block".into()));
}

// T-033: blocked pattern has stderr log
#[test]
fn check_block_logs_to_stderr() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#;
    let (stdout, stderr, _) = shields("check", input);
    assert_eq!(parse_decision(&stdout), Some("block".into()));
    assert!(stderr.contains("git-push"));
}

// =============================================================
// acl subcommand integration tests (TC-02)
// =============================================================

// T-029: empty stdin → deny (fail-closed)
#[test]
fn acl_denies_empty_stdin() {
    let (stdout, stderr, _) = shields("acl", "");
    assert_eq!(parse_decision(&stdout), Some("deny".into()));
    assert!(stderr.contains("malformed"));
}

// T-022: path traversal → deny
#[test]
fn acl_denies_path_traversal() {
    let input = r#"{"tool_name":"Write","tool_input":{"file_path":"../../../etc/passwd"}}"#;
    let (stdout, _, _) = shields("acl", input);
    assert_eq!(parse_decision(&stdout), Some("deny".into()));
}

// File tool with no file_path → pass through
#[test]
fn acl_passes_bash_tool() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let (stdout, _, code) = shields("acl", input);
    assert!(stdout.is_empty());
    assert_eq!(code, 0);
}
