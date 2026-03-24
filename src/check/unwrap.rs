use std::path::Path;

// --- Thresholds (fail-close) ---

const MAX_DEPTH: usize = 5;
const MAX_TOKENS: usize = 1000;
const MAX_SEGMENTS: usize = 20;
const MAX_INPUT_BYTES: usize = 1_048_576; // 1 MB

// --- Public types ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    DynamicGeneration,
    PipeToShell,
    DepthExceeded,
    TooManyTokens,
    TooManySegments,
    InputTooLarge,
    ParseError,
}

impl BlockReason {
    pub fn context(&self) -> &'static str {
        match self {
            Self::DynamicGeneration => {
                "Dynamic command generation (e.g. $() or backticks) inside shell -c is blocked."
            }
            Self::PipeToShell => {
                "Piping to a shell (e.g. curl | bash) is blocked. Download and review first."
            }
            Self::DepthExceeded => "Command nesting depth exceeded safety limit.",
            Self::TooManyTokens => "Command has too many tokens.",
            Self::TooManySegments => "Command has too many segments.",
            Self::InputTooLarge => "Command input exceeds size limit.",
            Self::ParseError => "Command could not be parsed safely.",
        }
    }
}

#[derive(Debug)]
pub struct UnwrapResult {
    pub segments: Vec<Vec<String>>,
    pub block: Option<BlockReason>,
    pub path: Vec<String>,
}

impl UnwrapResult {
    fn empty() -> Self {
        Self {
            segments: vec![],
            block: None,
            path: vec![],
        }
    }

    fn blocked(reason: BlockReason) -> Self {
        Self {
            segments: vec![],
            block: Some(reason),
            path: vec![],
        }
    }
}

// --- Recognized shells and wrappers ---

const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh"];

const WRAPPERS: &[&str] = &[
    "sudo", "doas", "pkexec", "env", "nohup", "nice", "exec", "command",
];

const WRAPPERS_WITH_ARG: &[&str] = &["timeout"];

// --- Entry point ---

pub fn unwrap(command: &str) -> UnwrapResult {
    if command.is_empty() {
        return UnwrapResult::empty();
    }
    if command.len() > MAX_INPUT_BYTES {
        return UnwrapResult::blocked(BlockReason::InputTooLarge);
    }

    let segments = compound_split(command);

    if segments.len() > MAX_SEGMENTS {
        return UnwrapResult::blocked(BlockReason::TooManySegments);
    }

    let mut all_segments = Vec::new();
    let mut path = Vec::new();

    for (i, seg) in segments.iter().enumerate() {
        let tokens = match shell_words::split(seg) {
            Ok(t) => t,
            Err(_) => return UnwrapResult::blocked(BlockReason::ParseError),
        };

        if tokens.len() > MAX_TOKENS {
            return UnwrapResult::blocked(BlockReason::TooManyTokens);
        }

        if i > 0 && is_bare_shell(&tokens) {
            return UnwrapResult::blocked(BlockReason::PipeToShell);
        }

        let mut seg_path = Vec::new();
        match unwrap_tokens(&tokens, 0, &mut seg_path) {
            Ok(inner_segments) => {
                if !seg_path.is_empty() && path.is_empty() {
                    path = seg_path;
                }
                all_segments.extend(inner_segments);
            }
            Err(reason) => return UnwrapResult::blocked(reason),
        }
    }

    UnwrapResult {
        segments: all_segments,
        block: None,
        path,
    }
}

// --- Compound split (quote-aware) ---

fn compound_split(command: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(c) = chars.next() {
        // Single-quoted: no escapes, only closing ' ends the region (POSIX)
        if in_single {
            current.push(c);
            if c == '\'' {
                in_single = false;
            }
            continue;
        }
        // Double-quoted: backslash escapes the next char
        if in_double {
            if c == '\\' {
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
                continue;
            }
            current.push(c);
            if c == '"' {
                in_double = false;
            }
            continue;
        }
        // Unquoted
        match c {
            '\\' => {
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            '\'' => {
                in_single = true;
                current.push(c);
            }
            '"' => {
                in_double = true;
                current.push(c);
            }
            '&' if chars.peek() == Some(&'&') => {
                chars.next();
                push_segment(&mut segments, &mut current);
            }
            '|' if chars.peek() == Some(&'|') => {
                chars.next();
                push_segment(&mut segments, &mut current);
            }
            '|' => {
                push_segment(&mut segments, &mut current);
            }
            ';' => {
                push_segment(&mut segments, &mut current);
            }
            _ => current.push(c),
        }
    }

    push_segment(&mut segments, &mut current);
    segments
}

fn push_segment(segments: &mut Vec<String>, current: &mut String) {
    if !current.trim().is_empty() {
        segments.push(current.trim().to_string());
    }
    current.clear();
}

// --- Recursive unwrap ---

fn unwrap_tokens(
    tokens: &[String],
    depth: usize,
    path: &mut Vec<String>,
) -> Result<Vec<Vec<String>>, BlockReason> {
    if depth > MAX_DEPTH {
        return Err(BlockReason::DepthExceeded);
    }
    if tokens.is_empty() {
        return Ok(vec![]);
    }

    let stripped = strip_wrappers(tokens, path);
    if stripped.is_empty() {
        return Ok(vec![]);
    }

    // Check for shell launcher: bash/sh/... -c "inner"
    if let Some(inner) = extract_shell_launcher(&stripped, path) {
        if contains_dynamic_generation(&inner) {
            return Err(BlockReason::DynamicGeneration);
        }

        let inner_segments = compound_split(&inner);
        let mut results = Vec::new();
        for seg in &inner_segments {
            let inner_tokens = shell_words::split(seg).map_err(|_| BlockReason::ParseError)?;
            results.extend(unwrap_tokens(&inner_tokens, depth + 1, path)?);
        }
        return Ok(results);
    }

    Ok(vec![stripped])
}

// --- Wrapper stripping ---

fn strip_wrappers(tokens: &[String], path: &mut Vec<String>) -> Vec<String> {
    let mut i = 0;
    let len = tokens.len();

    while i < len {
        let cmd = basename(&tokens[i]);

        if WRAPPERS.contains(&cmd) {
            path.push(cmd.to_string());
            i += 1;
            // Skip env's KEY=VAL arguments
            if cmd == "env" {
                while i < len && tokens[i].contains('=') {
                    i += 1;
                }
            }
            continue;
        }

        if WRAPPERS_WITH_ARG.contains(&cmd) {
            path.push(cmd.to_string());
            i += 1;
            if i < len {
                i += 1;
            }
            continue;
        }

        break;
    }

    tokens[i..].to_vec()
}

// --- Shell launcher extraction ---

fn extract_shell_launcher(tokens: &[String], path: &mut Vec<String>) -> Option<String> {
    if tokens.len() < 2 {
        return None;
    }

    let cmd = basename(&tokens[0]);
    if !SHELLS.contains(&cmd) {
        return None;
    }

    // Look for -c flag (possibly combined like -lc, -xc)
    for (i, arg) in tokens.iter().enumerate().skip(1) {
        if arg == "-c" {
            let cmd_idx = i + 1;
            if cmd_idx < tokens.len() {
                path.push(format!("{cmd} -c"));
                return Some(tokens[cmd_idx].clone());
            }
            return None;
        }
        // Combined short flags like -lc, -xc (single dash + ascii letters + c)
        if arg.starts_with('-')
            && !arg.starts_with("--")
            && arg.ends_with('c')
            && arg.len() >= 3
            && arg[1..].bytes().all(|b| b.is_ascii_alphabetic())
        {
            let cmd_idx = i + 1;
            if cmd_idx < tokens.len() {
                path.push(format!("{cmd} {arg}"));
                return Some(tokens[cmd_idx].clone());
            }
            return None;
        }
        if !arg.starts_with('-') {
            return None;
        }
    }

    None
}

// --- Structural detection ---

fn contains_dynamic_generation(command: &str) -> bool {
    command.contains("$(") || command.contains('`')
}

fn is_bare_shell(tokens: &[String]) -> bool {
    // Strip wrappers before checking — catches `sudo bash`, `env sh`, etc.
    let mut path = Vec::new();
    let stripped = strip_wrappers(tokens, &mut path);
    match stripped.first() {
        Some(t) => {
            let cmd = basename(t);
            SHELLS.contains(&cmd) && stripped.len() == 1
        }
        None => false,
    }
}

fn basename(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    // --- T-004: compound split ---

    #[test]
    fn t004_compound_split_and_or() {
        let segs = compound_split("echo ok && rm -rf /");
        assert_eq!(segs, vec!["echo ok", "rm -rf /"]);
    }

    // T-005: quoted operators not split
    #[test]
    fn t005_quoted_operators_not_split() {
        let segs = compound_split("echo 'a && b'");
        assert_eq!(segs.len(), 1);
    }

    // T-006: multiple operators
    #[test]
    fn t006_multiple_operators() {
        let segs = compound_split("a && b || c; d");
        assert_eq!(segs, vec!["a", "b", "c", "d"]);
    }

    // T-027: no space around operator
    #[test]
    fn t027_no_space_compound_split() {
        let segs = compound_split("echo ok&&rm -rf /");
        assert_eq!(segs, vec!["echo ok", "rm -rf /"]);
    }

    // --- T-007, T-008: wrapper stripping ---

    #[test]
    fn t007_strip_sudo_env() {
        let tokens = tokens(&["sudo", "env", "rm", "-rf", "/"]);
        let mut path = vec![];
        let result = strip_wrappers(&tokens, &mut path);
        assert_eq!(result, vec!["rm", "-rf", "/"]);
        assert_eq!(path, vec!["sudo", "env"]);
    }

    #[test]
    fn t008_strip_nohup_timeout() {
        let tokens = tokens(&["nohup", "timeout", "5", "rm", "-rf", "/"]);
        let mut path = vec![];
        let result = strip_wrappers(&tokens, &mut path);
        assert_eq!(result, vec!["rm", "-rf", "/"]);
        assert_eq!(path, vec!["nohup", "timeout"]);
    }

    // T-029: env KEY=VAL
    #[test]
    fn t029_strip_env_key_val() {
        let tokens = tokens(&["env", "KEY=VAL", "rm", "-rf", "/"]);
        let mut path = vec![];
        let result = strip_wrappers(&tokens, &mut path);
        assert_eq!(result, vec!["rm", "-rf", "/"]);
    }

    // --- T-009..013: shell launcher extraction ---

    #[test]
    fn t009_shell_launcher_bash_c() {
        let tokens = tokens(&["bash", "-c", "rm -rf /"]);
        let mut path = vec![];
        let inner = extract_shell_launcher(&tokens, &mut path);
        assert_eq!(inner, Some("rm -rf /".into()));
        assert_eq!(path, vec!["bash -c"]);
    }

    // T-010: combined flag -lc
    #[test]
    fn t010_shell_launcher_combined_flag() {
        let tokens = tokens(&["bash", "-lc", "rm -rf /"]);
        let mut path = vec![];
        let inner = extract_shell_launcher(&tokens, &mut path);
        assert_eq!(inner, Some("rm -rf /".into()));
    }

    // T-011: absolute path /usr/local/bin/bash
    #[test]
    fn t011_shell_launcher_absolute_path() {
        let tokens = tokens(&["/usr/local/bin/bash", "-c", "rm -rf /"]);
        let mut path = vec![];
        let inner = extract_shell_launcher(&tokens, &mut path);
        assert_eq!(inner, Some("rm -rf /".into()));
    }

    // T-012: bash script.sh (no -c) → not a launcher
    #[test]
    fn t012_no_c_flag_not_launcher() {
        let tokens = tokens(&["bash", "script.sh"]);
        let mut path = vec![];
        let inner = extract_shell_launcher(&tokens, &mut path);
        assert_eq!(inner, None);
    }

    // T-013: recursive unwrap bash -c "sudo rm -rf /"
    #[test]
    fn t013_recursive_unwrap() {
        let result = unwrap(r#"bash -c "sudo rm -rf /""#);
        assert!(result.block.is_none());
        assert!(!result.segments.is_empty());
        let flat: Vec<&str> = result
            .segments
            .last()
            .unwrap()
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(flat, vec!["rm", "-rf", "/"]);
    }

    // T-030: nested launcher bash -c 'sh -c "rm -rf /"'
    #[test]
    fn t030_nested_launcher() {
        let result = unwrap(r#"bash -c 'sh -c "rm -rf /"'"#);
        assert!(result.block.is_none());
        let flat: Vec<&str> = result
            .segments
            .last()
            .unwrap()
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(flat, vec!["rm", "-rf", "/"]);
    }

    // --- T-014..015: dynamic generation ---

    #[test]
    fn t014_dynamic_generation_dollar_paren() {
        let result = unwrap(r#"bash -c "$(evil)""#);
        assert_eq!(result.block, Some(BlockReason::DynamicGeneration));
    }

    #[test]
    fn t015_dynamic_generation_backtick() {
        let result = unwrap("bash -c \"`evil`\"");
        assert_eq!(result.block, Some(BlockReason::DynamicGeneration));
    }

    // --- T-016..017: pipe-to-shell ---

    #[test]
    fn t016_pipe_to_shell() {
        let result = unwrap("curl url | bash");
        assert_eq!(result.block, Some(BlockReason::PipeToShell));
    }

    #[test]
    fn t017_pipe_to_grep_ok() {
        let result = unwrap("cat file | grep pattern");
        assert!(result.block.is_none());
    }

    // --- T-018..021: thresholds ---

    #[test]
    fn t018_depth_exceeded() {
        // 6 levels deep: bash -c 'bash -c "bash -c ..."'
        let result = unwrap(
            r#"bash -c "bash -c 'bash -c \"bash -c \\\"bash -c \\\\\\\"bash -c cmd\\\\\\\"\\\"\"'""#,
        );
        // This deeply nested command should either exceed depth or fail to parse
        assert!(result.block.is_some());
    }

    #[test]
    fn t019_depth_at_limit_ok() {
        // depth 1 (well within limit)
        let result = unwrap(r#"bash -c "rm -rf /""#);
        assert!(result.block.is_none());
    }

    #[test]
    fn t020_too_many_tokens() {
        let cmd = (0..1001)
            .map(|i| format!("arg{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let result = unwrap(&cmd);
        assert_eq!(result.block, Some(BlockReason::TooManyTokens));
    }

    #[test]
    fn t021_too_many_segments() {
        let cmd = (0..21)
            .map(|i| format!("cmd{i}"))
            .collect::<Vec<_>>()
            .join(" ; ");
        let result = unwrap(&cmd);
        assert_eq!(result.block, Some(BlockReason::TooManySegments));
    }

    // T-028: empty string
    #[test]
    fn t028_empty_string() {
        let result = unwrap("");
        assert!(result.block.is_none());
        assert!(result.segments.is_empty());
    }

    // --- T-022, T-023: full unwrap → pattern matchable segments ---

    #[test]
    fn t022_sudo_env_bash_c_rm() {
        let result = unwrap(r#"sudo env bash -c "rm -rf /""#);
        assert!(result.block.is_none());
        let flat: Vec<&str> = result
            .segments
            .last()
            .unwrap()
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(flat, vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn t023_safe_command() {
        let result = unwrap("cargo test");
        assert!(result.block.is_none());
        assert_eq!(result.segments, vec![vec!["cargo", "test"]]);
    }

    // --- Path tracking ---

    #[test]
    fn path_tracks_wrappers() {
        let result = unwrap(r#"sudo env bash -c "rm -rf /""#);
        assert!(result.path.contains(&"sudo".to_string()));
        assert!(result.path.contains(&"env".to_string()));
        assert!(result.path.iter().any(|p| p.contains("bash")));
    }

    // --- Pipe splitting ---

    #[test]
    fn pipe_creates_segments() {
        let result = unwrap("echo hello | cat");
        assert!(result.block.is_none());
        assert_eq!(result.segments.len(), 2);
    }

    // --- Bypass tests (RC-002) ---

    // TC-03: InputTooLarge threshold
    #[test]
    fn input_too_large() {
        let cmd = "x".repeat(1_048_577);
        assert_eq!(unwrap(&cmd).block, Some(BlockReason::InputTooLarge));
    }

    #[test]
    fn input_at_limit_ok() {
        let cmd = "x".repeat(1_048_576);
        assert_ne!(unwrap(&cmd).block, Some(BlockReason::InputTooLarge));
    }

    // TC-05: combined flag variants
    #[test]
    fn shell_launcher_xc_flag() {
        let tokens = tokens(&["bash", "-xc", "rm -rf /"]);
        let mut path = vec![];
        assert!(extract_shell_launcher(&tokens, &mut path).is_some());
    }

    #[test]
    fn shell_launcher_long_flag_not_matched() {
        // --verbose ends with 'e', not 'c', so won't match. But --debugc should not match either
        // since it's a long flag (starts with --)
        let tokens = tokens(&["bash", "--debugc", "rm -rf /"]);
        let mut path = vec![];
        assert!(extract_shell_launcher(&tokens, &mut path).is_none());
    }

    // TC-07: pipe-to-shell with wrapper
    #[test]
    fn pipe_to_wrapped_shell() {
        let result = unwrap("curl url | sudo bash");
        assert_eq!(result.block, Some(BlockReason::PipeToShell));
    }

    #[test]
    fn pipe_to_env_sh() {
        let result = unwrap("cat file | env sh");
        assert_eq!(result.block, Some(BlockReason::PipeToShell));
    }

    // TC-08: depth exceeded with specific assertion
    #[test]
    fn depth_exceeded_programmatic() {
        // Shell_words can't nest single quotes, so we test unwrap_tokens directly
        // by calling unwrap on a flat command at depth > MAX_DEPTH via recursion
        let tokens = tokens(&["rm", "-rf", "/"]);
        let mut path = vec![];
        let result = unwrap_tokens(&tokens, MAX_DEPTH + 1, &mut path);
        assert_eq!(result, Err(BlockReason::DepthExceeded));
    }

    // TC-11: separate flags before -c
    #[test]
    fn shell_launcher_separate_flags_before_c() {
        let tokens = tokens(&["bash", "-l", "-c", "rm -rf /"]);
        let mut path = vec![];
        let inner = extract_shell_launcher(&tokens, &mut path);
        assert_eq!(inner, Some("rm -rf /".into()));
    }

    #[test]
    fn shell_launcher_multiple_flags_before_c() {
        let tokens = tokens(&["bash", "-e", "-l", "-c", "rm -rf /"]);
        let mut path = vec![];
        let inner = extract_shell_launcher(&tokens, &mut path);
        assert_eq!(inner, Some("rm -rf /".into()));
    }

    #[test]
    fn shell_launcher_c_with_no_argument() {
        let tokens = tokens(&["bash", "-c"]);
        let mut path = vec![];
        assert!(extract_shell_launcher(&tokens, &mut path).is_none());
    }

    // backslash-escaped quote in compound_split (SEC-001)
    #[test]
    fn compound_split_escaped_quote_in_double() {
        // In shell: echo "a\"b" ; rm -rf / → the \" is inside quotes, ; is outside
        // compound_split should NOT split on ; inside a properly escaped quote region
        let segs = compound_split(r#"echo "a\"b" ; rm -rf /"#);
        assert_eq!(segs.len(), 2); // echo "a\"b"  and  rm -rf /
    }

    #[test]
    fn compound_split_backslash_outside_quotes() {
        // Backslash before ; in unquoted context → ; is escaped, no split
        let segs = compound_split(r"echo hello\; world");
        assert_eq!(segs.len(), 1);
    }

    // doas wrapper stripping (SEC-005)
    #[test]
    fn strip_doas() {
        let tokens = tokens(&["doas", "rm", "-rf", "/"]);
        let mut path = vec![];
        let result = strip_wrappers(&tokens, &mut path);
        assert_eq!(result, vec!["rm", "-rf", "/"]);
        assert_eq!(path, vec!["doas"]);
    }

    #[test]
    fn doas_bash_c_dynamic_gen() {
        let result = unwrap(r#"doas bash -c "$(evil)""#);
        assert_eq!(result.block, Some(BlockReason::DynamicGeneration));
    }
}
