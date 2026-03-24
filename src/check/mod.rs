pub mod normalize;
pub mod patterns;
pub mod secrets;
pub mod unwrap;

use crate::input::HookInput;
use crate::output::Decision;

pub fn run(input: &HookInput, custom_patterns: &[patterns::Pattern], custom_secrets: &[regex::Regex]) {
    let command = match input.command() {
        Some(cmd) if !cmd.is_empty() => cmd,
        _ => return,
    };

    let oneline = command.replace('\n', " ");
    let tool = &input.tool_name;
    let agent = input.agent_id.as_deref().unwrap_or("-");
    let all_patterns = PatternSets {
        builtins: patterns::builtin_patterns(),
        custom: custom_patterns,
    };
    let decoded = normalize::decode(&oneline);
    let log_ctx = LogContext { tool, agent, oneline: &oneline };

    if check_via_unwrap(&decoded, &log_ctx, &all_patterns) {
        return;
    }

    if check_via_fallback(&decoded, &log_ctx, &all_patterns) {
        return;
    }

    let staged = secrets::get_staged_files();
    if let Some((file, desc)) = secrets::check_secrets(&oneline, &staged, custom_secrets) {
        eprintln!("shields: BLOCKED tool={tool} agent={agent} secret=\"{desc}\" file=\"{file}\"");
        Decision::block(
            &format!("Sensitive file staged: {file}"),
            Some(&format!("{desc}. Remove it from staging with: git reset HEAD {file}")),
        )
        .print();
        #[allow(clippy::needless_return)]
        return;
    }
}

// ── Phase A ──────────────────────────────────────────────────────────────────

fn check_via_unwrap(decoded: &str, ctx: &LogContext, pats: &PatternSets) -> bool {
    let result = unwrap::unwrap(decoded);

    if let Some(reason) = &result.block {
        let via = format_path(&result.path);
        eprintln!("shields: BLOCKED tool={} agent={} reason=\"{reason:?}\"{via} command=\"{}\"", ctx.tool, ctx.agent, ctx.oneline);
        Decision::block(&format!("Structural block: {reason:?}"), Some(reason.context())).print();
        return true;
    }

    for segment in &result.segments {
        let joined = segment.join(" ");
        let stripped = normalize::strip(&joined);
        if let Some(pat) = pats.find_match(&joined).or_else(|| pats.find_match(&stripped)) {
            let via = format_path(&result.path);
            block_on_pattern(pat, &via, ctx);
            return true;
        }
    }

    false
}

// ── Phase B ──────────────────────────────────────────────────────────────────

fn check_via_fallback(decoded: &str, ctx: &LogContext, pats: &PatternSets) -> bool {
    let stripped = normalize::strip(decoded);

    for target in [ctx.oneline, decoded, stripped.as_str()] {
        if let Some(pat) = pats.find_match(target) {
            block_on_pattern(pat, "", ctx);
            return true;
        }
    }

    false
}

// ── Shared helpers ───────────────────────────────────────────────────────────

struct LogContext<'a> {
    tool: &'a str,
    agent: &'a str,
    oneline: &'a str,
}

struct PatternSets<'a> {
    builtins: &'a [patterns::Pattern],
    custom: &'a [patterns::Pattern],
}

impl PatternSets<'_> {
    fn find_match<'a>(&'a self, command: &str) -> Option<&'a patterns::Pattern> {
        patterns::check_command(command, self.builtins)
            .or_else(|| patterns::check_command(command, self.custom))
    }
}

fn block_on_pattern(pat: &patterns::Pattern, via: &str, ctx: &LogContext) {
    eprintln!("shields: BLOCKED tool={} agent={} pattern=\"{}\"{via} command=\"{}\"", ctx.tool, ctx.agent, pat.id, ctx.oneline);
    eprintln!("shields: hint: {}", pat.context);
    Decision::block(&format!("Dangerous pattern: {}", pat.id), Some(&pat.context)).print();
}

fn format_path(path: &[String]) -> String {
    if path.is_empty() {
        String::new()
    } else {
        format!(" (via {})", path.join(" > "))
    }
}
