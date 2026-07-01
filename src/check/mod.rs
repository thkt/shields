pub mod normalize;
pub mod patterns;
pub mod secrets;
pub mod unwrap;

use crate::input::HookInput;
use crate::output::Decision;

pub fn run(
    input: &HookInput,
    custom_patterns: &[patterns::Pattern],
    custom_secrets: &[regex::Regex],
) {
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
    let log_ctx = LogContext {
        tool,
        agent,
        oneline: &oneline,
    };

    // Phase A (per-segment) then Phase B (whole-line fallback). A block from
    // either phase outranks an ask, so Phase A defers its ask: a pipe-spanning
    // block pattern — invisible to per-segment matching because compound_split
    // consumes the `|` — can still escalate over an earlier ask segment.
    let deferred_ask = match check_via_unwrap(&decoded, &log_ctx, &all_patterns) {
        Verdict::Handled => return,
        Verdict::DeferredAsk(pat, via) => Some((pat, via)),
        Verdict::NoMatch => None,
    };

    if let Some(pat) = find_via_fallback(&oneline, &decoded, &all_patterns)
        && (matches!(pat.action, patterns::Action::Block) || deferred_ask.is_none())
    {
        decide_on_pattern(pat, "", &log_ctx);
        return;
    }

    if let Some((pat, via)) = deferred_ask {
        decide_on_pattern(pat, &via, &log_ctx);
        return;
    }

    let staged = secrets::get_staged_files();
    if let Some((file, desc)) = secrets::check_secrets(&oneline, &staged, custom_secrets) {
        eprintln!("shields: BLOCKED tool={tool} agent={agent} secret=\"{desc}\" file=\"{file}\"");
        Decision::block(
            &format!("Sensitive file staged: {file}"),
            Some(&format!(
                "{desc}. Remove it from staging with: git reset HEAD {file}"
            )),
        )
        .print();
        #[allow(clippy::needless_return)]
        return;
    }
}

// ── Phase A ──────────────────────────────────────────────────────────────────

fn check_via_unwrap<'a>(decoded: &str, ctx: &LogContext, pats: &'a PatternSets) -> Verdict<'a> {
    let result = unwrap::unwrap(decoded);

    if let Some(reason) = &result.block {
        let via = format_path(&result.path);
        eprintln!(
            "shields: BLOCKED tool={} agent={} reason=\"{reason:?}\"{via} command=\"{}\"",
            ctx.tool, ctx.agent, ctx.oneline
        );
        Decision::block(
            &format!("Structural block: {reason:?}"),
            Some(reason.context()),
        )
        .print();
        return Verdict::Handled;
    }

    // Escalate to the most-severe match across all segments. A compound
    // command like "git push && rm -rf /" must block on the rm segment, not
    // stop at the earlier ask-tier git-push: returning on the first match
    // would let an approved ask prompt run a later block-tier payload.
    let mut ask_match: Option<&patterns::Pattern> = None;
    for segment in &result.segments {
        let joined = segment.join(" ");
        let stripped = normalize::strip(&joined);
        if let Some(pat) = pats
            .find_match(&joined)
            .or_else(|| pats.find_match(&stripped))
        {
            match pat.action {
                patterns::Action::Block => {
                    let via = format_path(&result.path);
                    decide_on_pattern(pat, &via, ctx);
                    return Verdict::Handled;
                }
                patterns::Action::Ask => {
                    ask_match.get_or_insert(pat);
                }
            }
        }
    }

    // Defer the ask instead of emitting it: the whole-line fallback may still
    // find a block that per-segment matching cannot (see run's Phase B).
    match ask_match {
        Some(pat) => Verdict::DeferredAsk(pat, format_path(&result.path)),
        None => Verdict::NoMatch,
    }
}

// ── Phase B ──────────────────────────────────────────────────────────────────

fn find_via_fallback<'a>(
    oneline: &str,
    decoded: &str,
    pats: &'a PatternSets,
) -> Option<&'a patterns::Pattern> {
    let stripped = normalize::strip(decoded);

    for target in [oneline, decoded, stripped.as_str()] {
        if let Some(pat) = pats.find_match(target) {
            return Some(pat);
        }
    }

    None
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

/// Outcome of the per-segment Phase A scan. `Handled` means a decision was
/// already printed (a block). `DeferredAsk` holds an ask plus its via-path that
/// the whole-line Phase B fallback may still override with a block. `NoMatch`
/// means nothing matched.
enum Verdict<'a> {
    Handled,
    DeferredAsk(&'a patterns::Pattern, String),
    NoMatch,
}

impl PatternSets<'_> {
    fn find_match<'a>(&'a self, command: &str) -> Option<&'a patterns::Pattern> {
        patterns::check_command(command, self.builtins)
            .or_else(|| patterns::check_command(command, self.custom))
    }
}

fn decision_for(pat: &patterns::Pattern) -> Decision {
    match pat.action {
        patterns::Action::Block => Decision::block(
            &format!("Dangerous pattern: {}", pat.id),
            Some(&pat.context),
        ),
        patterns::Action::Ask => {
            Decision::ask(&format!("Review required: {}", pat.id), Some(&pat.context))
        }
    }
}

fn decide_on_pattern(pat: &patterns::Pattern, via: &str, ctx: &LogContext) {
    let label = match pat.action {
        patterns::Action::Block => "BLOCKED",
        patterns::Action::Ask => "ASK",
    };
    eprintln!(
        "shields: {label} tool={} agent={} pattern=\"{}\"{via} command=\"{}\"",
        ctx.tool, ctx.agent, pat.id, ctx.oneline
    );
    eprintln!("shields: hint: {}", pat.context);
    decision_for(pat).print();
}

fn format_path(path: &[String]) -> String {
    if path.is_empty() {
        String::new()
    } else {
        format!(" (via {})", path.join(" > "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use patterns::{builtin_patterns, check_command};

    fn matched(command: &str) -> &'static patterns::Pattern {
        check_command(command, builtin_patterns()).expect("command should match a builtin pattern")
    }

    #[test]
    fn ask_pattern_yields_ask_decision() {
        let pat = matched("git push origin main");
        assert_eq!(pat.id, "git-push");
        let json = serde_json::to_value(decision_for(pat)).unwrap();
        assert_eq!(json["decision"], "ask");
    }

    #[test]
    fn block_pattern_yields_block_decision() {
        let pat = matched("rm -rf /tmp/x");
        assert_eq!(pat.id, "rm-recursive");
        let json = serde_json::to_value(decision_for(pat)).unwrap();
        assert_eq!(json["decision"], "block");
    }
}
