pub mod normalize;
pub mod patterns;
pub mod secrets;

use crate::input::HookInput;
use crate::output::Decision;

pub fn run(input: &HookInput, custom_patterns: &[patterns::Pattern], custom_secrets: &[regex::Regex]) {
    let command = match input.command() {
        Some(cmd) if !cmd.is_empty() => cmd,
        _ => return,
    };

    let oneline = command.replace('\n', " ");
    let normalized = normalize::normalize(&oneline);

    let builtins = patterns::builtin_patterns();
    for target in [&oneline, &normalized] {
        if let Some(pat) = patterns::check_command(target, builtins)
            .or_else(|| patterns::check_command(target, custom_patterns))
        {
            eprintln!("shields: BLOCKED pattern=\"{}\" command=\"{}\"", pat.id, oneline);
            Decision::block(
                &format!("Dangerous pattern: {}", pat.id),
                Some(&pat.context),
            )
            .print();
            return;
        }
    }

    let staged = secrets::get_staged_files();
    if let Some((file, desc)) = secrets::check_secrets(&oneline, &staged, custom_secrets) {
        eprintln!("shields: BLOCKED secret=\"{desc}\" file=\"{file}\"");
        Decision::block(
            &format!("Sensitive file staged: {file}"),
            Some(&format!("{desc}. Remove it from staging with: git reset HEAD {file}")),
        )
        .print();
    }
}
