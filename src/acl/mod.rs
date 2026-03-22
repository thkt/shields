pub mod path;
pub mod rules;

use crate::input::HookInput;
use crate::output::Decision;

pub fn run(input: &HookInput, safe_dirs: &[String], deny_subagent: &[String]) {
    let file_path_str = match input.file_path() {
        Some(p) if !p.is_empty() => p,
        _ => return,
    };

    let resolved = match path::resolve(file_path_str) {
        Some(p) => p,
        None => {
            Decision::deny("Path traversal detected").print();
            return;
        }
    };

    let home = match std::env::var("HOME") {
        Ok(h) => std::path::PathBuf::from(h),
        Err(_) => {
            Decision::deny("shields: HOME not set").print();
            return;
        }
    };

    let (decision, reason) = rules::evaluate(
        &resolved,
        &input.tool_name,
        input.is_subagent(),
        &home,
        safe_dirs,
        deny_subagent,
    );

    match decision {
        rules::AclDecision::Approve => Decision::approve(reason).print(),
        rules::AclDecision::Ask => Decision::ask(reason, None).print(),
        rules::AclDecision::Deny => Decision::deny(reason).print(),
    }
}
