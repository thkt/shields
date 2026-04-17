mod acl;
mod check;
mod config;
mod input;
mod output;

use std::env;

use clap::{Parser, Subcommand};

use config::ShieldsConfig;
use input::HookInput;
use output::Decision;

#[derive(Parser)]
#[command(version, about = "Claude Code security hook: command guard + file ACL")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Check,
    Acl,
}

/// Fail-closed: block (check) or deny (acl) with a message.
fn fail_closed(command: &Commands, message: &str) {
    match command {
        Commands::Check => Decision::block(message, None).print(),
        Commands::Acl => Decision::deny(message).print(),
    }
}

fn main() {
    let cli = Cli::parse();

    let input = match HookInput::from_stdin() {
        Ok(input) => input,
        Err(e) => {
            let msg = format!("shields: malformed input: {e}");
            eprintln!("{msg}");
            fail_closed(&cli.command, &msg);
            return;
        }
    };

    let project_dir = env::current_dir().unwrap_or_default();
    let config = ShieldsConfig::load(&project_dir);

    if let Some(err) = &config.config_error {
        let msg = format!("shields: {err}");
        eprintln!("{msg}");
        fail_closed(&cli.command, &msg);
        return;
    }

    match cli.command {
        Commands::Check => {
            if config.check_enabled {
                check::run(&input, &config.custom_patterns, &config.secrets_patterns);
            } else {
                eprintln!("shields: check disabled via config");
            }
        }
        Commands::Acl => {
            if config.acl_enabled {
                acl::run(&input, &config.safe_dirs, &config.deny_subagent);
            } else {
                eprintln!("shields: acl disabled via config");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn t032_version_is_configured() {
        let cmd = Cli::command();
        let version = cmd.get_version().expect("version should be set");
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn cli_parses_check_subcommand() {
        let cli = Cli::try_parse_from(["shields", "check"]).unwrap();
        assert!(matches!(cli.command, Commands::Check));
    }

    #[test]
    fn cli_parses_acl_subcommand() {
        let cli = Cli::try_parse_from(["shields", "acl"]).unwrap();
        assert!(matches!(cli.command, Commands::Acl));
    }

    #[test]
    fn cli_rejects_unknown_subcommand() {
        assert!(Cli::try_parse_from(["shields", "unknown"]).is_err());
    }

    #[test]
    fn cli_requires_subcommand() {
        assert!(Cli::try_parse_from(["shields"]).is_err());
    }
}
