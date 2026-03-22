use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ToolInput {
    Bash { command: String },
    File { file_path: String },
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields populated via serde but not all accessed in code
pub struct HookInput {
    pub tool_name: String,
    pub tool_input: ToolInput,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
}

impl HookInput {
    pub fn from_stdin() -> Result<Self, serde_json::Error> {
        let stdin = std::io::stdin();
        serde_json::from_reader(stdin.lock())
    }

    #[cfg(test)]
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn command(&self) -> Option<&str> {
        match &self.tool_input {
            ToolInput::Bash { command } => Some(command),
            _ => None,
        }
    }

    pub fn file_path(&self) -> Option<&str> {
        match &self.tool_input {
            ToolInput::File { file_path } => Some(file_path),
            _ => None,
        }
    }

    pub fn is_subagent(&self) -> bool {
        self.agent_id.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Valid input parsing ---

    #[test]
    fn parse_bash_command_with_all_fields() {
        let json = r#"{
            "tool_name": "Bash",
            "tool_input": { "command": "cargo test" },
            "agent_id": "sub-123",
            "agent_type": "code"
        }"#;
        let input = HookInput::parse(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.command(), Some("cargo test"));
        assert_eq!(input.agent_id.as_deref(), Some("sub-123"));
        assert_eq!(input.agent_type.as_deref(), Some("code"));
        assert!(input.is_subagent());
    }

    #[test]
    fn parse_file_tool_input() {
        let json = r#"{
            "tool_name": "Write",
            "tool_input": { "file_path": "/tmp/test.rs" },
            "agent_id": null,
            "agent_type": null
        }"#;
        let input = HookInput::parse(json).unwrap();
        assert_eq!(input.tool_name, "Write");
        assert_eq!(input.file_path(), Some("/tmp/test.rs"));
        assert!(!input.is_subagent());
    }

    #[test]
    fn parse_optional_fields_absent() {
        let json = r#"{
            "tool_name": "Bash",
            "tool_input": { "command": "ls" }
        }"#;
        let input = HookInput::parse(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert!(input.agent_id.is_none());
        assert!(input.agent_type.is_none());
        assert!(!input.is_subagent());
    }

    // --- Fail-closed error handling (FR-011) ---

    // T-027/T-029: empty stdin → parse error
    #[test]
    fn t027_t029_empty_input_is_parse_error() {
        assert!(HookInput::parse("").is_err());
    }

    // T-028: malformed JSON → parse error
    #[test]
    fn t028_malformed_json_is_parse_error() {
        assert!(HookInput::parse("not valid json{{{").is_err());
    }

    // --- Edge cases ---

    #[test]
    fn missing_required_tool_name_is_error() {
        assert!(HookInput::parse(r#"{"tool_input": {"command": "ls"}}"#).is_err());
    }

    #[test]
    fn missing_required_tool_input_is_error() {
        assert!(HookInput::parse(r#"{"tool_name": "Bash"}"#).is_err());
    }

    #[test]
    fn null_json_is_parse_error() {
        assert!(HookInput::parse("null").is_err());
    }

    #[test]
    fn array_json_is_parse_error() {
        assert!(HookInput::parse("[]").is_err());
    }
}
