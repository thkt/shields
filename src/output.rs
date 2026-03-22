use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionKind {
    Block,
    Deny,
    Ask,
    Approve,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub decision: DecisionKind,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

impl Decision {
    pub fn block(reason: &str, context: Option<&str>) -> Self {
        Self {
            decision: DecisionKind::Block,
            reason: reason.into(),
            additional_context: context.map(Into::into),
        }
    }

    pub fn deny(reason: &str) -> Self {
        Self {
            decision: DecisionKind::Deny,
            reason: reason.into(),
            additional_context: None,
        }
    }

    pub fn ask(reason: &str, context: Option<&str>) -> Self {
        Self {
            decision: DecisionKind::Ask,
            reason: reason.into(),
            additional_context: context.map(Into::into),
        }
    }

    pub fn approve(reason: &str) -> Self {
        Self {
            decision: DecisionKind::Approve,
            reason: reason.into(),
            additional_context: None,
        }
    }

    pub fn print(&self) {
        match serde_json::to_string(self) {
            Ok(json) => println!("{json}"),
            Err(_) => {
                eprintln!("shields: failed to serialize decision");
                std::process::exit(2);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Block decision ---

    #[test]
    fn block_decision_serializes_with_context() {
        let d = Decision::block("rm -rf detected", Some("Use a safer deletion command"));
        let json: serde_json::Value = serde_json::to_value(&d).unwrap();
        assert_eq!(json["decision"], "block");
        assert_eq!(json["reason"], "rm -rf detected");
        assert_eq!(json["additionalContext"], "Use a safer deletion command");
    }

    #[test]
    fn block_decision_omits_null_context() {
        let d = Decision::block("blocked", None);
        let json: serde_json::Value = serde_json::to_value(&d).unwrap();
        assert_eq!(json["decision"], "block");
        assert_eq!(json["reason"], "blocked");
        assert!(json.get("additionalContext").is_none());
    }

    // T-029: deny output for acl
    #[test]
    fn t029_deny_decision_serializes() {
        let d = Decision::deny("shields: malformed input");
        let json_str = serde_json::to_string(&d).unwrap();
        let json: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(json["decision"], "deny");
        assert_eq!(json["reason"], "shields: malformed input");
    }

    // --- Ask decision ---

    #[test]
    fn ask_decision_serializes() {
        let d = Decision::ask("sensitive file access", Some("Confirm before proceeding"));
        let json: serde_json::Value = serde_json::to_value(&d).unwrap();
        assert_eq!(json["decision"], "ask");
        assert_eq!(json["reason"], "sensitive file access");
        assert_eq!(json["additionalContext"], "Confirm before proceeding");
    }

    // --- Approve decision ---

    #[test]
    fn approve_decision_serializes() {
        let d = Decision {
            decision: DecisionKind::Approve,
            reason: String::new(),
            additional_context: None,
        };
        let json: serde_json::Value = serde_json::to_value(&d).unwrap();
        assert_eq!(json["decision"], "approve");
    }

    // T-027: block output when empty stdin in check
    #[test]
    fn t027_block_on_empty_stdin_output_format() {
        let d = Decision::block("shields: malformed input", None);
        let json: serde_json::Value = serde_json::to_value(&d).unwrap();
        assert_eq!(json["decision"], "block");
        assert_eq!(json["reason"], "shields: malformed input");
    }

    // T-028: block output when malformed JSON in check
    #[test]
    fn t028_block_on_malformed_json_output_format() {
        let d = Decision::block("shields: malformed input", None);
        let json_str = serde_json::to_string(&d).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["decision"], "block");
        assert_eq!(parsed["reason"], "shields: malformed input");
    }

    // --- Roundtrip ---

    #[test]
    fn decision_roundtrip_is_valid_json() {
        let d = Decision::block("test reason", Some("context with \"quotes\""));
        let json_str = serde_json::to_string(&d).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["reason"], "test reason");
        assert_eq!(parsed["additionalContext"], "context with \"quotes\"");
    }
}
